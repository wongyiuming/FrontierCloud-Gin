package business_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/opaqueledger"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func TestOpaquePublishedReceiptIsPinnedAndDoesNotSettle(t *testing.T) {
	ctx := context.Background()
	db := database(t)
	master := strings.Repeat("1", 32)
	key := bytes.Repeat([]byte{7}, 32)
	v, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	seed := protocol.Encode(bytes.Repeat([]byte{9}, 32))
	sealed, err := v.Seal(seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: master, Role: "Standalone", PrivateKey: sealed, CreatedAt: 123}); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: "https://master.test", Allocation: 2 * store.GiB, PhysicalFree: 10 * store.GiB}, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	repo := db.Nodes().(*business.Repository)
	if err = repo.InitializeOpaqueCapacityKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	intent := business.OpaqueCapacityIntent{OperationID: strings.Repeat("a", 64), MasterID: master, MemberID: master, BlobID: strings.Repeat("b", 64), Digest: strings.Repeat("c", 64), Bytes: 123}
	if _, err = repo.ReserveOpaqueCapacity(ctx, key, intent, 10*store.GiB); err != nil {
		t.Fatal(err)
	}
	scope, _, err := repo.BindOpaqueCapacityScope(ctx, key, intent.OperationID, strings.Repeat("2", 64), strings.Repeat("3", 64))
	if err != nil {
		t.Fatal(err)
	}
	receipt := protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-published-v1", MasterID: master, OwnerID: master, Generation: scope.Generation, OperationID: intent.OperationID, StageID: scope.StageID, BlobID: intent.BlobID, Digest: intent.Digest, Challenge: scope.PublishChallenge, Bytes: intent.Bytes, State: "published"}
	payload, err := receipt.Payload()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := protocol.Sign(seed, payload)
	if err != nil {
		t.Fatal(err)
	}
	bad := receipt
	bad.Challenge = scope.CleanupChallenge
	if _, err = repo.RecordOpaquePublishedReceipt(ctx, key, v, bad, signature); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("wrong challenge accepted", err)
	}
	if _, err = repo.RecordOpaquePublishedReceipt(ctx, key, v, receipt, signature+"a"); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("invalid signature accepted", err)
	}
	wrongVault, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.RecordOpaquePublishedReceipt(ctx, key, wrongVault, receipt, signature); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("wrong master vault accepted", err)
	}
	raw := db.(interface{ Database() *sql.DB }).Database()
	trigger := `CREATE TRIGGER fail_publish_receipt BEFORE UPDATE ON sealed_tree_capacity_scopes BEGIN SELECT RAISE(ABORT,'fixture'); END`
	if db.Backend() == "mysql" {
		trigger = `CREATE TRIGGER fail_publish_receipt BEFORE UPDATE ON sealed_tree_capacity_scopes FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='fixture'`
	}
	if _, err = raw.Exec(trigger); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.RecordOpaquePublishedReceipt(ctx, key, v, receipt, signature); err == nil {
		t.Fatal("faulted receipt committed")
	}
	if _, err = raw.Exec(`DROP TRIGGER fail_publish_receipt`); err != nil {
		t.Fatal(err)
	}
	type result struct {
		already bool
		err     error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			already, e := repo.RecordOpaquePublishedReceipt(ctx, key, v, receipt, signature)
			results <- result{already, e}
		}()
	}
	wg.Wait()
	close(results)
	first, retries := 0, 0
	for value := range results {
		if value.err != nil {
			t.Fatal("concurrent receipt", value.err)
		}
		if value.already {
			retries++
		} else {
			first++
		}
	}
	if first != 1 || retries != 1 {
		t.Fatal("receipt was not atomically idempotent", first, retries)
	}
	if already, err := repo.RecordOpaquePublishedReceipt(ctx, key, v, receipt, signature); err != nil || !already {
		t.Fatal("receipt retry failed", err)
	}
	verifyReceipt := func(proof protocol.OpaqueCapacityReceipt, sig string, proofVault *vault.Vault) error {
		tx, e := raw.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		lock := ""
		if db.Backend() == "mysql" {
			lock = " FOR UPDATE"
		}
		return opaqueledger.VerifyPublished(ctx, tx, key, proofVault, proof, sig, lock)
	}
	if err := verifyReceipt(receipt, signature, v); err != nil {
		t.Fatal("shared ledger rejected persisted receipt", err)
	}
	if err := verifyReceipt(bad, signature, v); err == nil {
		t.Fatal("shared ledger accepted changed challenge")
	}
	if err := verifyReceipt(receipt, signature+"a", v); err == nil {
		t.Fatal("shared ledger accepted changed signature")
	}
	if err := verifyReceipt(receipt, signature, wrongVault); err == nil {
		t.Fatal("shared ledger accepted wrong vault")
	}
	recovered, existed, err := repo.BindOpaqueCapacityScope(ctx, key, intent.OperationID, scope.Generation, scope.StageID)
	if err != nil || !existed || recovered.PublishedSignature != signature {
		t.Fatal("receipt not recoverable", err)
	}
	var reserved int64
	if err = raw.QueryRow(`SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?`, master).Scan(&reserved); err != nil || reserved != intent.Bytes {
		t.Fatal("receipt altered quota", err)
	}
	var ciphertext []byte
	if err = raw.QueryRow(`SELECT sealed FROM sealed_tree_capacity_scopes`).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte(signature)) || bytes.Contains(ciphertext, []byte(scope.PublishChallenge)) {
		t.Fatal("receipt leaked plaintext")
	}
	cleaned := receipt
	cleaned.Kind = "opaque-capacity-cleaned-v1"
	cleaned.State = "cleaned"
	cleaned.Challenge = scope.CleanupChallenge
	cleanupPayload, err := cleaned.Payload()
	if err != nil {
		t.Fatal(err)
	}
	cleanupSignature, err := protocol.Sign(seed, cleanupPayload)
	if err != nil {
		t.Fatal(err)
	}
	if already, err := repo.RecordOpaqueCleanedReceipt(ctx, key, v, cleaned, cleanupSignature); err != nil || already {
		t.Fatal("cleanup not recorded", err)
	}
	if err := verifyReceipt(receipt, signature, v); err == nil {
		t.Fatal("shared ledger accepted a cleaned receipt")
	}
	if already, err := repo.RecordOpaqueCleanedReceipt(ctx, key, v, cleaned, cleanupSignature); err != nil || !already {
		t.Fatal("cleanup retry", err)
	}
	if _, err = repo.RecordOpaquePublishedReceipt(ctx, key, v, receipt, signature); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("published proof resurrected after cleanup", err)
	}
	if err = raw.QueryRow(`SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?`, master).Scan(&reserved); err != nil || reserved != intent.Bytes {
		t.Fatal("cleanup proof released quota", err)
	}
	raceIntent := intent
	raceIntent.OperationID = strings.Repeat("d", 64)
	raceIntent.BlobID = strings.Repeat("e", 64)
	raceIntent.Digest = strings.Repeat("f", 64)
	raceIntent.Bytes = 1
	if _, err = repo.ReserveOpaqueCapacity(ctx, key, raceIntent, 10*store.GiB); err != nil {
		t.Fatal(err)
	}
	raceScope, _, err := repo.BindOpaqueCapacityScope(ctx, key, raceIntent.OperationID, scope.Generation, strings.Repeat("6", 64))
	if err != nil {
		t.Fatal(err)
	}
	racePublished := protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-published-v1", MasterID: master, OwnerID: master, Generation: raceScope.Generation, OperationID: raceIntent.OperationID, StageID: raceScope.StageID, BlobID: raceIntent.BlobID, Digest: raceIntent.Digest, Challenge: raceScope.PublishChallenge, Bytes: raceIntent.Bytes, State: "published"}
	raceCleaned := racePublished
	raceCleaned.Kind = "opaque-capacity-cleaned-v1"
	raceCleaned.State = "cleaned"
	raceCleaned.Challenge = raceScope.CleanupChallenge
	rp, _ := racePublished.Payload()
	rc, _ := raceCleaned.Payload()
	rps, _ := protocol.Sign(seed, rp)
	rcs, _ := protocol.Sign(seed, rc)
	var raceWG sync.WaitGroup
	raceErrors := make(chan error, 2)
	raceWG.Add(2)
	go func() {
		defer raceWG.Done()
		_, e := repo.RecordOpaquePublishedReceipt(ctx, key, v, racePublished, rps)
		if e != nil && !errors.Is(e, store.ErrNodeState) {
			raceErrors <- e
		}
	}()
	go func() {
		defer raceWG.Done()
		_, e := repo.RecordOpaqueCleanedReceipt(ctx, key, v, raceCleaned, rcs)
		if e != nil {
			raceErrors <- e
		}
	}()
	raceWG.Wait()
	close(raceErrors)
	for e := range raceErrors {
		t.Fatal("published/cleanup race", e)
	}
	if _, err = repo.RecordOpaquePublishedReceipt(ctx, key, v, racePublished, rps); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("race resurrected published proof", err)
	}
	otherSealed, err := v.Seal(protocol.Encode(bytes.Repeat([]byte{5}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = raw.Exec(`UPDATE node_identity SET private_key=? WHERE singleton=1`, otherSealed); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.RecordOpaqueCleanedReceipt(ctx, key, v, cleaned, cleanupSignature); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("reinitialized Master accepted", err)
	}
}

func TestOpaquePublishedReceiptRejectsRepairedOwner(t *testing.T) {
	ctx := context.Background()
	db := database(t)
	master, owner, relationship := strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32)
	v, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	masterSeed := protocol.Encode(bytes.Repeat([]byte{9}, 32))
	sealed, err := v.Seal(masterSeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: master, Role: "Standalone", PrivateKey: sealed, CreatedAt: 123}); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: "https://master.test", Allocation: 2 * store.GiB, PhysicalFree: 10 * store.GiB}, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	ownerSeed := protocol.Encode(bytes.Repeat([]byte{4}, 32))
	ownerPublic, err := protocol.PublicKey(ownerSeed)
	if err != nil {
		t.Fatal(err)
	}
	rel := store.Relationship{ID: relationship, PeerID: owner, Endpoint: "https://owner.test", PublicKey: ownerPublic, Credential: "fixture", Direction: "downstream", Mode: "Relay", State: "pending", Protocol: 2, CreatedAt: time.Now().Unix()}
	if err = db.Nodes().PrepareRelationship(ctx, rel, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = db.Nodes().ActivateRelationship(ctx, relationship, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	configuration := store.ResourceConfiguration{}
	configuration.Storage.Enabled, configuration.Storage.Allocation = true, 2*store.GiB
	if err = db.Pool().ConfigureMember(ctx, owner, configuration, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = db.Nodes().RecordHeartbeat(ctx, relationship, true, 1, map[string]any{"storage_free": int64(10 * store.GiB)}, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	repo := db.Nodes().(*business.Repository)
	key := bytes.Repeat([]byte{7}, 32)
	if err = repo.InitializeOpaqueCapacityKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	intent := business.OpaqueCapacityIntent{OperationID: strings.Repeat("a", 64), MasterID: master, MemberID: owner, BlobID: strings.Repeat("b", 64), Digest: strings.Repeat("c", 64), Bytes: 123}
	if _, err = repo.ReserveOpaqueCapacity(ctx, key, intent, 10*store.GiB); err != nil {
		t.Fatal(err)
	}
	scope, _, err := repo.BindOpaqueCapacityScope(ctx, key, intent.OperationID, strings.Repeat("4", 64), strings.Repeat("5", 64))
	if err != nil {
		t.Fatal(err)
	}
	receipt := protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-published-v1", MasterID: master, OwnerID: owner, RelationshipID: scope.RelationshipID, RelationshipBinding: scope.RelationshipBinding, Generation: scope.Generation, OperationID: intent.OperationID, StageID: scope.StageID, BlobID: intent.BlobID, Digest: intent.Digest, Challenge: scope.PublishChallenge, Bytes: intent.Bytes, State: "published"}
	payload, err := receipt.Payload()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := protocol.Sign(ownerSeed, payload)
	if err != nil {
		t.Fatal(err)
	}
	wrongSig, err := protocol.Sign(masterSeed, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.RecordOpaquePublishedReceipt(ctx, key, v, receipt, wrongSig); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("wrong owner signer accepted", err)
	}
	raw := db.(interface{ Database() *sql.DB }).Database()
	if _, err = raw.Exec(`UPDATE node_relationships SET credential=? WHERE relationship_id=?`, "repaired-fixture", relationship); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.RecordOpaquePublishedReceipt(ctx, key, v, receipt, signature); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("repaired relationship accepted", err)
	}
	if _, err = raw.Exec(`UPDATE node_relationships SET credential=? WHERE relationship_id=?`, "fixture", relationship); err != nil {
		t.Fatal(err)
	}
	if already, err := repo.RecordOpaquePublishedReceipt(ctx, key, v, receipt, signature); err != nil || already {
		t.Fatal("paired owner proof rejected", err)
	}
	verifyOwner := func() error {
		tx, e := raw.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		lock := ""
		if db.Backend() == "mysql" {
			lock = " FOR UPDATE"
		}
		return opaqueledger.VerifyPublished(ctx, tx, key, v, receipt, signature, lock)
	}
	if err := verifyOwner(); err != nil {
		t.Fatal("shared ledger rejected paired owner", err)
	}
	if _, err = raw.Exec(`UPDATE node_relationships SET credential=? WHERE relationship_id=?`, "repaired-fixture", relationship); err != nil {
		t.Fatal(err)
	}
	if err := verifyOwner(); err == nil {
		t.Fatal("shared ledger accepted replaced relationship instance")
	}
	var reserved int64
	if err = raw.QueryRow(`SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?`, owner).Scan(&reserved); err != nil || reserved != intent.Bytes {
		t.Fatal("remote proof changed capacity", err)
	}
	if _, err = raw.Exec(`UPDATE node_relationships SET credential=? WHERE relationship_id=?`, "fixture", relationship); err != nil {
		t.Fatal(err)
	}
	treeKey := bytes.Repeat([]byte{6}, 32)
	mac := func(value string) string {
		h := hmac.New(sha256.New, treeKey)
		h.Write([]byte(value))
		return hex.EncodeToString(h.Sum(nil))
	}
	objectIndex := strings.Repeat("e", 64)
	blobIndex := mac("frontiercloud:sealed-tree:blob:v1\x00" + intent.BlobID)
	completion := mac("frontiercloud:sealed-tree:completion:v1\x00" + intent.OperationID + objectIndex + blobIndex)
	if _, err = raw.Exec(`INSERT INTO sealed_tree_operation_ids(operation_id,completed,object_index,blob_index,receipt_mac) VALUES(?,1,?,?,?)`, intent.OperationID, objectIndex, blobIndex, completion); err != nil {
		t.Fatal(err)
	}
	tx, err := raw.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	lock := ""
	if db.Backend() == "mysql" {
		lock = " FOR UPDATE"
	}
	if already, e := opaqueledger.SettlePublished(ctx, tx, key, treeKey, v, receipt, signature, lock); e != nil || already {
		tx.Rollback()
		t.Fatal("follower settlement or scope encoding failed", e)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = verifyOwner(); err != nil {
		t.Fatal("settled follower proof did not recover", err)
	}
	if already, e := repo.RecordOpaquePublishedReceipt(ctx, key, v, receipt, signature); e != nil || !already {
		t.Fatal("settled follower receipt retry", e)
	}
	if already, e := repo.ReserveOpaqueCapacity(ctx, key, intent, 10*store.GiB); e != nil || !already {
		t.Fatal("follower reservation retry", e)
	}
	if recovered, found, e := repo.RecoverOpaqueCapacity(ctx, key, intent.OperationID); e != nil || !found || recovered != intent {
		t.Fatal("follower recovery", e)
	}
	reopened := business.New(raw, db.Backend())
	var retries sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		retries.Add(1)
		go func() {
			defer retries.Done()
			already, e := reopened.ReserveOpaqueCapacity(ctx, key, intent, 10*store.GiB)
			if e == nil && !already {
				e = errors.New("follower reservation repeated")
			}
			if e == nil {
				var found bool
				var recovered business.OpaqueCapacityIntent
				recovered, found, e = reopened.RecoverOpaqueCapacity(ctx, key, intent.OperationID)
				if e == nil && (!found || recovered != intent) {
					e = errors.New("follower settled recovery mismatch")
				}
			}
			if e != nil {
				results <- e
			}
		}()
	}
	retries.Wait()
	close(results)
	for e := range results {
		t.Fatal("concurrent follower settled retry", e)
	}
}
