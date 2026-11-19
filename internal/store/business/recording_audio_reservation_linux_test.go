//go:build linux

package business

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/selectedupload"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
	_ "modernc.org/sqlite"
)

type recordingAudioFixtureGate struct{}
type recordingAudioFixtureLease struct{}

func (recordingAudioFixtureGate) AcquireSelectedUpload(context.Context, *sealedtree.SQLStore) (SelectedUploadRuntimeLease, error) {
	return recordingAudioFixtureLease{}, nil
}
func (recordingAudioFixtureLease) Check(ctx context.Context) error { return ctx.Err() }
func (recordingAudioFixtureLease) Release()                        {}

type recordingAudioFixtureDeadline struct{}

func (recordingAudioFixtureDeadline) SetReadDeadline(time.Time) error { return nil }

// This is a synthetic Owner adapter using the real fenced stream, durable
// vault intent, BlobPublisher and signed receipt. It is not node.Service or
// a real HTTP listener; those require a separate cross-package fixture.
type recordingAudioFixtureOwner struct {
	root  *os.Root
	fence *ownerfence.Fence
	vault *vault.Vault
	seed  string
}

func (o *recordingAudioFixtureOwner) SelectedLocalFree(context.Context) (int64, error) {
	return 10 * store.GiB, nil
}
func (o *recordingAudioFixtureOwner) SelectedLocalOperation(ctx context.Context, claim protocol.SelectedStorageUpload, deadline selectedupload.ReadDeadline, body io.ReadCloser, action string) (protocol.OpaqueCapacityReceipt, string, error) {
	lease, err := o.fence.Acquire(ctx, false)
	if err != nil {
		return protocol.OpaqueCapacityReceipt{}, "", err
	}
	pub, err := sealedtree.NewBlobPublisher(o.root)
	if err != nil {
		lease.Release()
		return protocol.OpaqueCapacityReceipt{}, "", err
	}
	var prepared *sealedtree.PreparedBlob
	var receipt protocol.OpaqueCapacityReceipt
	var signature string
	err = selectedupload.RunOperationStaged(ctx, lease, deadline, body, time.Minute, o.root, o.vault, claim, action == "recover", func(c context.Context) (func(), error) {
		if action == "recover" {
			return nil, nil
		}
		prepared, err = pub.Prepare(c, claim.OperationID, claim.ObjectID, claim.Size, claim.ContentSHA256, body)
		if err != nil {
			return nil, err
		}
		return func() { _ = prepared.Close() }, nil
	}, func(c context.Context) error {
		if action == "recover" {
			err = pub.PublishStaged(c, claim.OperationID, claim.ObjectID, claim.Size, claim.ContentSHA256)
		} else {
			err = prepared.Publish(c)
		}
		if err != nil {
			return err
		}
		receipt = protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-published-v1", MasterID: claim.Master, OwnerID: claim.Owner, Generation: claim.Generation, OperationID: claim.OperationID, StageID: claim.StageID, BlobID: claim.ObjectID, Digest: claim.ContentSHA256, Challenge: claim.PublishChallenge, Bytes: claim.Size, State: "published"}
		payload, e := receipt.Payload()
		if e != nil {
			return e
		}
		signature, e = protocol.Sign(o.seed, payload)
		return e
	})
	return receipt, signature, err
}

// A real SQLite/tree/Owner-fence transaction exercises only admission and
// accounting. The authorization callback is synthetic; no Owner bytes, HTTP
// endpoint, product runtime or recovery workflow is claimed by this fixture.
func TestRecordingAudioReservationAtomicSelectedOwner(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "audio.db"))+"?_pragma=busy_timeout(1000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	treeKey, err := sealedtree.New(bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	tree, err := sealedtree.InitializeSQLite(ctx, db, treeKey, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	statements, err := migrations.Statements("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range statements {
		if _, err = db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	treeDir := t.TempDir()
	if err = os.Chmod(treeDir, 0700); err != nil {
		t.Fatal(err)
	}
	treeRoot, err := os.OpenRoot(treeDir)
	if err != nil {
		t.Fatal(err)
	}
	defer treeRoot.Close()
	if _, err = sealedtree.InitializeFence(ctx, tree, treeRoot, treeDir); err != nil {
		t.Fatal(err)
	}
	r := New(db, "sqlite")
	ownerDir := t.TempDir()
	if err = os.Mkdir(filepath.Join(ownerDir, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	ownerRoot, err := os.OpenRoot(ownerDir)
	if err != nil {
		t.Fatal(err)
	}
	defer ownerRoot.Close()
	fence, err := ownerfence.Create(ownerRoot, ownerDir, selectedCoordinatorCodec{})
	if err != nil {
		t.Fatal(err)
	}
	if err = r.ConfigureOwnerControlFence(func(ctx context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return fence.Acquire(ctx, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err = r.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	master, user := strings.Repeat("1", 32), strings.Repeat("2", 32)
	nodeVault, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	masterSeed := protocol.Encode(bytes.Repeat([]byte{9}, 32))
	private, err := nodeVault.Seal(masterSeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO node_identity(singleton,node_id,role,endpoint,private_key,created_at) VALUES(1,?,'Master','https://master.test',?,1)`, master, private); err != nil {
		t.Fatal(err)
	}
	if err = r.ConfigurePublicOrigin("https://master.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO public_ingress_config(singleton,node_id,public_origin,generation,updated_at) VALUES(1,?,'https://master.test',1,1)`, master); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO cluster_storage_members(member_id,relationship_id,member_kind,transport,storage_enabled,allocated_bytes,used_bytes,reserved_bytes,physical_free_bytes,health,writable,updated_at) VALUES(?,NULL,'MasterLocal','Local',1,?,0,0,?,'online',1,1)`, master, 2*store.GiB, 10*store.GiB); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO karaoke_users(user_id,username,username_key,password_hash,status,quota_bytes,used_bytes,created_at,updated_at) VALUES(?,'fixture','fixture','!','active',?,0,1,1)`, user, store.GiB); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	if err = r.InitializeOpaqueCapacityKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	recoveryInventory := func(visit func(RecoveryRecordingPlacement) error) (result RecoveryRecordingInventory, err error) {
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		err = r.WithOwnerControlExclusive(bounded, func(held context.Context) error {
			lease, err := tree.AcquireReadFence(held)
			if err != nil {
				return err
			}
			defer lease.Release()
			result, err = r.VisitRecoveryRecordings(held, tree, lease, key, nodeVault, visit)
			return errors.Join(err, lease.Check(held))
		})
		return result, err
	}
	blockedRecoveryVisit := func(RecoveryRecordingPlacement) error {
		t.Fatal("unfinished recording reached the recovery visitor")
		return nil
	}
	if got, err := recoveryInventory(blockedRecoveryVisit); err != nil || got != (RecoveryRecordingInventory{}) {
		t.Fatal("empty shared-lease recovery inventory", got, err)
	}
	meta, err := mediacrypto.NewMetadata(128)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("3", 32)
	browser := "browser:v2:" + strings.Repeat("4", 64)
	binding, err := store.RecordingAudioPreparationBinding(user, browser, id)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := mediacrypto.New(bytes.Repeat([]byte{6}, 32))
	if err != nil {
		t.Fatal(err)
	}
	client, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := manager.NewSession(browser, base64.StdEncoding.EncodeToString(client.PublicKey().Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	sessionCtx, err := manager.WithDirectSession(ctx, browser, grant.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	expected := store.PublicIngress{NodeID: master, PublicOrigin: "https://master.test", Generation: 1}
	prepareCtx, prepareCancel := context.WithTimeout(sessionCtx, 3*time.Second)
	stale := expected
	stale.Generation++
	if err = r.ReserveRecordingAudioPreparation(prepareCtx, tree, stale, user, browser, id, meta); err == nil {
		prepareCancel()
		t.Fatal("stale ingress generation was accepted")
	}
	if err = r.ReserveRecordingAudioPreparation(prepareCtx, tree, expected, user, browser, id, meta); err != nil {
		prepareCancel()
		t.Fatal(err)
	}
	prepareCancel()
	manager.RevokeBinding(browser)
	newMeta, err := mediacrypto.NewMetadata(127)
	if err != nil {
		t.Fatal(err)
	}
	revokedCtx, revokedCancel := context.WithTimeout(sessionCtx, 3*time.Second)
	if err = r.ReserveRecordingAudioPreparation(revokedCtx, tree, expected, user, browser, strings.Repeat("6", 32), newMeta); err == nil {
		revokedCancel()
		t.Fatal("revoked browser session was accepted")
	}
	revokedCancel()
	req := recordingAudioAdmission{UserID: user, RecordingID: id, MemberID: master, Digest: strings.Repeat("5", 64), Binding: binding, Title: "私有标题", ContentType: "audio/webm", Encryption: meta}
	check := func(context.Context, queryer, recordingAudioAdmission) error { return nil }
	reserve := func(v recordingAudioAdmission, callback func(context.Context, queryer, recordingAudioAdmission) error) (recordingAudioIntent, bool, error) {
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		return r.reserveRecordingAudioCoordinated(bounded, tree, key, v, 10*store.GiB, store.KaraokeAudit{}, callback)
	}
	if _, err = db.Exec(`CREATE TRIGGER fail_recording_audit BEFORE INSERT ON karaoke_audit_log BEGIN SELECT RAISE(FAIL,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if _, _, err = reserve(req, check); err == nil {
		t.Fatal("injected audit failure committed")
	}
	var used, reserved, rows int64
	if err = db.QueryRow(`SELECT used_bytes FROM karaoke_users WHERE user_id=?`, user).Scan(&used); err != nil || used != 0 {
		t.Fatal("failed transaction charged user", err)
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM sealed_recording_audio`).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("failed transaction retained audio intent", err)
	}
	if _, err = db.Exec(`DROP TRIGGER fail_recording_audit`); err != nil {
		t.Fatal(err)
	}
	first, prior, err := reserve(req, check)
	if err != nil || prior {
		t.Fatal("new reservation", err)
	}
	second, prior, err := reserve(req, check)
	if err != nil || !prior || second != first {
		t.Fatal("exact retry", err)
	}
	if err = db.QueryRow(`SELECT used_bytes FROM karaoke_users WHERE user_id=?`, user).Scan(&used); err != nil || used != meta.CiphertextSize {
		t.Fatal("user charged more than once", err)
	}
	if err = db.QueryRow(`SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?`, master).Scan(&reserved); err != nil || reserved != meta.CiphertextSize {
		t.Fatal("Owner reservation incorrect", err)
	}
	if got, err := recoveryInventory(blockedRecoveryVisit); !errors.Is(err, store.ErrRecordingState) || got != (RecoveryRecordingInventory{}) {
		t.Fatal("pending recording accepted by shared-lease inventory", got, err)
	}
	bind := func(callback func(context.Context, queryer, recordingAudioIntent) error) (OpaqueCapacityScope, bool, error) {
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		return r.bindRecordingAudioScope(bounded, tree, key, user, id, callback)
	}
	blobIndex, err := treeKey.BlobIndex(first.BlobID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`DELETE FROM sealed_tree_blob_ids WHERE blob_index=?`, blobIndex); err != nil {
		t.Fatal(err)
	}
	if _, _, err = bind(func(context.Context, queryer, recordingAudioIntent) error { return nil }); err == nil {
		t.Fatal("missing global blob tombstone was accepted")
	}
	if _, err = db.Exec(`INSERT INTO sealed_tree_blob_ids(blob_index) VALUES(?)`, blobIndex); err != nil {
		t.Fatal(err)
	}
	calls := 0
	if _, _, err = bind(func(context.Context, queryer, recordingAudioIntent) error {
		calls++
		if calls == 2 {
			return errors.New("fixture authorization revoked")
		}
		return nil
	}); err == nil {
		t.Fatal("scope committed after authorization was revoked")
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_capacity_scopes`).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("failed scope transaction was not rolled back", err)
	}
	scopeCheck := func(context.Context, queryer, recordingAudioIntent) error { return nil }
	scope, exists, err := bind(scopeCheck)
	if err != nil || exists || scope.OperationID != first.OperationID {
		t.Fatal("bind Owner stage scope", err)
	}
	retriedScope, exists, err := bind(scopeCheck)
	if err != nil || !exists || retriedScope != scope {
		t.Fatal("Owner stage scope retry changed", err)
	}
	changed := req
	changed.Digest = strings.Repeat("6", 64)
	if _, _, err = reserve(changed, check); err == nil {
		t.Fatal("changed content was accepted as retry")
	}
	changed = req
	changed.MemberID = strings.Repeat("9", 32)
	if _, _, err = reserve(changed, check); err == nil {
		t.Fatal("unavailable requested Owner was silently replaced")
	}
	if _, _, err = reserve(req, func(context.Context, queryer, recordingAudioAdmission) error { return errors.New("denied") }); err == nil {
		t.Fatal("unauthorized retry was accepted")
	}
	receipt := protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-published-v1", MasterID: master, OwnerID: master, Generation: scope.Generation, OperationID: first.OperationID, StageID: scope.StageID, BlobID: first.BlobID, Digest: first.Digest, Challenge: scope.PublishChallenge, Bytes: first.Bytes, State: "published"}
	payload, err := receipt.Payload()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := protocol.Sign(masterSeed, payload)
	if err != nil {
		t.Fatal(err)
	}
	finalize := func(sig string) (bool, error) {
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		return r.finalizeRecordingAudio(bounded, tree, key, nodeVault, user, id, receipt, sig, store.KaraokeAudit{}, scopeCheck)
	}
	if _, err = finalize(signature + "bad"); err == nil {
		t.Fatal("invalid Owner signature was accepted")
	}
	if _, err = db.Exec(`CREATE TRIGGER fail_recording_finalize BEFORE INSERT ON karaoke_audit_log BEGIN SELECT RAISE(FAIL,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = finalize(signature); err == nil {
		t.Fatal("finalize audit failure committed")
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_operation_ids WHERE operation_id=?`, first.OperationID).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("failed finalize left a completion", err)
	}
	if err = db.QueryRow(`SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?`, master).Scan(&reserved); err != nil || reserved != first.Bytes {
		t.Fatal("failed finalize changed capacity", err)
	}
	if _, err = db.Exec(`DROP TRIGGER fail_recording_finalize`); err != nil {
		t.Fatal(err)
	}
	if prior, err = finalize(signature); err != nil || prior {
		t.Fatal("signed finalize", err)
	}
	if prior, err = finalize(signature); err != nil || !prior {
		t.Fatal("signed finalize retry", err)
	}
	if err = db.QueryRow(`SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?`, master).Scan(&used, &reserved); err != nil || used != first.Bytes || reserved != 0 {
		t.Fatal("Owner capacity not settled exactly once", err)
	}
	if _, err = tree.Check(ctx); err != nil {
		t.Fatal("tree check after recording completion", err)
	}
	if got, err := recoveryInventory(func(item RecoveryRecordingPlacement) error {
		if item.OwnerID != master || item.RecordingID != id || item.BlobID != first.BlobID ||
			item.Publication != receipt || item.PublicationSignature != signature ||
			item.UserUsedBytes != first.Bytes || item.OwnerUsedBytes != first.Bytes || item.OwnerReservedBytes != 0 {
			t.Fatal("Local signed recording inventory mismatch")
		}
		return nil
	}); err != nil || got.Recordings != 1 || got.Bytes != first.Bytes {
		t.Fatal("Local recording completion was not verified in shared snapshot", got, err)
	}
	if _, err = db.Exec(`DELETE FROM sealed_tree_blob_ids WHERE blob_index=?`, blobIndex); err != nil {
		t.Fatal(err)
	}
	if got, err := recoveryInventory(blockedRecoveryVisit); !errors.Is(err, store.ErrRecordingState) || got != (RecoveryRecordingInventory{}) {
		t.Fatal("missing permanent blob identity accepted by recovery inventory", got, err)
	}
	if _, err = db.Exec(`INSERT INTO sealed_tree_blob_ids(blob_index) VALUES(?)`, blobIndex); err != nil {
		t.Fatal(err)
	}
	recoveryAccounting := func() (result RecoveryAccounting, err error) {
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		err = r.WithOwnerControlExclusive(bounded, func(held context.Context) error {
			owner, err := r.AcquireOwnerControlShared(held)
			if err != nil {
				return err
			}
			defer owner.Release()
			lease, err := tree.AcquireReadFence(held)
			if err != nil {
				return err
			}
			defer lease.Release()
			result, err = r.VerifyRecoveryAccounting(held, owner, tree, lease, key, nodeVault)
			return errors.Join(err, lease.Check(held))
		})
		return result, err
	}
	if got, err := recoveryAccounting(); err != nil || got.Media != 0 || got.Recordings != 1 || len(got.Owners) != 1 ||
		got.Owners[0].ID != master || got.Owners[0].Objects != 1 || got.Owners[0].Bytes != first.Bytes {
		t.Fatal("settled recording did not reconcile exact Master accounting", got, err)
	}
	expectedObjects := buildRecoveryExpectationsFixture(t, ctx, r, tree, key, nodeVault)
	if expectedObjects.Accounting.Recordings != 1 || len(expectedObjects.Owners) != 1 || len(expectedObjects.Owners[0].Recordings) != 1 ||
		len(expectedObjects.Owners[0].Media) != 0 || len(expectedObjects.Owners[0].S3) != 0 {
		t.Fatal("grouped recovery expectations did not match settled recording")
	}
	recording := expectedObjects.Owners[0].Recordings[0]
	if recording.Kind != "recording" || recording.ObjectID != id || recording.OwnerID != master || recording.BlobID != first.BlobID ||
		recording.Bytes != first.Bytes || recording.NativeSHA256 != first.Digest || recording.ReadAlias == "" || recording.AliasRevision == "" {
		t.Fatal("recording expectations lost exact native verification fields")
	}
	if _, err = db.Exec(`UPDATE cluster_storage_members SET used_bytes=used_bytes+1 WHERE member_id=?`, master); err != nil {
		t.Fatal(err)
	}
	if _, err = recoveryAccounting(); !errors.Is(err, errRecoveryAccounting) {
		t.Fatal("unexplained Owner usage passed exact accounting", err)
	}
	if _, err = db.Exec(`UPDATE cluster_storage_members SET used_bytes=used_bytes-1 WHERE member_id=?`, master); err != nil {
		t.Fatal(err)
	}
	// A second recording exercises real AES-GCM ciphertext, filesystem staging,
	// an interrupted pre-commit authorization, and authenticated stage replay.
	plain := []byte("synthetic private recording audio")
	physicalMeta, err := mediacrypto.NewMetadata(int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(bytes.Repeat([]byte{11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := base64.StdEncoding.DecodeString(physicalMeta.NoncePrefix)
	if err != nil {
		t.Fatal(err)
	}
	nonce := append(prefix, 0, 0, 0, 0)
	ciphertext := aead.Seal(nil, nonce, plain, physicalMeta.ChunkAAD(0))
	cipherHash := sha256.Sum256(ciphertext)
	physicalID := strings.Repeat("7", 32)
	physicalBinding, err := store.RecordingAudioPreparationBinding(user, browser, physicalID)
	if err != nil {
		t.Fatal(err)
	}
	grant, err = manager.NewSession(browser, base64.StdEncoding.EncodeToString(client.PublicKey().Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	sessionCtx, err = manager.WithDirectSession(ctx, browser, grant.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	prepareCtx, prepareCancel = context.WithTimeout(sessionCtx, 3*time.Second)
	if err = r.ReserveRecordingAudioPreparation(prepareCtx, tree, expected, user, browser, physicalID, physicalMeta); err != nil {
		prepareCancel()
		t.Fatal(err)
	}
	prepareCancel()
	owner := &recordingAudioFixtureOwner{root: ownerRoot, fence: fence, vault: nodeVault, seed: masterSeed}
	runtime, err := NewSelectedUploadRuntime(r, tree, key, manager, nodeVault, "https://master.test", recordingAudioFixtureGate{})
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.ConfigureLocalOwner(owner); err != nil {
		t.Fatal(err)
	}
	token, err := manager.SignTransientPreparation(physicalBinding, physicalMeta)
	if err != nil {
		t.Fatal(err)
	}
	account := store.KaraokeUser{ID: user, PasswordHash: "!", Status: "active", CreatedAt: 1}
	ticket := store.RecordingAudioTicketRequest{RecordingID: physicalID, MemberID: master, CipherSHA256: hex.EncodeToString(cipherHash[:]), Title: "另一条私有标题", ContentType: "audio/webm", SessionID: grant.SessionID, Encryption: physicalMeta, PreparationToken: token}
	admitCtx, admitCancel := context.WithTimeout(sessionCtx, 3*time.Second)
	defer admitCancel()
	if err = runtime.AdmitRecordingAudioTicket(admitCtx, tree, stale, account, browser, ticket, store.KaraokeAudit{}); err == nil {
		t.Fatal("stale ingress admission")
	}
	wrongAccount := account
	wrongAccount.PasswordHash = "changed"
	if err = runtime.AdmitRecordingAudioTicket(admitCtx, tree, expected, wrongAccount, browser, ticket, store.KaraokeAudit{}); err == nil {
		t.Fatal("stale account admission")
	}
	wrongTicket := ticket
	wrongTicket.PreparationToken = "invalid"
	if err = runtime.AdmitRecordingAudioTicket(admitCtx, tree, expected, account, browser, wrongTicket, store.KaraokeAudit{}); err == nil {
		t.Fatal("invalid preparation admission")
	}
	if _, err = db.Exec(`UPDATE cluster_storage_members SET transport='Direct' WHERE member_id=?`, master); err != nil {
		t.Fatal(err)
	}
	if err = runtime.AdmitRecordingAudioTicket(admitCtx, tree, expected, account, browser, ticket, store.KaraokeAudit{}); err == nil {
		t.Fatal("mismatched Local transport admission")
	}
	if _, err = db.Exec(`UPDATE cluster_storage_members SET transport='Local' WHERE member_id=?`, master); err != nil {
		t.Fatal(err)
	}
	if err = runtime.AdmitRecordingAudioTicket(admitCtx, tree, expected, account, browser, ticket, store.KaraokeAudit{}); err != nil {
		t.Fatal("authorized physical reservation", err)
	}
	if err = runtime.AdmitRecordingAudioTicket(admitCtx, tree, expected, account, browser, ticket, store.KaraokeAudit{}); err != nil {
		t.Fatal("authorized reservation retry", err)
	}
	physicalIntent, _, _, found, err := r.readRecordingAudioIntentTx(ctx, db, key, physicalID)
	if err != nil || !found {
		t.Fatal("physical intent", err)
	}
	physicalCheckCalls := 0
	uploadCtx, uploadCancel := context.WithTimeout(sessionCtx, 10*time.Second)
	_, err = runtime.UploadRecordingAudioLocal(uploadCtx, tree, expected, account, browser, physicalID, "upload", int64(len(ciphertext)+1), recordingAudioFixtureDeadline{}, io.NopCloser(bytes.NewReader(ciphertext)), store.KaraokeAudit{}, func(context.Context) error { return nil })
	if err == nil {
		t.Fatal("wrong content length accepted")
	}
	_, err = runtime.UploadRecordingAudioLocal(uploadCtx, tree, expected, account, browser, physicalID, "upload", int64(len(ciphertext)), recordingAudioFixtureDeadline{}, io.NopCloser(bytes.NewReader(ciphertext)), store.KaraokeAudit{}, func(context.Context) error {
		physicalCheckCalls++
		if physicalCheckCalls == 2 {
			return errors.New("fixture session revoked before finalize")
		}
		return nil
	})
	uploadCancel()
	if err == nil || physicalCheckCalls != 2 {
		t.Fatal("expected pre-finalize interruption", err)
	}
	path, err := sealedtree.BlobPath(physicalIntent.BlobID)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := ownerRoot.ReadFile(path)
	if err != nil || !bytes.Equal(stored, ciphertext) || bytes.Contains(stored, plain) {
		t.Fatal("Owner did not persist exact ciphertext", err)
	}
	if err = db.QueryRow(`SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?`, master).Scan(&reserved); err != nil || reserved != physicalIntent.Bytes {
		t.Fatal("interrupted finalize released reservation", err)
	}
	recoverCtx, recoverCancel := context.WithTimeout(sessionCtx, 10*time.Second)
	prior, err = runtime.UploadRecordingAudioLocal(recoverCtx, tree, expected, account, browser, physicalID, "recover", 0, recordingAudioFixtureDeadline{}, io.NopCloser(bytes.NewReader(nil)), store.KaraokeAudit{}, func(context.Context) error { return nil })
	recoverCancel()
	if err != nil || prior {
		t.Fatal("authenticated physical stage recovery", err)
	}
	readyCtx, readyCancel := context.WithTimeout(sessionCtx, 3*time.Second)
	defer readyCancel()
	prior, err = runtime.UploadRecordingAudioLocal(readyCtx, tree, expected, account, browser, physicalID, "recover", 0, recordingAudioFixtureDeadline{}, io.NopCloser(bytes.NewReader(nil)), store.KaraokeAudit{}, func(context.Context) error { return nil })
	if err != nil || !prior {
		t.Fatal("completed recovery must be idempotent", err)
	}
	var completionMAC string
	if err = db.QueryRow(`SELECT receipt_mac FROM sealed_tree_operation_ids WHERE operation_id=?`, physicalIntent.OperationID).Scan(&completionMAC); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE sealed_tree_operation_ids SET receipt_mac=? WHERE operation_id=?`, strings.Repeat("f", 64), physicalIntent.OperationID); err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.UploadRecordingAudioLocal(readyCtx, tree, expected, account, browser, physicalID, "recover", 0, recordingAudioFixtureDeadline{}, io.NopCloser(bytes.NewReader(nil)), store.KaraokeAudit{}, func(context.Context) error { return nil }); err == nil {
		t.Fatal("tampered completed operation accepted")
	}
	if got, err := recoveryInventory(func(item RecoveryRecordingPlacement) error {
		if item.RecordingID == physicalID {
			t.Fatal("tampered completion reached recovery visitor")
		}
		return nil
	}); !errors.Is(err, store.ErrRecordingState) || got != (RecoveryRecordingInventory{}) {
		t.Fatal("tampered completion accepted by recovery inventory", got, err)
	}
	if _, err = db.Exec(`UPDATE sealed_tree_operation_ids SET receipt_mac=? WHERE operation_id=?`, completionMAC, physicalIntent.OperationID); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?`, master).Scan(&reserved); err != nil || reserved != 0 {
		t.Fatal("physical recovery did not settle reservation", err)
	}
	if _, err = tree.Check(ctx); err != nil {
		t.Fatal("tree check after physical recording", err)
	}
	var baselineUser, baselineReserved int64
	if err = db.QueryRow(`SELECT used_bytes FROM karaoke_users WHERE user_id=?`, user).Scan(&baselineUser); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?`, master).Scan(&baselineReserved); err != nil {
		t.Fatal(err)
	}
	makePending := func(t *testing.T, user, id string) mediacrypto.Metadata {
		t.Helper()
		meta, e := mediacrypto.NewMetadata(64)
		if e != nil {
			t.Fatal(e)
		}
		prepCtx, cancel := context.WithTimeout(sessionCtx, 3*time.Second)
		defer cancel()
		if e = r.ReserveRecordingAudioPreparation(prepCtx, tree, expected, user, browser, id, meta); e != nil {
			t.Fatal(e)
		}
		binding, e := store.RecordingAudioPreparationBinding(user, browser, id)
		if e != nil {
			t.Fatal(e)
		}
		request := recordingAudioAdmission{UserID: user, RecordingID: id, MemberID: master, Digest: strings.Repeat("b", 64), Binding: binding, Title: "待处理录音", ContentType: "audio/webm", Encryption: meta}
		if _, was, e := reserve(request, check); e != nil || was {
			t.Fatal("pending reservation", e)
		}
		if _, e = db.Exec(`UPDATE karaoke_recordings SET updated_at=? WHERE recording_id=?`, time.Now().Unix()-3601, id); e != nil {
			t.Fatal(e)
		}
		return meta
	}
	unstartedID := strings.Repeat("8", 32)
	unstartedMeta := makePending(t, user, unstartedID)
	expiryCtx, expiryCancel := context.WithTimeout(ctx, 10*time.Second)
	defer expiryCancel()
	if _, err = db.Exec(`CREATE TRIGGER fail_recording_expiry BEFORE INSERT ON karaoke_audit_log BEGIN SELECT RAISE(FAIL,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.expireUnstartedRecordingAudio(expiryCtx, tree, user, unstartedID); err == nil {
		t.Fatal("expiry audit failure committed")
	}
	if _, err = db.Exec(`DROP TRIGGER fail_recording_expiry`); err != nil {
		t.Fatal(err)
	}
	var beforeExpiry int64
	if err = db.QueryRow(`SELECT used_bytes FROM karaoke_users WHERE user_id=?`, user).Scan(&beforeExpiry); err != nil || beforeExpiry != baselineUser+unstartedMeta.CiphertextSize {
		t.Fatal("failed expiry altered quota", err)
	}
	expired, err := runtime.expireUnstartedRecordingAudio(expiryCtx, tree, user, unstartedID)
	if err != nil || !expired {
		t.Fatal("unstarted expiry", err)
	}
	expired, err = runtime.expireUnstartedRecordingAudio(expiryCtx, tree, user, unstartedID)
	if err != nil || expired {
		t.Fatal("expiry retry charged twice", err)
	}
	if err = db.QueryRow(`SELECT used_bytes FROM karaoke_users WHERE user_id=?`, user).Scan(&beforeExpiry); err != nil || beforeExpiry != baselineUser {
		t.Fatal("expiry user refund", err)
	}
	if err = db.QueryRow(`SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?`, master).Scan(&reserved); err != nil || reserved != baselineReserved {
		t.Fatal("expiry node refund", err)
	}
	if got, err := recoveryInventory(func(item RecoveryRecordingPlacement) error {
		if item.RecordingID == unstartedID || item.UserUsedBytes != baselineUser || item.OwnerReservedBytes != baselineReserved {
			t.Fatal("cancelled recording consumed recovered quota")
		}
		return nil
	}); err != nil || got.Recordings != 2 || got.Bytes != baselineUser {
		t.Fatal("terminal cancelled recording blocked settled inventory", got, err)
	}
	prepCtx, prepCancel := context.WithTimeout(sessionCtx, 3*time.Second)
	if err = r.ReserveRecordingAudioPreparation(prepCtx, tree, expected, user, browser, strings.Repeat("a", 32), unstartedMeta); err == nil {
		prepCancel()
		t.Fatal("expired file ID reused")
	}
	prepCancel()
	scopedID := strings.Repeat("9", 32)
	scopedMeta := makePending(t, user, scopedID)
	if _, _, err = r.bindRecordingAudioScope(expiryCtx, tree, key, user, scopedID, scopeCheck); err != nil {
		t.Fatal("bind active scope", err)
	}
	expired, err = runtime.expireUnstartedRecordingAudio(expiryCtx, tree, user, scopedID)
	if err != nil || expired {
		t.Fatal("scoped pending was expired", err)
	}
	if err = db.QueryRow(`SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?`, master).Scan(&reserved); err != nil || reserved != baselineReserved+scopedMeta.CiphertextSize {
		t.Fatal("scoped reservation was refunded", err)
	}
	pageA, pageB := strings.Repeat("a", 32), strings.Repeat("b", 32)
	makePending(t, user, pageA)
	makePending(t, user, pageB)
	if _, err = db.Exec(`UPDATE karaoke_recordings SET updated_at=? WHERE recording_id IN (?,?,?)`, time.Now().Unix()-3700, scopedID, pageA, pageB); err != nil {
		t.Fatal(err)
	}
	page, err := runtime.ExpireUnstartedRecordingAudioPage(expiryCtx, tree, RecordingAudioExpiryCursor{}, 1)
	if err != nil || page.Scanned != 1 || page.Expired != 0 || !page.More || page.Next.RecordingID != scopedID {
		t.Fatal("scoped first page", page, err)
	}
	page, err = runtime.ExpireUnstartedRecordingAudioPage(expiryCtx, tree, page.Next, 1)
	if err != nil || page.Scanned != 1 || page.Expired != 1 || !page.More || page.Next.RecordingID != pageA {
		t.Fatal("expiry second page", page, err)
	}
	page, err = runtime.ExpireUnstartedRecordingAudioPage(expiryCtx, tree, page.Next, 1)
	if err != nil || page.Scanned != 1 || page.Expired != 1 || page.More || page.Next != (RecordingAudioExpiryCursor{}) {
		t.Fatal("expiry final page", page, err)
	}
	if err = db.QueryRow(`SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?`, master).Scan(&reserved); err != nil || reserved != baselineReserved+scopedMeta.CiphertextSize {
		t.Fatal("pagination altered scoped reservation", err)
	}
	if _, err = tree.Check(ctx); err != nil {
		t.Fatal("tree after expiry", err)
	}
	t.Run("delete account after recording cleanup", func(t *testing.T) {
		user, recording := strings.Repeat("d", 32), strings.Repeat("c", 32)
		if err := r.RegisterUser(ctx, store.KaraokeUser{ID: user, Username: "cleanupfixture", NameKey: "cleanupfixture", PasswordHash: "fixture-credential", Quota: store.GiB}, "192.0.2.10", "20261025", store.KaraokeAudit{}); err != nil {
			t.Fatal(err)
		}
		meta := makePending(t, user, recording)
		account, err := r.UserByID(ctx, user)
		if err != nil || account == nil || account.Status != "active" || account.Used != meta.CiphertextSize {
			t.Fatal("pending recording did not charge the account", err)
		}
		audit := store.KaraokeAudit{Action: "account-delete", RequestID: "account-delete-fixture"}
		deleteAccount := func() (bool, error) {
			bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			return r.DeleteEmptySealedUser(bounded, tree, user, account, audit)
		}
		if removed, err := deleteAccount(); removed || !errors.Is(err, store.ErrUserHasRecordings) {
			t.Fatal("account deletion bypassed pending recording", removed, err)
		}
		current, err := r.UserByID(ctx, user)
		if err != nil || current == nil || *current != *account {
			t.Fatal("rejected deletion changed account", err)
		}
		cleanup, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if expired, err := runtime.expireUnstartedRecordingAudio(cleanup, tree, user, recording); err != nil || !expired {
			t.Fatal("unstarted recording cleanup", expired, err)
		}
		if removed, err := deleteAccount(); err != nil || !removed {
			t.Fatal("cleaned account deletion", removed, err)
		}
		current, err = r.UserByID(ctx, user)
		if err != nil || current == nil || current.ID != user || current.Status != "deleted" || current.Username == account.Username || current.NameKey != "deleted:"+user || current.PasswordHash != "!" || current.Used != 0 || current.Quota != 0 {
			t.Fatal("account tombstone did not scrub credentials or retain identity", err)
		}
		if original, err := r.UserByName(ctx, account.NameKey); err != nil || original != nil {
			t.Fatal("original account name was not released", err)
		}
		var state, owner string
		if err := db.QueryRow(`SELECT state,user_id FROM karaoke_recordings WHERE recording_id=?`, recording).Scan(&state, &owner); err != nil || state != "deleted" || owner != user {
			t.Fatal("account deletion changed recording tombstone", err)
		}
		listed, err := r.ListUsers(ctx, "", 1, 50)
		if err != nil || listed.Total != 1 || len(listed.Items) != 1 || listed.Items[0].ID == user {
			t.Fatal("deleted account remains visible", err)
		}
		if removed, err := deleteAccount(); err != nil || removed {
			t.Fatal("account deletion retry changed outcome", removed, err)
		}
		var audited int
		if err := db.QueryRow(`SELECT COUNT(*) FROM karaoke_audit_log WHERE user_id=? AND action='account-delete' AND result='success' AND request_id=?`, user, audit.RequestID).Scan(&audited); err != nil || audited != 1 {
			t.Fatal("account deletion success was not audited exactly once", audited, err)
		}
	})
}
