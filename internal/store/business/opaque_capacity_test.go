package business_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
)

func TestOpaqueCapacityZeroSizePreservesAccounting(t *testing.T) {
	ctx := context.Background()
	db := database(t)
	master := strings.Repeat("1", 32)
	if _, err := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: master, Role: "Standalone", PrivateKey: "fixture", CreatedAt: 123}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: "https://master.test", Allocation: 2 * store.GiB, PhysicalFree: 10 * store.GiB}, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	repo := db.Nodes().(*business.Repository)
	key := bytes.Repeat([]byte{7}, 32)
	if err := repo.InitializeOpaqueCapacityKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	empty := sha256.Sum256(nil)
	intent := business.OpaqueCapacityIntent{OperationID: strings.Repeat("a", 64), MasterID: master, MemberID: master, BlobID: strings.Repeat("b", 64), Digest: hex.EncodeToString(empty[:]), Bytes: 0}
	if already, err := repo.ReserveOpaqueCapacity(ctx, key, intent, 10*store.GiB); err != nil || already {
		t.Fatal("empty reservation", err)
	}
	if already, err := repo.ReserveOpaqueCapacity(ctx, key, intent, 10*store.GiB); err != nil || !already {
		t.Fatal("empty idempotent retry", err)
	}
	if got, found, err := repo.RecoverOpaqueCapacity(ctx, key, intent.OperationID); err != nil || !found || got != intent {
		t.Fatal("empty recovery", err)
	}
	if _, _, err := repo.BindOpaqueCapacityScope(ctx, key, intent.OperationID, strings.Repeat("4", 64), strings.Repeat("5", 64)); err != nil {
		t.Fatal("empty scope", err)
	}
	bad := intent
	bad.OperationID = strings.Repeat("c", 64)
	bad.BlobID = strings.Repeat("d", 64)
	bad.Digest = strings.Repeat("e", 64)
	if _, err := repo.ReserveOpaqueCapacity(ctx, key, bad, 10*store.GiB); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("wrong empty digest", err)
	}
	nonempty := bad
	nonempty.Digest = strings.Repeat("f", 64)
	nonempty.Bytes = 1
	if _, err := repo.ReserveOpaqueCapacity(ctx, key, nonempty, 10*store.GiB); err != nil {
		t.Fatal("reservation after empty", err)
	}
	raw := db.(interface{ Database() *sql.DB }).Database()
	var reserved int64
	if err := raw.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", master).Scan(&reserved); err != nil || reserved != 1 {
		t.Fatal("wrong combined accounting", err)
	}
	if already, err := repo.ReserveOpaqueCapacity(ctx, key, intent, 10*store.GiB); err != nil || !already {
		t.Fatal("empty retry after nonempty", err)
	}
}

func TestOpaqueCapacityReservationIsEncryptedAtomicAndRecoverable(t *testing.T) {
	ctx := context.Background()
	db := database(t)
	master := strings.Repeat("1", 32)
	if _, err := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: master, Role: "Standalone", PrivateKey: "fixture", CreatedAt: 123}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: "https://master.test", Allocation: 2 * store.GiB, PhysicalFree: 10 * store.GiB}, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	repo := db.Nodes().(*business.Repository)
	key := bytes.Repeat([]byte{7}, 32)
	if err := repo.InitializeOpaqueCapacityKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := repo.InitializeOpaqueCapacityKey(ctx, bytes.Repeat([]byte{8}, 32)); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("wrong key initialized", err)
	}
	intent := business.OpaqueCapacityIntent{OperationID: strings.Repeat("a", 64), MasterID: master, MemberID: master, BlobID: strings.Repeat("b", 64), Digest: strings.Repeat("c", 64), Bytes: store.GiB + 1}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := repo.ReserveOpaqueCapacity(ctx, key, intent, 10*store.GiB)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal("concurrent identical reservation", err)
		}
	}
	raw := db.(interface{ Database() *sql.DB }).Database()
	var reserved int64
	if err := raw.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", master).Scan(&reserved); err != nil || reserved != intent.Bytes {
		t.Fatal("reservation counted more than once", err)
	}
	generation, stage := strings.Repeat("2", 64), strings.Repeat("3", 64)
	scope, existed, err := repo.BindOpaqueCapacityScope(ctx, key, intent.OperationID, generation, stage)
	if err != nil || existed || scope.PublishChallenge == scope.CleanupChallenge || scope.MasterBinding == "" || scope.RelationshipID != "" {
		t.Fatal("bind local scope", err)
	}
	again, existed, err := repo.BindOpaqueCapacityScope(ctx, key, intent.OperationID, generation, stage)
	if err != nil || !existed || again != scope {
		t.Fatal("scope retry changed", err)
	}
	if _, _, err := repo.BindOpaqueCapacityScope(ctx, key, intent.OperationID, strings.Repeat("4", 64), stage); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("changed generation accepted", err)
	}
	var sealedScope []byte
	if err := raw.QueryRow("SELECT sealed FROM sealed_tree_capacity_scopes").Scan(&sealedScope); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{intent.OperationID, generation, stage, scope.PublishChallenge, scope.CleanupChallenge} {
		if bytes.Contains(sealedScope, []byte(value)) {
			t.Fatal("scope leaked a raw identifier")
		}
	}
	other := intent
	other.OperationID = strings.Repeat("d", 64)
	other.BlobID = strings.Repeat("e", 64)
	if _, err := repo.ReserveOpaqueCapacity(ctx, key, other, 10*store.GiB); !errors.Is(err, store.ErrStorageCapacity) {
		t.Fatal("capacity oversubscribed", err)
	}
	duplicate := intent
	duplicate.OperationID = strings.Repeat("9", 64)
	duplicate.Bytes = 1
	if _, err := repo.ReserveOpaqueCapacity(ctx, key, duplicate, 10*store.GiB); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("blob reused by different operation", err)
	}
	changed := intent
	changed.Digest = strings.Repeat("f", 64)
	if _, err := repo.ReserveOpaqueCapacity(ctx, key, changed, 10*store.GiB); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("operation changed on retry", err)
	}
	if err := raw.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", master).Scan(&reserved); err != nil || reserved != intent.Bytes {
		t.Fatal("failed reservation changed capacity", err)
	}
	trigger := "CREATE TRIGGER fail_opaque_capacity BEFORE UPDATE ON cluster_storage_members BEGIN SELECT RAISE(ABORT,'fixture'); END"
	if db.Backend() == "mysql" {
		trigger = "CREATE TRIGGER fail_opaque_capacity BEFORE UPDATE ON cluster_storage_members FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='fixture'"
	}
	if _, err := raw.Exec(trigger); err != nil {
		t.Fatal(err)
	}
	failed := intent
	failed.OperationID = strings.Repeat("8", 64)
	failed.BlobID = strings.Repeat("7", 64)
	failed.Bytes = 1
	if _, err := repo.ReserveOpaqueCapacity(ctx, key, failed, 10*store.GiB); err == nil {
		t.Fatal("injected update failure committed")
	}
	if _, err := raw.Exec("DROP TRIGGER fail_opaque_capacity"); err != nil {
		t.Fatal(err)
	}
	if _, found, err := repo.RecoverOpaqueCapacity(ctx, key, failed.OperationID); err != nil || found {
		t.Fatal("failed transaction retained intent", err)
	}
	if err := raw.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", master).Scan(&reserved); err != nil || reserved != intent.Bytes {
		t.Fatal("failed transaction changed capacity", err)
	}
	reopened := business.New(raw, db.Backend())
	got, found, err := reopened.RecoverOpaqueCapacity(ctx, key, intent.OperationID)
	if err != nil || !found || got != intent {
		t.Fatal("reservation recovery", err)
	}
	if _, _, err = reopened.RecoverOpaqueCapacity(ctx, bytes.Repeat([]byte{8}, 32), intent.OperationID); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("wrong key accepted", err)
	}
	var index, enc string
	var sealed []byte
	if err = raw.QueryRow("SELECT operation_index,encryption_id,sealed FROM sealed_tree_capacity_intents").Scan(&index, &enc, &sealed); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{intent.OperationID, intent.MemberID, intent.BlobID, intent.Digest} {
		if index == value || enc == value || bytes.Contains(sealed, []byte(value)) {
			t.Fatal("capacity intent leaked a raw identifier")
		}
	}
	sealed[len(sealed)-1] ^= 1
	if _, err = raw.Exec("UPDATE sealed_tree_capacity_intents SET sealed=? WHERE operation_index=?", sealed, index); err != nil {
		t.Fatal(err)
	}
	if _, _, err = reopened.RecoverOpaqueCapacity(ctx, key, intent.OperationID); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("tampered intent accepted", err)
	}
}

func TestOpaqueCapacityReservationUsesSelectedOnlineFollower(t *testing.T) {
	ctx := context.Background()
	db := database(t)
	master, owner, relationship := strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32)
	if _, err := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: master, Role: "Standalone", PrivateKey: "fixture", CreatedAt: 123}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: "https://master.test", Allocation: 2 * store.GiB, PhysicalFree: 10 * store.GiB}, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	rel := store.Relationship{ID: relationship, PeerID: owner, Endpoint: "https://owner.test", PublicKey: strings.Repeat("A", 43), Credential: "fixture", Direction: "downstream", Mode: "Relay", State: "pending", Protocol: 2, CreatedAt: time.Now().Unix()}
	if err := db.Nodes().PrepareRelationship(ctx, rel, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Nodes().ActivateRelationship(ctx, relationship, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	configuration := store.ResourceConfiguration{}
	configuration.Storage.Enabled, configuration.Storage.Allocation = true, 2*store.GiB
	if err := db.Pool().ConfigureMember(ctx, owner, configuration, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Nodes().RecordHeartbeat(ctx, relationship, true, 1, map[string]any{"storage_free": int64(10 * store.GiB)}, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	repo := db.Nodes().(*business.Repository)
	key := bytes.Repeat([]byte{6}, 32)
	if err := repo.InitializeOpaqueCapacityKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	intent := business.OpaqueCapacityIntent{OperationID: strings.Repeat("a", 64), MasterID: master, MemberID: owner, BlobID: strings.Repeat("b", 64), Digest: strings.Repeat("c", 64), Bytes: store.GiB}
	if _, err := repo.ReserveOpaqueCapacity(ctx, key, intent, 10*store.GiB); err != nil {
		t.Fatal("online selected follower", err)
	}
	scope, _, err := repo.BindOpaqueCapacityScope(ctx, key, intent.OperationID, strings.Repeat("4", 64), strings.Repeat("5", 64))
	if err != nil || scope.RelationshipID != relationship || scope.RelationshipBinding == "" {
		t.Fatal("follower scope missing relationship instance", err)
	}
	raw := db.(interface{ Database() *sql.DB }).Database()
	if _, err := raw.Exec("UPDATE node_relationships SET credential=? WHERE relationship_id=?", "repaired-fixture", relationship); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.BindOpaqueCapacityScope(ctx, key, intent.OperationID, strings.Repeat("4", 64), strings.Repeat("5", 64)); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("replaced relationship instance accepted", err)
	}
	if _, err := raw.Exec("UPDATE node_relationships SET credential=? WHERE relationship_id=?", "fixture", relationship); err != nil {
		t.Fatal(err)
	}
	var remote, local int64
	if err := raw.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", owner).Scan(&remote); err != nil || remote != intent.Bytes {
		t.Fatal("wrong owner reserved", err)
	}
	if err := raw.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", master).Scan(&local); err != nil || local != 0 {
		t.Fatal("master unexpectedly reserved", err)
	}
	if err := db.Nodes().RecordHeartbeat(ctx, relationship, false, 1, nil, time.Now().Unix()+121); err != nil {
		t.Fatal(err)
	}
	intent.OperationID, intent.BlobID = strings.Repeat("d", 64), strings.Repeat("e", 64)
	if _, err := repo.ReserveOpaqueCapacity(ctx, key, intent, 10*store.GiB); !errors.Is(err, store.ErrStorageCapacity) {
		t.Fatal("offline follower accepted", err)
	}
}

func TestOpaqueCapacityLedgerRejectsCounterRollbackAndTampering(t *testing.T) {
	ctx := context.Background()
	db := database(t)
	master := strings.Repeat("1", 32)
	if _, err := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: master, Role: "Standalone", PrivateKey: "fixture", CreatedAt: 123}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: "https://master.test", Allocation: 4 * store.GiB, PhysicalFree: 10 * store.GiB}, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	repo := db.Nodes().(*business.Repository)
	key := bytes.Repeat([]byte{9}, 32)
	if err := repo.InitializeOpaqueCapacityKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	first := business.OpaqueCapacityIntent{OperationID: strings.Repeat("a", 64), MasterID: master, MemberID: master, BlobID: strings.Repeat("b", 64), Digest: strings.Repeat("c", 64), Bytes: store.GiB}
	second := first
	second.OperationID = strings.Repeat("d", 64)
	second.BlobID = strings.Repeat("e", 64)
	for _, intent := range []business.OpaqueCapacityIntent{first, second} {
		if _, err := repo.ReserveOpaqueCapacity(ctx, key, intent, 10*store.GiB); err != nil {
			t.Fatal(err)
		}
	}
	raw := db.(interface{ Database() *sql.DB }).Database()
	var reserved int64
	if err := raw.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", master).Scan(&reserved); err != nil || reserved != 2*store.GiB {
		t.Fatal("ledger total", err)
	}
	if _, err := raw.Exec("UPDATE cluster_storage_members SET reserved_bytes=? WHERE member_id=?", store.GiB, master); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.RecoverOpaqueCapacity(ctx, key, first.OperationID); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("counter rollback accepted", err)
	}
	if _, err := repo.ReserveOpaqueCapacity(ctx, key, second, 10*store.GiB); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("retry accepted reduced aggregate", err)
	}
	if _, err := raw.Exec("UPDATE cluster_storage_members SET reserved_bytes=? WHERE member_id=?", 2*store.GiB, master); err != nil {
		t.Fatal(err)
	}
	var index string
	var sealed []byte
	if err := raw.QueryRow("SELECT member_index,sealed FROM sealed_tree_capacity_accounts").Scan(&index, &sealed); err != nil {
		t.Fatal(err)
	}
	if index == master || bytes.Contains(sealed, []byte(master)) {
		t.Fatal("ledger leaked member identity")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := raw.Exec("UPDATE sealed_tree_capacity_accounts SET sealed=? WHERE member_index=?", sealed, index); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.RecoverOpaqueCapacity(ctx, key, first.OperationID); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("tampered ledger accepted", err)
	}
}
