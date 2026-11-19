//go:build linux && ledger_fixture

package business_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/deployment"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// Test-only bypass of the closed legacy-writer gate. The owner receipt is
// synthetic; this does not prove source authorization or actual owner I/O.
func TestFixtureRealBusinessTreeAndCapacityShareTransaction(t *testing.T) {
	ctx := context.Background()
	if reopenedPath := os.Getenv("FRONTIERCLOUD_TEST_OLD_WRITER_DB"); reopenedPath != "" {
		opened, err := sqlitestore.OpenExisting(ctx, reopenedPath)
		if err != nil {
			t.Fatal(err)
		}
		defer opened.Close()
		candidate := opened.Nodes().(*business.Repository)
		if err = candidate.CheckLegacyPhysicalWritesAllowed(ctx); !errors.Is(err, store.ErrNodeState) {
			t.Fatal("separate process permitted old physical writer", err)
		}
		if err = candidate.SetHidden(ctx, []string{"music/group"}, true, store.AdminAudit{}); !errors.Is(err, store.ErrNodeState) {
			t.Fatal("separate process permitted old metadata writer", err)
		}
		return
	}
	db := database(t)
	if db.Backend() != "sqlite" {
		t.Skip("tree runtime supports SQLite only")
	}
	raw := db.(interface{ Database() *sql.DB }).Database()
	var path string
	if err := raw.QueryRowContext(ctx, `SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&path); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	c := config.Config{DataRoot: dir, SQLitePath: path, DatabaseType: config.DatabaseSQLite, SecretsDirectory: filepath.Join(dir, "secrets")}
	if err := deployment.Bind(ctx, c, nil); err != nil {
		t.Fatal(err)
	}
	nodeVault, err := vault.Open(c.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	seed := protocol.Encode(bytes.Repeat([]byte{9}, 32))
	sealed, err := nodeVault.Seal(seed)
	if err != nil {
		t.Fatal(err)
	}
	master := strings.Repeat("1", 32)
	if _, err = db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: master, Role: "Standalone", PrivateKey: sealed, CreatedAt: 123}); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: "https://master.test", Allocation: 2 * store.GiB, PhysicalFree: 10 * store.GiB}, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if _, err = raw.ExecContext(ctx, `CREATE TABLE legacy_business_fixture(value TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err = raw.ExecContext(ctx, `INSERT INTO legacy_business_fixture VALUES('preserved')`); err != nil {
		t.Fatal(err)
	}
	fenceDir := filepath.Join(dir, "tree-private")
	if err = os.Mkdir(fenceDir, 0700); err != nil {
		t.Fatal(err)
	}
	gate, err := maintenance.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err = gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	tree, err := sealedtree.New(bytes.Repeat([]byte{0x42}, 32), bytes.Repeat([]byte{0x91}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rootID := strings.Repeat("a", 64)
	if err = sealedtree.FixtureInitializeExisting(ctx, c, gate, tree, rootID, fenceDir); err != nil {
		t.Fatal(err)
	}
	storeTree, err := sealedtree.OpenSQLite(ctx, raw, tree, rootID)
	if err != nil {
		t.Fatal(err)
	}
	fenceRoot, err := os.OpenRoot(fenceDir)
	if err != nil {
		t.Fatal(err)
	}
	defer fenceRoot.Close()
	if _, err = sealedtree.OpenFence(ctx, storeTree, fenceRoot, fenceDir); err != nil {
		t.Fatal(err)
	}
	existing := sealedtree.Entry{ParentID: rootID, ObjectID: strings.Repeat("d", 64), Kind: "directory", Name: "already-present"}
	if err = storeTree.CreateDirectoryWithFacts(ctx, existing, sealedtree.Facts{ObjectID: existing.ObjectID}); err != nil {
		t.Fatal("create existing tree object", err)
	}
	// A real initialized tree remains a durable old-writer stop while work is
	// incomplete, including a newly opened repository on the same SQLite file.
	reopenedStore, err := sqlitestore.OpenExisting(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedStore.Close()
	for _, candidate := range []*business.Repository{db.Nodes().(*business.Repository), reopenedStore.Nodes().(*business.Repository)} {
		if err = candidate.CheckLegacyPhysicalWritesAllowed(ctx); !errors.Is(err, store.ErrNodeState) {
			t.Fatal("real tree permitted old physical writers", err)
		}
		if err = candidate.SetHidden(ctx, []string{"music/group"}, true, store.AdminAudit{}); !errors.Is(err, store.ErrNodeState) {
			t.Fatal("real tree permitted old metadata writer", err)
		}
	}
	oldWriterExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(oldWriterExecutable, "-test.run=^TestFixtureRealBusinessTreeAndCapacityShareTransaction$")
	child.Env = append(os.Environ(), "FRONTIERCLOUD_TEST_OLD_WRITER_DB="+path)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("separate old-writer process: %v: %s", err, output)
	}
	object := strings.Repeat("b", 64)
	entry := sealedtree.Entry{ParentID: rootID, ObjectID: object, Kind: "audio", Name: "fixture.mp3"}
	location := sealedtree.Placement{ObjectID: object, NativeObjectID: object, OwnerID: master, Bytes: 123, SHA256: strings.Repeat("c", 64)}
	pending, err := storeTree.PrepareFileWithFreshLocators(ctx, entry, location, sealedtree.Facts{ObjectID: object})
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Nodes().(*business.Repository)
	key := bytes.Repeat([]byte{7}, 32)
	if err = repo.InitializeOpaqueCapacityKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	intent := business.OpaqueCapacityIntent{OperationID: pending.OperationID, MasterID: master, MemberID: master, BlobID: pending.BlobID, Digest: location.SHA256, Bytes: location.Bytes}
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
	if _, err = raw.ExecContext(ctx, `CREATE TRIGGER fail_receipt_update BEFORE UPDATE ON sealed_tree_capacity_scopes BEGIN SELECT RAISE(ABORT,'receipt-fault'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.RecordOpaquePublishedReceipt(ctx, key, nodeVault, receipt, signature); err == nil || !strings.Contains(err.Error(), "receipt-fault") {
		t.Fatal("receipt fault not observed", err)
	}
	if _, _, err = storeTree.Get(ctx, object); err == nil {
		t.Fatal("receipt fault exposed pending object")
	}
	if _, err = raw.ExecContext(ctx, `DROP TRIGGER fail_receipt_update`); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.RecordOpaquePublishedReceipt(ctx, key, nodeVault, receipt, signature); err != nil {
		t.Fatal(err)
	}
	if _, err = raw.ExecContext(ctx, `CREATE TRIGGER fail_capacity_update BEFORE UPDATE ON sealed_tree_capacity_scopes BEGIN SELECT RAISE(ABORT,'injected'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = sealedtree.FixtureCommitSignedPending(ctx, storeTree, key, nodeVault, receipt, signature); err == nil {
		t.Fatal("injected fault accepted")
	}
	if _, _, err = storeTree.Get(ctx, object); err == nil {
		t.Fatal("tree became visible after rollback")
	}
	var used, reserved int64
	if err = raw.QueryRowContext(ctx, `SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?`, master).Scan(&used, &reserved); err != nil || used != 0 || reserved != 123 {
		t.Fatalf("partial accounting %d/%d: %v", used, reserved, err)
	}
	if _, err = raw.ExecContext(ctx, `DROP TRIGGER fail_capacity_update`); err != nil {
		t.Fatal(err)
	}
	// Discard the original pool to model a restart after recording the receipt
	// but before committing the combined tree and capacity transaction.
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	restartDB, err := sqlitestore.OpenExisting(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer restartDB.Close()
	raw = restartDB.Database()
	repo = business.New(raw, "sqlite")
	storeTree, err = sealedtree.OpenSQLite(ctx, raw, tree, rootID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sealedtree.OpenFence(ctx, storeTree, fenceRoot, fenceDir); err != nil {
		t.Fatal(err)
	}
	if already, e := repo.RecordOpaquePublishedReceipt(ctx, key, nodeVault, receipt, signature); e != nil || !already {
		t.Fatal("receipt retry after restart", already, e)
	}
	if _, e := sealedtree.FixtureCommitSignedPending(ctx, storeTree, key, nodeVault, receipt, signature+"x"); e == nil {
		t.Fatal("tampered receipt accepted after restart")
	}
	if err = raw.QueryRowContext(ctx, `SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?`, master).Scan(&used, &reserved); err != nil || used != 0 || reserved != 123 {
		t.Fatalf("restart changed pending accounting %d/%d: %v", used, reserved, err)
	}
	encodedReceipt, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runChild := func(mode string, expectedExit int) {
		t.Helper()
		child := exec.Command(executable, "-test.run=^TestFixtureBusinessTreeCrashHelper$")
		child.Env = append(os.Environ(), "FC_LEDGER_CRASH_PATH="+path, "FC_LEDGER_CRASH_RECEIPT="+string(encodedReceipt), "FC_LEDGER_CRASH_SIGNATURE="+signature, "FC_LEDGER_CRASH_MODE="+mode)
		output, runErr := child.CombinedOutput()
		exit, ok := runErr.(*exec.ExitError)
		if !ok || exit.ExitCode() != expectedExit {
			t.Fatalf("%s child did not exit at crash point: %v %s", mode, runErr, output)
		}
	}
	runChild("before", 74)
	if _, _, err = storeTree.Get(ctx, object); err == nil {
		t.Fatal("uncommitted child exposed pending object")
	}
	if err = raw.QueryRowContext(ctx, `SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?`, master).Scan(&used, &reserved); err != nil || used != 0 || reserved != 123 {
		t.Fatalf("uncommitted child changed accounting %d/%d: %v", used, reserved, err)
	}
	runChild("after", 73)
	if _, _, err = storeTree.Get(ctx, object); err != nil {
		t.Fatal(err)
	}
	if got, _, e := storeTree.Get(ctx, existing.ObjectID); e != nil || got.Name != existing.Name || got.Kind != existing.Kind {
		t.Fatal("existing tree directory changed", got, e)
	}
	// A lost success response must recover from the committed database state,
	// without re-reserving capacity or publishing the pending row twice.
	if err = restartDB.Close(); err != nil {
		t.Fatal(err)
	}
	completedDB, err := sqlitestore.OpenExisting(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer completedDB.Close()
	raw = completedDB.Database()
	reopened, err := sealedtree.OpenSQLite(ctx, raw, tree, rootID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sealedtree.OpenFence(ctx, reopened, fenceRoot, fenceDir); err != nil {
		t.Fatal(err)
	}
	if already, e := sealedtree.FixtureCommitSignedPending(ctx, reopened, key, nodeVault, receipt, signature); e != nil || !already {
		t.Fatalf("retry %v: %v", already, e)
	}
	newRepo := business.New(raw, db.Backend())
	if already, e := newRepo.ReserveOpaqueCapacity(ctx, key, intent, 10*store.GiB); e != nil || !already {
		t.Fatal("reservation retry", e)
	}
	if _, found, e := newRepo.RecoverOpaqueCapacity(ctx, key, intent.OperationID); e != nil || !found {
		t.Fatal("recovery", e)
	}
	if err = raw.QueryRowContext(ctx, `SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?`, master).Scan(&used, &reserved); err != nil || used != 123 || reserved != 0 {
		t.Fatalf("accounting %d/%d: %v", used, reserved, err)
	}
	var legacy string
	if err = raw.QueryRowContext(ctx, `SELECT value FROM legacy_business_fixture`).Scan(&legacy); err != nil || legacy != "preserved" {
		t.Fatal("legacy data changed", err)
	}
}

// The child exits immediately after the transaction commits, without closing
// its database pool or returning an acknowledgement to its parent.
func TestFixtureBusinessTreeCrashHelper(t *testing.T) {
	path := os.Getenv("FC_LEDGER_CRASH_PATH")
	if path == "" {
		return
	}
	ctx := context.Background()
	var receipt protocol.OpaqueCapacityReceipt
	if err := json.Unmarshal([]byte(os.Getenv("FC_LEDGER_CRASH_RECEIPT")), &receipt); err != nil {
		t.Fatal(err)
	}
	db, err := sqlitestore.OpenExisting(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	nodeVault, err := vault.Open(filepath.Join(filepath.Dir(path), "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	tree, err := sealedtree.New(bytes.Repeat([]byte{0x42}, 32), bytes.Repeat([]byte{0x91}, 32))
	if err != nil {
		t.Fatal(err)
	}
	storeTree, err := sealedtree.OpenSQLite(ctx, db.Database(), tree, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	fenceDir := filepath.Join(filepath.Dir(path), "tree-private")
	fenceRoot, err := os.OpenRoot(fenceDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sealedtree.OpenFence(ctx, storeTree, fenceRoot, fenceDir); err != nil {
		t.Fatal(err)
	}
	if already, err := sealedtree.FixtureCommitSignedPendingWithCrashHook(ctx, storeTree, bytes.Repeat([]byte{7}, 32), nodeVault, receipt, os.Getenv("FC_LEDGER_CRASH_SIGNATURE"), func() {
		if os.Getenv("FC_LEDGER_CRASH_MODE") == "before" {
			os.Exit(74)
		}
	}); err != nil || already {
		t.Fatal("child commit", already, err)
	}
	os.Exit(73)
}
