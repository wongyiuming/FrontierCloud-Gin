//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	_ "modernc.org/sqlite"
)

// Low-level fixture wrappers supply synthetic attestation only to test CAS;
// the real coordinator always derives and checks the actual archive report.
func captureOfflineFenceEvidence(ctx context.Context, gate *maintenance.Gate, dataRoot, databasePath string, root *os.Root, directory string, master []byte, v *vault.Vault, nodeID, sha string) (out fenceRecoveryEvidence, err error) {
	err = gate.InspectSQLite(ctx, dataRoot, databasePath, func(c context.Context, check func() error) error {
		var e error
		out, e = captureFenceEvidenceHeld(c, check, dataRoot, databasePath, root, directory, master, v, nodeID, sha)
		return e
	})
	return
}
func rebindOfflineFence(ctx context.Context, gate *maintenance.Gate, dataRoot, databasePath string, root *os.Root, directory string, master []byte, v *vault.Vault, nodeID, sha string, proof fenceRecoveryEvidence) (bool, error) {
	return rebindOfflineFencePrepared(ctx, gate, dataRoot, databasePath, root, directory, master, v, nodeID, sha, proof, func(_ context.Context, check func() error) error { return check() }, func(_ context.Context, check func() error) error { return check() })
}

func TestOfflineFenceRecoveryRebindAndRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	source := t.TempDir()
	if err := os.Chmod(source, 0700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(source, "db.sqlite")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath)+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(100)")
	if err != nil {
		t.Fatal(err)
	}
	master := bytes.Repeat([]byte{7}, 32)
	salt := bytes.Repeat([]byte{8}, 32)
	tree, err := New(master, salt)
	if err != nil {
		t.Fatal(err)
	}
	s, err := InitializeSQLite(ctx, db, tree, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dbPath, 0600); err != nil {
		t.Fatal(err)
	}
	node := strings.Repeat("b", 32)
	nodeVault, err := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := nodeVault.Seal(protocol.Encode(bytes.Repeat([]byte{4}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT,role TEXT,private_key TEXT,created_at INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO node_identity VALUES(1,?,'Master',?,123)`, node, sealed); err != nil {
		t.Fatal(err)
	}
	fenceDir := filepath.Join(source, "tree")
	if err = os.Mkdir(fenceDir, 0700); err != nil {
		t.Fatal(err)
	}
	fenceRoot, err := os.OpenRoot(fenceDir)
	if err != nil {
		t.Fatal(err)
	}
	defer fenceRoot.Close()
	if _, err = InitializeFence(ctx, s, fenceRoot, fenceDir); err != nil {
		t.Fatal(err)
	}
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("c", 64), Kind: "directory", Name: "album"}
	if err = s.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: entry.ObjectID}); err != nil {
		t.Fatal(err)
	}
	binding := existingMasterBinding(tree, s.rootID, node, sealed, 123)
	if err = os.WriteFile(filepath.Join(fenceDir, existingMasterBindingFile), binding, 0600); err != nil {
		t.Fatal(err)
	}
	clear(binding)
	if _, err = db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	archiveSHA := hex.EncodeToString(digest[:]) // fixture attestation only
	gate, err := maintenance.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err = gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	proof, err := captureOfflineFenceEvidence(ctx, gate, source, dbPath, fenceRoot, fenceDir, master, nodeVault, node, archiveSHA)
	if err != nil {
		t.Fatal("source evidence", err)
	}
	target := t.TempDir()
	if err = os.Chmod(target, 0700); err != nil {
		t.Fatal(err)
	}
	targetDB := filepath.Join(target, "db.sqlite")
	if err = os.WriteFile(targetDB, raw, 0600); err != nil {
		t.Fatal(err)
	}
	targetDir := filepath.Join(target, "tree")
	if err = os.Mkdir(targetDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{treeFenceFile, existingMasterBindingFile} {
		content, e := os.ReadFile(filepath.Join(fenceDir, name))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(targetDir, name), content, 0600); e != nil {
			t.Fatal(e)
		}
	}
	targetRoot, err := os.OpenRoot(targetDir)
	if err != nil {
		t.Fatal(err)
	}
	defer targetRoot.Close()
	targetGate, err := maintenance.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer targetGate.Close()
	if err = targetGate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	call := func(p fenceRecoveryEvidence, sha string) (bool, error) {
		return rebindOfflineFence(ctx, targetGate, target, targetDB, targetRoot, targetDir, master, nodeVault, node, sha, p)
	}
	if _, err = call(proof, strings.Repeat("f", 64)); err == nil {
		t.Fatal("mismatched archive accepted")
	}
	bad := proof
	bad.Inode++
	if _, err = call(bad, archiveSHA); err == nil {
		t.Fatal("tampered evidence accepted")
	}
	sqlDB, err := recoverySQLite(targetDB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sqlDB.Exec(`CREATE TRIGGER injected BEFORE UPDATE OF fence_tag ON sealed_tree_fence BEGIN SELECT RAISE(ABORT,'injected'); END`); err != nil {
		t.Fatal(err)
	}
	sqlDB.Close()
	if _, err = call(proof, archiveSHA); err == nil {
		t.Fatal("injected transaction failure accepted")
	}
	sqlDB, err = recoverySQLite(targetDB)
	if err != nil {
		t.Fatal(err)
	}
	var tag string
	var generation int64
	if err = sqlDB.QueryRow(`SELECT fence_tag FROM sealed_tree_fence WHERE singleton=1`).Scan(&tag); err != nil {
		t.Fatal(err)
	}
	if err = sqlDB.QueryRow(`SELECT write_fence FROM sealed_tree_meta WHERE singleton=1`).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	if tag != proof.OldTag || generation != proof.Generation {
		t.Fatal("failed transaction changed tag or generation")
	}
	if _, err = sqlDB.Exec(`DROP TRIGGER injected`); err != nil {
		t.Fatal(err)
	}
	sqlDB.Close()
	already, err := call(proof, archiveSHA)
	if err != nil || already {
		t.Fatal("rebind", already, err)
	}
	already, err = call(proof, archiveSHA)
	if err != nil || !already {
		t.Fatal("idempotent retry", already, err)
	}
	sqlDB, err = recoverySQLite(targetDB)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := OpenSQLiteWithMaster(ctx, sqlDB, master)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenFence(ctx, restored, targetRoot, targetDir); err != nil {
		t.Fatal("new binding not usable", err)
	}
	lease, err := restored.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = lease.Check(ctx); err != nil {
		t.Fatal(err)
	}
	lease.Release()
	sqlDB.Close()
	enabled, err := targetGate.Enabled()
	if err != nil || !enabled {
		t.Fatal("maintenance was cleared", err)
	}
	prior := filepath.Join(targetDir, treeFenceFile)
	contents, err := os.ReadFile(prior)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(prior, prior+".old"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(prior, contents, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = call(proof, archiveSHA); err == nil {
		t.Fatal("replaced recovery fence accepted")
	}
}
