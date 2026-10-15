package operator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
)

func TestOrdinaryStateBackupRejectsRelationsBeforeFreeze(t *testing.T) {
	d, r, runner, _ := upgradeFixture(t)
	runner.relations = []NodeFact{{NodeID: strings.Repeat("a", 32), State: "active"}}
	output := filepath.Join(t.TempDir(), "refused.tar")
	if _, e := d.BackupState(context.Background(), r, output, true, false); e == nil {
		t.Fatal("unrestorable ordinary cluster archive admitted")
	}
	if _, e := os.Lstat(output); !os.IsNotExist(e) {
		t.Fatal("refused archive was published", e)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "maintenance enter") || strings.Contains(call, " stop ") {
			t.Fatal("cluster refusal froze writers", call)
		}
	}
}

func TestOrdinaryRestoreRetryRejectsDatabaseReceiptDrift(t *testing.T) {
	d, r, runner, p := upgradeFixture(t)
	r.Database = "mysql"
	r.State = "upgrade_fenced"
	p.StateRestore = true
	p.Database = "mysql"
	p.SHA256 = p.digest()
	state := UpgradeState{Version: 1, Phase: "restoring_state", Plan: p, Previous: r, RestoreReceipt: &r, BackupSHA: strings.Repeat("a", 64)}
	if e := d.saveUpgrade(state); e != nil {
		t.Fatal(e)
	}
	runner.calls = nil
	tampered := r
	tampered.Database = "sqlite"
	if _, e := d.RestoreState(context.Background(), tampered, "unused", state.BackupSHA, p.NodeID, t.TempDir(), true, true, true, false); e == nil {
		t.Fatal("database drift bypassed external-writer confirmation")
	}
	if len(runner.calls) != 0 {
		t.Fatal("tampered retry invoked Docker before refusal", runner.calls)
	}
}

func TestRestoreCapacityAggregatesGrowthAcrossStateRoots(t *testing.T) {
	roots := map[string]string{"data": t.TempDir(), "runtime_secrets": t.TempDir()}
	entries := []recovery.Entry{{Path: "data/db", Bytes: 1 << 30}, {Path: "runtime_secrets/missing-key", Bytes: 1 << 30}}
	for _, available := range []uint64{(1 << 30) + (600 << 20), (3 << 30) + (512 << 20)} {
		err := checkRestoreFilesystemCapacity(roots, entries, func(string) (uint64, error) { return available, nil }, func(string) (string, error) { return "same-device", nil })
		if (err == nil) != (available >= (3<<30)+(512<<20)) {
			t.Fatal("shared filesystem growth not budgeted", available, err)
		}
	}
}

func TestRestoreCapacityDoesNotTreatSparseFilesAsReleasedSpace(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"db", "wal"} {
		f, e := os.Create(filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}
		e = f.Truncate(1 << 30)
		if closeErr := f.Close(); e != nil || closeErr != nil {
			t.Fatal(e, closeErr)
		}
	}
	entries := []recovery.Entry{{Path: "data/db", Bytes: 1 << 30}, {Path: "data/wal", Bytes: 1 << 30}}
	err := checkRestoreFilesystemCapacity(map[string]string{"data": dir}, entries, func(string) (uint64, error) { return (1 << 30) + (600 << 20), nil }, func(string) (string, error) { return "sparse-device", nil })
	if err == nil {
		t.Fatal("sparse logical size counted as released allocation")
	}
}

func TestMySQLCredentialDriftRefusedWithoutReplacingSecret(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "mysql_root_password")
	if e := os.WriteFile(file, []byte("current-test-password"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, "mysql_password"), []byte("application-test-password"), 0600); e != nil {
		t.Fatal(e)
	}
	appHash := sha256.Sum256([]byte("application-test-password"))
	appEntry := recovery.Entry{Path: "runtime_secrets/mysql_password", SHA256: hex.EncodeToString(appHash[:])}
	h := sha256.Sum256([]byte("archived-test-password"))
	entry := recovery.Entry{Path: "runtime_secrets/mysql_root_password", SHA256: hex.EncodeToString(h[:])}
	if e := checkMySQLRecoveryCredential(map[string]string{"runtime_secrets": dir}, []recovery.Entry{entry}); e == nil {
		t.Fatal("credential drift admitted")
	}
	actual, e := os.ReadFile(file)
	if e != nil || string(actual) != "current-test-password" {
		t.Fatal("credential preflight replaced live secret", e)
	}
	h = sha256.Sum256(actual)
	entry.SHA256 = hex.EncodeToString(h[:])
	if e = checkMySQLRecoveryCredential(map[string]string{"runtime_secrets": dir}, []recovery.Entry{entry, appEntry}); e != nil {
		t.Fatal(e)
	}
	appFile := filepath.Join(dir, "mysql_password")
	if e = os.WriteFile(appFile, []byte("rotated-application-password"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = checkMySQLRecoveryCredential(map[string]string{"runtime_secrets": dir}, []recovery.Entry{entry, appEntry}); e == nil {
		t.Fatal("application credential drift admitted despite unchanged root credential")
	}
	appActual, e := os.ReadFile(appFile)
	if e != nil || string(appActual) != "rotated-application-password" {
		t.Fatal("application credential refusal changed live state", e)
	}
}
