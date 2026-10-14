package operator

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
)

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
	if e = checkMySQLRecoveryCredential(map[string]string{"runtime_secrets": dir}, []recovery.Entry{entry}); e != nil {
		t.Fatal(e)
	}
}
