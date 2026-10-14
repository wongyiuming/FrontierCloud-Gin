package operator

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
)

func TestFailedUpgradeStateRecoveryRestoresDatabaseKeyAndRetainsMedia(t *testing.T) {
	d, r, runner, p := upgradeFixture(t)
	keyPath := filepath.Join(runner.data, "media-keys", "media-premaster.key")
	if e := os.Mkdir(filepath.Dir(keyPath), 0700); e != nil {
		t.Fatal(e)
	}
	key := bytes.Repeat([]byte{7}, 32)
	if e := os.WriteFile(keyPath, key, 0600); e != nil {
		t.Fatal(e)
	}
	runner.fail = "prepare-release"
	state, e := d.ApplyUpgrade(context.Background(), r, p, p.SHA256, p.NodeID, filepath.Join(d.Directory, "recovery.tar"), false, fakeEvidence{true}, upgradeImages{})
	if e == nil || state.Phase != "failed_fenced" {
		t.Fatal(state, e)
	}
	check, e := recovery.Check(context.Background(), state.BackupFile, state.BackupSHA)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, ref := range check.Manifest.KeyReferences {
		if ref == "data/media-keys/media-premaster.key" {
			found = true
		}
	}
	if !found {
		t.Fatal("actual premaster archive reference missing")
	}
	database := filepath.Join(runner.data, "frontiercloud.db")
	if e = os.WriteFile(database, []byte("failed-schema-state"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(database+"-wal", []byte("failed-wal-state"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(keyPath, []byte("corrupt-key"), 0600); e != nil {
		t.Fatal(e)
	}
	_, next, e := Open(d.Directory)
	if e != nil {
		t.Fatal(e)
	}
	directory := filepath.Join(t.TempDir(), "retained-recovery")
	runner.fail = ""
	state, e = d.RecoverUpgradeState(context.Background(), next, p.SHA256, p.NodeID, state.BackupSHA, directory, false)
	if e != nil || state.Phase != "prepared_fenced" || state.Plan.RecoveryOf != p.SHA256 || state.Plan.Target != r.Revision {
		t.Fatal(state, e)
	}
	actual, e := os.ReadFile(database)
	if e != nil || string(actual) != "isolated-database-state" {
		t.Fatal("database not restored", e)
	}
	actual, e = os.ReadFile(keyPath)
	if e != nil || !bytes.Equal(actual, key) {
		t.Fatal("premaster not restored", e)
	}
	actual, e = os.ReadFile(filepath.Join(directory, "failed", "data", "frontiercloud.db"))
	if e != nil || string(actual) != "failed-schema-state" {
		t.Fatal("failed state discarded", e)
	}
	if _, e = os.Stat(database + "-wal"); !os.IsNotExist(e) {
		t.Fatal("failed WAL survived", e)
	}
	actual, e = os.ReadFile(filepath.Join(runner.data, "media", "music", "actual.mp3"))
	if e != nil || string(actual) != "ID3-actual-recovery-bytes" {
		t.Fatal("media changed", e)
	}
	if _, e = os.Stat(filepath.Join(runner.data, maintenance.Marker)); e != nil {
		t.Fatal("recovery opened writers", e)
	}
	_, next, e = Open(d.Directory)
	if e != nil {
		t.Fatal(e)
	}
	state, e = d.OpenUpgrade(context.Background(), next, state.Plan.SHA256, p.NodeID)
	if e != nil || state.Phase != "opened" {
		t.Fatal(state, e)
	}
}

func TestStateRecoveryRejectsOpenedOrUnapprovedUpgradeBeforeMutations(t *testing.T) {
	d, r, runner, p := upgradeFixture(t)
	state, e := d.ApplyUpgrade(context.Background(), r, p, p.SHA256, p.NodeID, filepath.Join(d.Directory, "recovery.tar"), false, fakeEvidence{true}, upgradeImages{})
	if e != nil {
		t.Fatal(e)
	}
	_, next, e := Open(d.Directory)
	if e != nil {
		t.Fatal(e)
	}
	runner.calls = nil
	if _, e = d.RecoverUpgradeState(context.Background(), next, p.SHA256, p.NodeID, state.BackupSHA, filepath.Join(t.TempDir(), "refused"), false); e == nil || len(runner.calls) != 0 {
		t.Fatal("prepared upgrade admitted rollback", e)
	}
	state, e = d.OpenUpgrade(context.Background(), next, p.SHA256, p.NodeID)
	if e != nil {
		t.Fatal(e)
	}
	_, next, e = Open(d.Directory)
	if e != nil {
		t.Fatal(e)
	}
	runner.calls = nil
	if _, e = d.RecoverUpgradeState(context.Background(), next, p.SHA256, p.NodeID, state.BackupSHA, filepath.Join(t.TempDir(), "refused"), false); e == nil || len(runner.calls) != 0 {
		t.Fatal("opened upgrade admitted destructive recovery", e)
	}
}
