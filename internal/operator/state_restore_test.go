package operator

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOrdinaryStateBackupRestoresWithoutUpgradeJournal(t *testing.T) {
	d, r, runner, _ := upgradeFixture(t)
	archive := filepath.Join(t.TempDir(), "state.tar")
	backup, e := d.BackupState(context.Background(), r, archive, true, false)
	if e != nil {
		t.Fatal(e)
	}
	database := filepath.Join(runner.data, "frontiercloud.db")
	if e = os.Remove(database); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(runner.secrets, "metrics_token"), []byte("target-created-secret"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(d.Directory, UpgradeJournal)); !os.IsNotExist(e) {
		t.Fatal("unexpected upgrade journal", e)
	}
	directory := filepath.Join(t.TempDir(), "ordinary-state-recovery")
	state, e := d.RestoreState(context.Background(), r, archive, backup.SHA256, runner.node, directory, true, true, false, false)
	if e != nil || state.Phase != "prepared_fenced" || !state.Plan.StateRestore {
		t.Fatal(state, e)
	}
	actual, e := os.ReadFile(database)
	if e != nil || string(actual) != "isolated-database-state" {
		t.Fatal("ordinary database state not restored", e)
	}
	if _, e = os.Stat(filepath.Join(runner.secrets, "metrics_token")); !os.IsNotExist(e) {
		t.Fatal("target-created secret survived", e)
	}
	actual, e = os.ReadFile(filepath.Join(directory, "failed", "runtime_secrets", "metrics_token"))
	if e != nil || string(actual) != "target-created-secret" {
		t.Fatal("target-created secret was not retained", e)
	}
	_, next, e := Open(d.Directory)
	if e != nil {
		t.Fatal(e)
	}
	state, e = d.OpenUpgrade(context.Background(), next, state.Plan.SHA256, runner.node)
	if e != nil || state.Phase != "opened" {
		t.Fatal(state, e)
	}
}

func TestRecoveryDirectoryRefusesSymlinkedAncestors(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "data")
	if e := os.Mkdir(real, 0700); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(root, "data-link")
	if e := os.Symlink(real, link); e != nil {
		t.Skip(e)
	}
	if _, e := safeRecoveryDirectory(filepath.Join(link, "recovery"), false); e == nil {
		t.Fatal("symlinked recovery ancestor admitted")
	}
	if _, e := os.Stat(filepath.Join(real, "recovery")); !os.IsNotExist(e) {
		t.Fatal("invalid recovery created material", e)
	}
}
