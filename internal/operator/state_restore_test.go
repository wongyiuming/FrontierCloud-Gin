package operator

import (
	"archive/tar"
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"os"
	"path/filepath"
	"testing"
)

func TestOrdinaryStateBackupRejectsIncompleteUpgrade(t *testing.T) {
	d, r, runner, p := upgradeFixture(t)
	state, e := d.ApplyUpgrade(context.Background(), r, p, p.SHA256, p.NodeID, filepath.Join(t.TempDir(), "upgrade.tar"), false, fakeEvidence{true}, upgradeImages{})
	if e != nil {
		t.Fatal(e)
	}
	_ = state
	_, next, e := Open(d.Directory)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = d.BackupState(context.Background(), next, filepath.Join(t.TempDir(), "blocked.tar"), true, false); e == nil {
		t.Fatal("fenced receipt admitted ordinary state backup")
	}
	if _, e = d.BackupState(context.Background(), r, filepath.Join(t.TempDir(), "blocked-source.tar"), true, false); e == nil {
		t.Fatal("pending journal admitted ordinary backup")
	}
	if !runner.stopped {
		t.Fatal("backup refusal opened writers")
	}
}

func TestStateRestoreChecksEveryDestinationCapacity(t *testing.T) {
	roots := map[string]string{"data": t.TempDir(), "runtime_secrets": t.TempDir()}
	entries := []recovery.Entry{{Path: "data/db", Bytes: 100}, {Path: "runtime_secrets/key", Bytes: 32}}
	seen := map[string]bool{}
	err := checkRestoreFilesystemCapacity(roots, entries, func(root string) (uint64, error) {
		seen[root] = true
		if root == roots["runtime_secrets"] {
			return 0, nil
		}
		return 1 << 30, nil
	}, func(root string) (string, error) { return root, nil })
	if err == nil || !seen[roots["runtime_secrets"]] {
		t.Fatal("full live destination filesystem passed", err, seen)
	}
}

func TestOrdinaryStateRestoreRejectsMissingActiveRelations(t *testing.T) {
	d, r, runner, _ := upgradeFixture(t)
	runner.role = "Master"
	runner.relations = []NodeFact{{NodeID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", State: "active", Direction: "downstream", Protocol: 2}}
	archive := filepath.Join(t.TempDir(), "cluster.tar")
	done, e := d.AcquireOperation()
	if e != nil {
		t.Fatal(e)
	}
	backup, e := d.backupLocked(context.Background(), r, archive, true, false)
	if closeErr := done(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = d.StateRestoreCheck(context.Background(), r, archive, backup.SHA256); e == nil {
		t.Fatal("uncoordinated active relations passed")
	}
}

func TestStateRestoreCanRetryHistoryAndEstablishMissingFence(t *testing.T) {
	d, r, runner, p := upgradeFixture(t)
	state, e := d.ApplyUpgrade(context.Background(), r, p, p.SHA256, p.NodeID, filepath.Join(t.TempDir(), "upgrade.tar"), false, fakeEvidence{true}, upgradeImages{})
	if e != nil {
		t.Fatal(e)
	}
	_, next, e := Open(d.Directory)
	if e != nil {
		t.Fatal(e)
	}
	state, e = d.OpenUpgrade(context.Background(), next, state.Plan.SHA256, runner.node)
	if e != nil {
		t.Fatal(e)
	}
	_, next, e = Open(d.Directory)
	if e != nil {
		t.Fatal(e)
	}
	archive := filepath.Join(t.TempDir(), "state.tar")
	backup, e := d.BackupState(context.Background(), next, archive, true, false)
	if e != nil {
		t.Fatal(e)
	}
	material := filepath.Join(t.TempDir(), "material")
	runner.fail = "info --format {{.Architecture}}"
	if _, e = d.RestoreState(context.Background(), next, archive, backup.SHA256, runner.node, material, true, true, false, false); e == nil {
		t.Fatal("injected pre-restoration failure missing")
	}
	runner.fail = ""
	if e = os.Remove(filepath.Join(runner.data, maintenance.Marker)); e != nil {
		t.Fatal(e)
	}
	if _, e = d.RestoreState(context.Background(), next, archive, backup.SHA256, runner.node, material, true, true, false, false); e == nil {
		t.Fatal("missing native fence accepted")
	}
	_, next, e = Open(d.Directory)
	if e != nil {
		t.Fatal(e)
	}
	state, e = d.RestoreState(context.Background(), next, archive, backup.SHA256, runner.node, material, true, true, true, false)
	if e != nil || state.Phase != "prepared_fenced" {
		t.Fatal("retry could not retain history and fence", state, e)
	}
}

func TestStateBackupRestoresNativeReceiptsAndMissingDirectoryMetadata(t *testing.T) {
	d, r, runner, _ := upgradeFixture(t)
	for _, name := range []string{".native-store", ".native-runtime"} {
		if e := os.WriteFile(filepath.Join(runner.data, name), []byte("captured-"+name), 0600); e != nil {
			t.Fatal(e)
		}
	}
	nested := filepath.Join(runner.secrets, "nested")
	if e := os.Mkdir(nested, 0750); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(nested, "identity"), []byte("directory-state"), 0600); e != nil {
		t.Fatal(e)
	}
	if os.Geteuid() == 0 {
		if e := os.Chown(nested, 65534, 65534); e != nil {
			t.Fatal(e)
		}
	}
	before, e := os.Stat(nested)
	if e != nil {
		t.Fatal(e)
	}
	want, e := tar.FileInfoHeader(before, "")
	if e != nil {
		t.Fatal(e)
	}
	archive := filepath.Join(t.TempDir(), "state.tar")
	backup, e := d.BackupState(context.Background(), r, archive, true, false)
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{".native-store", ".native-runtime"} {
		if e = os.Remove(filepath.Join(runner.data, name)); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.RemoveAll(nested); e != nil {
		t.Fatal(e)
	}
	state, e := d.RestoreState(context.Background(), r, archive, backup.SHA256, runner.node, filepath.Join(t.TempDir(), "material"), true, true, false, false)
	_ = state
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{".native-store", ".native-runtime"} {
		raw, e := os.ReadFile(filepath.Join(runner.data, name))
		if e != nil || string(raw) != "captured-"+name {
			t.Fatal("native receipt missing", e)
		}
	}
	info, e := os.Stat(nested)
	if e != nil {
		t.Fatal(e)
	}
	actual, e := tar.FileInfoHeader(info, "")
	if e != nil || actual.Uid != want.Uid || actual.Gid != want.Gid || actual.Mode != want.Mode {
		t.Fatal("directory metadata not restored", e)
	}
}

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
