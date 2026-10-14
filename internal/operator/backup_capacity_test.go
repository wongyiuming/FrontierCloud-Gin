package operator

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackupCapacityIsReadOnlyAndIncludesActualManagedRoots(t *testing.T) {
	d, r, runner, _ := upgradeFixture(t)
	runner.calls = nil
	before, err := os.ReadDir(d.Directory)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "new.tar")
	p, err := d.BackupCapacity(context.Background(), r, output)
	if err != nil || !p.Fits || p.DataBytes < 1 || p.ScratchBytes < 1 || p.ArchiveBytes <= p.DataBytes || p.RequiredBytes <= p.ArchiveBytes || !p.ReadOnly {
		t.Fatal(p, err)
	}
	after, err := os.ReadDir(d.Directory)
	if err != nil || len(before) != len(after) {
		t.Fatal("capacity inspection wrote state", err)
	}
	if _, err = os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("output created", err)
	}
	for _, call := range runner.calls {
		for _, bad := range []string{" pull ", " run ", " up ", " stop ", "maintenance enter"} {
			if strings.Contains(call, bad) {
				t.Fatal("capacity froze or started a writer", call)
			}
		}
	}
}

func TestInsufficientBackupCapacityRefusesUpgradeBeforeFreezeOrJournal(t *testing.T) {
	d, r, runner, plan := upgradeFixture(t)
	output := filepath.Join(t.TempDir(), "new.tar")
	p, err := d.BackupCapacity(context.Background(), r, output)
	if err != nil {
		t.Fatal(err)
	}
	// A sparse source proves that capacity counts logical archive bytes, not blocks.
	f, err := os.Create(filepath.Join(runner.data, "huge.dat"))
	if err != nil {
		t.Fatal(err)
	}
	err = f.Truncate(int64(p.FreeBytes) + (1 << 30))
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	runner.calls = nil
	if _, err = d.ApplyUpgrade(context.Background(), r, plan, plan.SHA256, plan.NodeID, output, false, fakeEvidence{true}, upgradeImages{}); err == nil || !strings.Contains(err.Error(), "capacity insufficient") {
		t.Fatal(err)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "maintenance enter") || strings.Contains(call, " stop ") {
			t.Fatal("capacity failure stopped source", call)
		}
	}
	for _, name := range []string{UpgradeJournal, OperationLock} {
		if _, err = os.Lstat(filepath.Join(d.Directory, name)); !os.IsNotExist(err) {
			t.Fatal("capacity failure left state", name, err)
		}
	}
}

func TestBackupCapacityRejectsOutputInsideSourceAndUnsafeEntries(t *testing.T) {
	for _, kind := range []string{"inside", "existing", "link", "missing-parent"} {
		t.Run(kind, func(t *testing.T) {
			d, r, runner, _ := upgradeFixture(t)
			output := filepath.Join(t.TempDir(), "new.tar")
			switch kind {
			case "inside":
				output = filepath.Join(runner.data, "new.tar")
			case "existing":
				if err := os.WriteFile(output, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "link":
				if err := os.Symlink("/outside", filepath.Join(runner.data, "unsafe")); err != nil {
					t.Fatal(err)
				}
			case "missing-parent":
				output = filepath.Join(t.TempDir(), "missing", "new.tar")
			}
			if _, err := d.BackupCapacity(context.Background(), r, output); err == nil {
				t.Fatal("unsafe capacity proof accepted", kind)
			}
		})
	}
}
