package operator

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestMySQLRetryCountsOnlyReclaimablePerTableAllocation(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "frontiercloud")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	table := filepath.Join(dir, "media.ibd")
	if e := os.WriteFile(table, make([]byte, 1<<20), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "ibdata1"), make([]byte, 1<<20), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, "orphan.ibd"), make([]byte, 1<<20), 0600); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(table)
	if e != nil {
		t.Fatal(e)
	}
	expected := diskAllocated(info)
	reclaimed, e := mysqlReclaimableData(root, "frontiercloud", []string{"media"})
	if e != nil || reclaimed != expected {
		t.Fatal("shared tablespace counted or table allocation lost", reclaimed, expected, e)
	}
	const budget = uint64(768 << 20)
	if e = checkMySQLDataCapacity(root, budget, func(string) (uint64, error) { return budget + (512 << 20) - expected + reclaimed, nil }); e != nil {
		t.Fatal("completed import prevented retry", e)
	}
}

func TestMySQLRecoveryRefusesUnknownBudgetBeforeCompose(t *testing.T) {
	d, _, runner, _ := upgradeFixture(t)
	runner.calls = nil
	if err := d.checkMySQLRestoreCapacity(context.Background(), Config{}, 0, false); err == nil {
		t.Fatal("historical archive without storage evidence admitted")
	}
	if len(runner.calls) != 0 {
		t.Fatal("unknown budget invoked database or volume commands", runner.calls)
	}
}

func TestMySQLRecoveryChecksServerFilesystemReserve(t *testing.T) {
	const budget = uint64(768 << 20)
	const serverRoot = "/mysql-server-volume"
	for _, free := range []uint64{budget, budget + (512 << 20) - 1, budget + (512 << 20)} {
		err := checkMySQLDataCapacity(serverRoot, budget, func(root string) (uint64, error) {
			if root != serverRoot {
				t.Fatal("checked archive destination instead of MySQL data filesystem")
			}
			return free, nil
		})
		if (err == nil) != (free >= budget+(512<<20)) {
			t.Fatal("import capacity failed to preserve reserve", free, err)
		}
	}
}
