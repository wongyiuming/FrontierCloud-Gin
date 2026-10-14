package operator

import (
	"context"
	"testing"
)

func TestMySQLRecoveryRefusesUnknownBudgetBeforeCompose(t *testing.T) {
	d, _, runner, _ := upgradeFixture(t)
	runner.calls = nil
	if err := d.checkMySQLRestoreCapacity(context.Background(), Config{}, 0); err == nil {
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
