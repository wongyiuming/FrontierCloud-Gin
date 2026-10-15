package operator

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMissingOrCorruptAdmissionRefusedBeforeUpgradeFreeze(t *testing.T) {
	for _, name := range []string{".native-store", ".native-runtime"} {
		for _, missing := range []bool{true, false} {
			t.Run(name+map[bool]string{true: "-missing", false: "-corrupt"}[missing], func(t *testing.T) {
				d, r, runner, p := upgradeFixture(t)
				data := runner.data
				file := filepath.Join(data, name)
				var e error
				if missing {
					e = os.Remove(file)
				} else {
					e = os.WriteFile(file, []byte("malformed-admission"), 0600)
				}
				if e != nil {
					t.Fatal(e)
				}
				runner.calls = nil
				_, e = d.ApplyUpgrade(context.Background(), r, p, p.SHA256, p.NodeID, filepath.Join(d.Directory, "refused.tar"), false, fakeEvidence{true}, upgradeImages{})
				if e == nil {
					t.Fatal("invalid admission published a recovery point")
				}
				for _, call := range runner.calls {
					if strings.Contains(call, "maintenance enter") || strings.Contains(call, " stop ") {
						t.Fatal("invalid admission froze writers", call)
					}
				}
				if _, e = os.Lstat(filepath.Join(d.Directory, UpgradeJournal)); !os.IsNotExist(e) {
					t.Fatal("upgrade journal published despite invalid admission", e)
				}
			})
		}
	}
}
