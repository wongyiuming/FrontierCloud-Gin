package operator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOperationLockSerializesMutationsAndNeverAutoTakesOver(t *testing.T) {
	d, _ := fixture(t)
	done, e := d.AcquireOperation()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = d.AcquireOperation(); e == nil {
		t.Fatal("concurrent operator mutation admitted")
	}
	report := d.Doctor(context.Background())
	blocked := false
	for _, check := range report.Checks {
		if check.Item == "host_operation" && check.State == "blocked" {
			blocked = true
		}
	}
	if !blocked {
		t.Fatal(report)
	}
	done()
	if _, e = os.Stat(filepath.Join(d.Directory, OperationLock)); !os.IsNotExist(e) {
		t.Fatal(e)
	}
}

type writerStateRunner struct{ states []byte }

func (r writerStateRunner) Run(context.Context, string, ...string) ([]byte, error) {
	return r.states, nil
}
func TestBackupWriterBoundaryRejectsEveryActiveStateExceptMySQL(t *testing.T) {
	for _, state := range []string{"running", "restarting", "paused", "removing", "unknown"} {
		d, _ := fixture(t)
		raw, _ := json.Marshal([]map[string]string{{"Service": "web", "State": state}, {"Service": "mysql", "State": "running"}})
		d.Runner = writerStateRunner{raw}
		if e := d.stoppedWriters(context.Background()); e == nil {
			t.Fatal("active writer accepted", state)
		}
	}
	d, _ := fixture(t)
	d.Runner = writerStateRunner{[]byte(`{"Service":"web","State":"exited"}
{"Service":"certificate-agent","State":"exited"}
{"Service":"mysql","State":"running"}
`)}
	if e := d.stoppedWriters(context.Background()); e != nil {
		t.Fatal(e)
	}
}
func TestBackupRejectsUnboundDeploymentBeforeFreeze(t *testing.T) {
	d, r := fixture(t)
	_, e := d.Backup(context.Background(), Receipt{}, filepath.Join(d.Directory, "backup.tar"), true, false)
	if e == nil {
		t.Fatal("unbound state accepted")
	}
	for _, call := range r.calls {
		if strings.Contains(call, "maintenance enter") || strings.Contains(call, " stop ") {
			t.Fatal("mutated before binding proof", call)
		}
	}
}
