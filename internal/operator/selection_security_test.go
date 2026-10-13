package operator

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestReceiptRejectsExecutionAndIsolationDriftBeforeOperations(t *testing.T) {
	changes := map[string]string{
		"entrypoint": `["/bin/sh"]`, "command": `["changed"]`, "user": `"0"`,
		"privileged": `true`, "cap_add": `["SYS_ADMIN"]`, "cap_drop": `["ALL"]`,
		"security_opt": `["seccomp=unconfined"]`, "read_only": `true`,
		"network_mode": `"host"`, "pid": `"host"`, "ipc": `"host"`,
		"devices": `["/dev/mem:/dev/mem"]`, "healthcheck": `{"test":["CMD","changed"]}`,
		"future_isolation_setting": `{"allow":true}`,
	}
	for field, value := range changes {
		t.Run(field, func(t *testing.T) {
			d, _, runner, _ := upgradeFixture(t)
			_, receipt, e := Open(d.Directory)
			if e != nil {
				t.Fatal(e)
			}
			service := runner.config.Services["web"]
			service.Execution = map[string]json.RawMessage{field: json.RawMessage(value)}
			runner.config.Services["web"] = service
			runner.calls = nil
			if _, e = d.ValidateReceipt(context.Background(), receipt); e == nil {
				t.Fatal("receipt accepted execution drift", field)
			}
			for _, call := range runner.calls {
				if !strings.Contains(call, " config --format json") {
					t.Fatal("drift inspection performed extra operations", runner.calls)
				}
			}
		})
	}
}

func TestSelectionHashCanonicalizesExecutionObjectsWithoutSecretRotationDrift(t *testing.T) {
	var a, b Config
	if e := json.Unmarshal([]byte(`{"name":"x","services":{"web":{"image":"a","environment":{"ADMIN_KEY":"old"},"healthcheck":{"timeout":"5s","test":["CMD","ok"]}}}}`), &a); e != nil {
		t.Fatal(e)
	}
	if e := json.Unmarshal([]byte(`{"services":{"web":{"healthcheck":{"test":["CMD","ok"],"timeout":"5s"},"environment":{"ADMIN_KEY":"rotated"},"image":"b"}},"name":"x"}`), &b); e != nil {
		t.Fatal(e)
	}
	if selectionHash(a) != selectionHash(b) {
		t.Fatal("JSON member order, image or secret rotation altered the selection")
	}
}
