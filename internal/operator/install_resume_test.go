package operator

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreparedInstallResumeKeepsIdentityAndSkipsInitializersAndPulls(t *testing.T) {
	d, receipt, runner, _ := upgradeFixture(t)
	receipt.State = "prepared"
	if e := replaceJSON(filepath.Join(d.Directory, ReceiptFile), receipt); e != nil {
		t.Fatal(e)
	}
	key := filepath.Join(runner.secrets, "node-vault.key")
	before, e := os.ReadFile(key)
	if e != nil {
		t.Fatal(e)
	}
	runner.calls = nil
	resumed, e := d.ResumeInstall(context.Background(), receipt)
	if e != nil || resumed.State != "ready" || resumed.Revision != receipt.Revision {
		t.Fatal(resumed, e)
	}
	after, e := os.ReadFile(key)
	if e != nil || string(before) != string(after) {
		t.Fatal("installation resume changed private identity material", e)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, " pull ") || strings.Contains(call, " latest") || strings.Contains(call, "-init") {
			t.Fatal("resume repeated fresh installation work", call)
		}
	}
	if _, e = d.ResumeInstall(context.Background(), resumed); e != nil {
		t.Fatal("ready resume is not idempotent", e)
	}
}

func TestPreparedInstallResumeRejectsConfigurationDrift(t *testing.T) {
	d, receipt, runner, _ := upgradeFixture(t)
	receipt.State = "prepared"
	service := runner.config.Services["web"]
	service.Environment["DATA_ROOT"] = "/unexpected"
	runner.config.Services["web"] = service
	runner.calls = nil
	if _, e := d.ResumeInstall(context.Background(), receipt); e == nil {
		t.Fatal("changed installation resumed")
	}
	for _, call := range runner.calls {
		if strings.Contains(call, " up ") {
			t.Fatal("changed installation started before binding validation", call)
		}
	}
}
