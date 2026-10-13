package operator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
)

func TestRestoredDeploymentCanBackUpAndRestoreItsActualBoundStateAgain(t *testing.T) {
	d, receipt, source, _ := upgradeFixture(t)
	ctx := context.Background()
	// Model the actual runtime secret consumer, not an unused declaration.
	web := source.config.Services["web"]
	web.Volumes = append(web.Volumes, Mount{Type: "volume", Source: "runtime_secrets", Target: "/run/frontiercloud-secrets"})
	source.config.Services["web"] = web
	receipt.SelectionHash = selectionHash(source.config)
	if e := replaceJSON(filepath.Join(d.Directory, ReceiptFile), receipt); e != nil {
		t.Fatal(e)
	}
	archive := filepath.Join(t.TempDir(), "first.tar")
	report, e := d.Backup(ctx, receipt, archive, true, false)
	if e != nil {
		t.Fatal(e)
	}
	first := filepath.Join(t.TempDir(), "first")
	if _, e = recovery.Apply(ctx, archive, first, report.SHA256, source.node); e != nil {
		t.Fatal(e)
	}
	cfg := source.config
	cfg.Services = map[string]Service{}
	for name, s := range source.config.Services {
		s.Image = receipt.ServiceImages[name]
		cfg.Services[name] = s
	}
	native := &upgradeRunner{fakeRunner: &fakeRunner{config: cfg}, data: filepath.Join(first, "data"), node: source.node, stopped: true}
	runner := &setRestoreRunner{upgradeRunner: native, directory: filepath.Join(first, "deployment"), source: cfg}
	restored, restoredReceipt, e := PrepareRestore(ctx, first, "recovered-first", report, runner)
	if e != nil {
		t.Fatal(e)
	}
	// Make a new durable secret prove that the second archive reads this bind,
	// never the old named source volume or an empty newly named declaration.
	if e = os.WriteFile(filepath.Join(first, "runtime_secrets", "retained-proof"), []byte("bound-private-state"), 0600); e != nil {
		t.Fatal(e)
	}
	// A receipt can describe a changed mount, but that does not grant it a
	// recovery class. An arbitrary secret bind must never become complete.
	originalCompose, e := os.ReadFile(filepath.Join(first, "deployment", RecoveredCompose))
	if e != nil {
		t.Fatal(e)
	}
	var changed map[string]any
	if json.Unmarshal(originalCompose, &changed) != nil {
		t.Fatal("invalid generated config")
	}
	foreign := t.TempDir()
	if e = os.WriteFile(filepath.Join(foreign, "foreign-secret"), []byte("must-not-capture"), 0600); e != nil {
		t.Fatal(e)
	}
	services := changed["services"].(map[string]any)
	for _, raw := range services["web"].(map[string]any)["volumes"].([]any) {
		mount := raw.(map[string]any)
		if mount["target"] == "/run/frontiercloud-secrets" {
			mount["source"] = foreign
		}
	}
	if e = replaceJSON(filepath.Join(first, "deployment", RecoveredCompose), changed); e != nil {
		t.Fatal(e)
	}
	changedReceipt := restoredReceipt
	changedConfig, e := restored.Config(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	changedReceipt.SelectionHash = selectionHash(changedConfig)
	if e = replaceJSON(filepath.Join(first, "deployment", ReceiptFile), changedReceipt); e != nil {
		t.Fatal(e)
	}
	invalid, e := restored.Backup(ctx, changedReceipt, filepath.Join(t.TempDir(), "unsafe.tar"), false, false)
	if e == nil && invalid.Manifest.CompleteCluster {
		t.Fatal("foreign bind was classified as complete")
	}
	for _, entry := range invalid.Manifest.Files {
		if entry.Path == "runtime_secrets/foreign-secret" {
			t.Fatal("unclassified bind was captured as trusted secrets")
		}
	}
	if e = os.WriteFile(filepath.Join(first, "deployment", RecoveredCompose), originalCompose, 0600); e != nil {
		t.Fatal(e)
	}
	if e = replaceJSON(filepath.Join(first, "deployment", ReceiptFile), restoredReceipt); e != nil {
		t.Fatal(e)
	}
	secondArchive := filepath.Join(t.TempDir(), "second.tar")
	secondReport, e := restored.Backup(ctx, restoredReceipt, secondArchive, false, false)
	if e != nil {
		t.Fatal(e)
	}
	if !secondReport.Manifest.CompleteCluster || len(secondReport.Manifest.Missing) != 0 {
		t.Fatal(secondReport.Manifest.Missing)
	}
	second := filepath.Join(t.TempDir(), "second")
	if _, e = recovery.Apply(ctx, secondArchive, second, secondReport.SHA256, source.node); e != nil {
		t.Fatal(e)
	}
	actual, e := os.ReadFile(filepath.Join(second, "runtime_secrets", "retained-proof"))
	if e != nil || string(actual) != "bound-private-state" {
		t.Fatal("repeated recovery lost the active secret bind", e)
	}
	raw, e := os.ReadFile(filepath.Join(second, "deployment", RecoveredCompose))
	if e != nil {
		t.Fatal(e)
	}
	var secondConfig Config
	if json.Unmarshal(raw, &secondConfig) != nil {
		t.Fatal("invalid archived recovered config")
	}
	secondNative := &upgradeRunner{fakeRunner: &fakeRunner{config: secondConfig}, data: filepath.Join(second, "data"), node: source.node, stopped: true}
	secondRunner := &setRestoreRunner{upgradeRunner: secondNative, directory: filepath.Join(second, "deployment"), source: secondConfig}
	// The archived generated file is an input on second recovery, so the new
	// prepared project must replace it atomically rather than claim it is absent.
	_, secondReceipt, e := PrepareRestore(ctx, second, "recovered-second", secondReport, secondRunner)
	if e != nil {
		t.Fatal(e)
	}
	if secondReceipt.Project != "recovered-second" || !secondReceipt.Recovered {
		t.Fatal(secondReceipt)
	}
	raw, e = os.ReadFile(filepath.Join(second, "deployment", RecoveredCompose))
	if e != nil {
		t.Fatal(e)
	}
	if json.Unmarshal(raw, &secondConfig) != nil {
		t.Fatal("invalid prepared config")
	}
	for _, mount := range secondConfig.Services["web"].Volumes {
		if mount.Target == "/run/frontiercloud-secrets" && mount.Source != filepath.Join(second, "runtime_secrets") {
			t.Fatal("second recovery retained previous secret bind")
		}
	}
}
