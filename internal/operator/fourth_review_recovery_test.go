package operator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
)

func TestPreparingSetRetainsKnownAtomicPublicationResidue(t *testing.T) {
	source, target, report, factory, _ := restoredSetFixture(t)
	state, e := PrepareRestoreSet(context.Background(), source, target, report.SHA256, report.Manifest.MasterID, "fc-scratch", factory)
	if e != nil {
		t.Fatal(e)
	}
	state.Phase = "preparing_fenced"
	if e = saveRestoreSet(state); e != nil {
		t.Fatal(e)
	}
	member := report.Manifest.Members[0]
	residue := filepath.Join(target, member.NodeID, "deployment", ImagesFile+".next-retained")
	if e = os.WriteFile(residue, []byte("interrupted private metadata"), 0600); e != nil {
		t.Fatal(e)
	}
	state, e = PrepareRestoreSet(context.Background(), source, target, report.SHA256, report.Manifest.MasterID, "fc-scratch", factory)
	if e != nil || state.Phase != "prepared_fenced" {
		t.Fatal(state.Phase, e)
	}
	bytes, e := os.ReadFile(residue)
	if e != nil || string(bytes) != "interrupted private metadata" {
		t.Fatal("crash evidence changed", e)
	}
}

func TestUpgradeMarkerIntentCannotClaimAdministratorFile(t *testing.T) {
	d, receipt, runner, plan := upgradeFixture(t)
	ctx := context.Background()
	state, e := d.ApplyUpgrade(ctx, receipt, plan, plan.SHA256, plan.NodeID, filepath.Join(d.Directory, "backup.tar"), false, fakeEvidence{true}, upgradeImages{})
	if e != nil {
		t.Fatal(e)
	}
	_, target, e := Open(d.Directory)
	if e != nil {
		t.Fatal(e)
	}
	state.Phase, state.ManualOwned, state.ManualStaged = "activating_fenced", true, true
	if e = d.saveUpgrade(state); e != nil {
		t.Fatal(e)
	}
	marker := filepath.Join(runner.data, sitecontrol.Manual)
	if e = os.WriteFile(marker, []byte("manual\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = d.OpenUpgrade(ctx, target, plan.SHA256, plan.NodeID); e == nil {
		t.Fatal("administrator maintenance claimed")
	}
	if _, e = os.Stat(marker); e != nil {
		t.Fatal("administrator marker removed", e)
	}
}

func TestInitializingReceiptReconstructsMissingImageLock(t *testing.T) {
	d, receipt, _, _ := upgradeFixture(t)
	receipt.State = "initializing"
	if e := replaceJSON(filepath.Join(d.Directory, ReceiptFile), receipt); e != nil {
		t.Fatal(e)
	}
	if e := os.Remove(filepath.Join(d.Directory, ImagesFile)); e != nil {
		t.Fatal(e)
	}
	resumed, e := d.ResumeInstall(context.Background(), receipt)
	if e != nil || resumed.State != "ready" {
		t.Fatal(resumed.State, e)
	}
	if _, e = d.ValidateReceipt(context.Background(), resumed); e != nil {
		t.Fatal(e)
	}
}

func TestReceiptBindsFullVolumeAndNetworkDefinitions(t *testing.T) {
	for _, field := range []string{"volumes", "networks", "configs", "secrets"} {
		t.Run(field, func(t *testing.T) {
			d, receipt, runner, _ := upgradeFixture(t)
			definitions := map[string]any{}
			if field == "volumes" {
				raw, _ := json.Marshal(runner.config.Volumes)
				_ = json.Unmarshal(raw, &definitions)
				for name, value := range definitions {
					v := value.(map[string]any)
					v["driver"] = "local"
					v["driver_opts"] = map[string]any{"type": "none", "o": "bind", "device": "/unapproved"}
					definitions[name] = v
				}
			} else {
				definitions["unapproved"] = map[string]any{"driver": "changed", "file": "/unapproved"}
			}
			raw, _ := json.Marshal(definitions)
			runner.config.Definitions = map[string]json.RawMessage{field: raw}
			if _, e := d.ValidateReceipt(context.Background(), receipt); e == nil {
				t.Fatal("unbound root definition accepted", field)
			}
		})
	}
}

type cleanupFailureRunner struct {
	*upgradeRunner
	parent string
}

func (r *cleanupFailureRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	result, e := r.upgradeRunner.Run(ctx, name, args...)
	workspaces, _ := filepath.Glob(filepath.Join(r.parent, ".fc-backup-*"))
	for _, root := range workspaces {
		_ = os.WriteFile(filepath.Join(root, "retained-cleanup-evidence"), []byte("cleanup remains pending"), 0600)
	}
	return result, e
}

func TestUpgradeRetainsVerifiedBackupWhenGeneratedScratchCleanupFails(t *testing.T) {
	d, receipt, runner, plan := upgradeFixture(t)
	d.Runner = &cleanupFailureRunner{upgradeRunner: runner, parent: d.Directory}
	state, e := d.ApplyUpgrade(context.Background(), receipt, plan, plan.SHA256, plan.NodeID, filepath.Join(d.Directory, "backup.tar"), false, fakeEvidence{true}, upgradeImages{})
	if e != nil || state.Phase != "prepared_fenced" || state.BackupCleanupWarning == "" || state.BackupScratch == "" {
		t.Fatal(state.Phase, state.BackupCleanupWarning, e)
	}
	verified, e := recovery.Check(context.Background(), state.BackupFile, state.BackupSHA)
	if e != nil || !verified.Verified {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(state.BackupScratch, "retained-cleanup-evidence")); e != nil {
		t.Fatal("retained cleanup material lost", e)
	}
}
