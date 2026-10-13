package operator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
)

func TestExclusiveJSONPublishesCompleteFileAndDoesNotOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "intent.json")
	if e := os.WriteFile(path+".next-interrupted", []byte("partial"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := exclusiveJSON(path, map[string]string{"phase": "initializing"}); e != nil {
		t.Fatal(e)
	}
	bytes, e := os.ReadFile(path)
	var value map[string]string
	if e != nil || json.Unmarshal(bytes, &value) != nil || value["phase"] != "initializing" {
		t.Fatal(e)
	}
	if e = exclusiveJSON(path, map[string]string{"phase": "changed"}); !os.IsExist(e) {
		t.Fatal("exclusive publication overwrote intent", e)
	}
	after, _ := os.ReadFile(path)
	if string(bytes) != string(after) {
		t.Fatal("intent changed")
	}
}

func TestPriorUpgradeArchiveRetryRequiresByteIdenticalJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.json")
	value := map[string]string{"phase": "opened", "plan": "same"}
	if e := exclusiveJSONOrSame(path, value); e != nil {
		t.Fatal(e)
	}
	if e := exclusiveJSONOrSame(path, value); e != nil {
		t.Fatal("history retry blocked", e)
	}
	if e := exclusiveJSONOrSame(path, map[string]string{"phase": "different"}); e == nil {
		t.Fatal("conflicting history accepted")
	}
}

func TestRestoreRejectsAdministratorMaintenanceBeforeActivationAndCanRetryAfterClearance(t *testing.T) {
	source, target, report, factory, _ := restoredSetFixture(t)
	ctx := context.Background()
	state, e := PrepareRestoreSet(ctx, source, target, report.SHA256, report.Manifest.MasterID, "fc-admin", factory)
	if e != nil {
		t.Fatal(e)
	}
	member := report.Manifest.Members[0]
	d, r, e := openRestoredMember(ctx, state, member, factory)
	if e != nil {
		t.Fatal(e)
	}
	marker := filepath.Join(target, member.NodeID, "data", sitecontrol.Manual)
	if e = os.WriteFile(marker, []byte("manual\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = d.activateRestore(ctx, r, member.NodeID, true, true); e == nil {
		t.Fatal("administrator maintenance silently activated")
	}
	journal, e := d.restoreState()
	if e != nil || journal.Phase != "prepared" {
		t.Fatal(journal.Phase, e)
	}
	if e = os.Remove(marker); e != nil {
		t.Fatal(e)
	}
	journal, e = d.activateRestore(ctx, r, member.NodeID, true, true)
	if e != nil || journal.Phase != "verified" || !journal.OwnManual {
		t.Fatal(journal.Phase, e)
	}
}

func TestRecoverySetReportsMemberScratchCleanupWarnings(t *testing.T) {
	items, runners := recoverySetFixture(t)
	output := filepath.Join(t.TempDir(), "archives")
	for i := range items {
		items[i].Deployment.Runner = &cleanupFailureRunner{upgradeRunner: runners[i], parent: output}
	}
	report, e := BackupSet(context.Background(), items, output, runners[0].node, true, false)
	if e != nil || !report.Verified || len(report.CleanupWarnings) != len(items) {
		t.Fatal(report.CleanupWarnings, e)
	}
	for _, warning := range report.CleanupWarnings {
		if warning.Warning == "" || warning.RetainedScratch == "" {
			t.Fatal("member cleanup warning lost")
		}
	}
}

func TestReadyUpgradeRetriesOnlyItsRecordedStageCleanup(t *testing.T) {
	d, r, runner, plan := upgradeFixture(t)
	ctx := context.Background()
	if _, e := d.ApplyUpgrade(ctx, r, plan, plan.SHA256, plan.NodeID, filepath.Join(d.Directory, "backup.tar"), false, fakeEvidence{true}, upgradeImages{}); e != nil {
		t.Fatal(e)
	}
	_, target, e := Open(d.Directory)
	if e != nil {
		t.Fatal(e)
	}
	state, e := d.OpenUpgrade(ctx, target, plan.SHA256, plan.NodeID)
	if e != nil {
		t.Fatal(e)
	}
	_, ready, e := Open(d.Directory)
	if e != nil {
		t.Fatal(e)
	}
	stage := filepath.Join(runner.data, upgradeManualStage+"-"+plan.SHA256)
	if e = os.WriteFile(stage, []byte("manual\n"), 0600); e != nil {
		t.Fatal(e)
	}
	admin := filepath.Join(runner.data, sitecontrol.Manual)
	if e = os.WriteFile(admin, []byte("manual\n"), 0600); e != nil {
		t.Fatal(e)
	}
	state.StageCleanupWarning = "retained generated stage requires cleanup"
	if e = d.saveUpgrade(state); e != nil {
		t.Fatal(e)
	}
	state, e = d.OpenUpgrade(ctx, ready, plan.SHA256, plan.NodeID)
	if e != nil || state.StageCleanupWarning != "" {
		t.Fatal(state.StageCleanupWarning, e)
	}
	if _, e = os.Stat(stage); !os.IsNotExist(e) {
		t.Fatal("recorded generated stage retained", e)
	}
	if _, e = os.Stat(admin); e != nil {
		t.Fatal("administrator maintenance removed", e)
	}
}
