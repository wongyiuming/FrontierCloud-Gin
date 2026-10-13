package operator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
)

func TestUpgradeResumeReconcilesBothSidesOfAtomicSwitch(t *testing.T) {
	for _, window := range []string{"old-lock-old-receipt", "new-lock-old-receipt", "new-lock-new-receipt", "preparing", "prepared"} {
		t.Run(window, func(t *testing.T) {
			d, original, runner, plan := upgradeFixture(t)
			ctx := context.Background()
			state, e := d.ApplyUpgrade(ctx, original, plan, plan.SHA256, plan.NodeID, filepath.Join(d.Directory, "backup.tar"), false, fakeEvidence{true}, upgradeImages{})
			if e != nil {
				t.Fatal(e)
			}
			_, next, e := Open(d.Directory)
			if e != nil {
				t.Fatal(e)
			}
			state.Phase = "switching_fenced"
			if window == "preparing" {
				state.Phase = "preparing_fenced"
			}
			if window == "prepared" {
				state.Phase = "prepared_fenced"
			}
			if e = d.saveUpgrade(state); e != nil {
				t.Fatal(e)
			}
			if strings.Contains(window, "old-receipt") {
				next = original
				if e = replaceJSON(filepath.Join(d.Directory, ReceiptFile), original); e != nil {
					t.Fatal(e)
				}
			}
			if strings.HasPrefix(window, "old-lock") {
				services := map[string]map[string]string{}
				for name, image := range original.ServiceImages {
					services[name] = map[string]string{"image": image}
				}
				if e = replaceJSON(filepath.Join(d.Directory, ImagesFile), map[string]any{"services": services}); e != nil {
					t.Fatal(e)
				}
			}
			if e = os.Remove(filepath.Join(runner.data, maintenance.Marker)); e != nil {
				t.Fatal(e)
			}
			state, e = d.ResumeUpgrade(ctx, next, plan.SHA256, plan.NodeID, false, fakeEvidence{true}, upgradeImages{})
			if e != nil || state.Phase != "prepared_fenced" {
				t.Fatal(state, e)
			}
			_, repaired, e := Open(d.Directory)
			if e != nil || repaired.Revision != plan.Target || repaired.State != "upgrade_fenced" {
				t.Fatal(repaired, e)
			}
			if _, e = os.Stat(filepath.Join(runner.data, maintenance.Marker)); e != nil {
				t.Fatal("resume opened native gate", e)
			}
		})
	}
}

func TestRestorePreparationRetryKeepsArchivedSourceProject(t *testing.T) {
	source, target, report, factory, _ := restoredSetFixture(t)
	ctx := context.Background()
	state, e := PrepareRestoreSet(ctx, source, target, report.SHA256, report.Manifest.MasterID, "fc-retry", factory)
	if e != nil {
		t.Fatal(e)
	}
	member := state.Report.Manifest.Members[0]
	d, _, e := openRestoredMember(ctx, state, member, factory)
	if e != nil {
		t.Fatal(e)
	}
	journal, e := d.restoreState()
	if e != nil {
		t.Fatal(e)
	}
	originalProject := journal.SourceProject
	journal.Phase = "preparing"
	if e = d.saveRestore(journal); e != nil {
		t.Fatal(e)
	}
	_, _, e = PrepareRestore(ctx, filepath.Join(target, member.NodeID), journal.Project, journal.Report, d.Runner)
	if e != nil {
		t.Fatal(e)
	}
	retried, e := d.restoreState()
	if e != nil || retried.SourceProject != originalProject || retried.SourceProject == retried.Project || retried.Phase != "prepared" {
		t.Fatal(retried, e)
	}
}

func TestRecoverySetResumesPartialPublicOpening(t *testing.T) {
	source, target, report, factory, _ := restoredSetFixture(t)
	ctx := context.Background()
	state, e := PrepareRestoreSet(ctx, source, target, report.SHA256, report.Manifest.MasterID, "fc-opening", factory)
	if e != nil {
		t.Fatal(e)
	}
	state, e = ActivateRestoreSet(ctx, target, report.SHA256, report.Manifest.MasterID, true, factory)
	if e != nil {
		t.Fatal(e)
	}
	state.Phase = "opening"
	if e = saveRestoreSet(state); e != nil {
		t.Fatal(e)
	}
	first := orderedSetMembers(state.Report.Manifest)[0]
	d, receipt, e := openRestoredMember(ctx, state, first, factory)
	if e != nil {
		t.Fatal(e)
	}
	journal, e := d.restoreState()
	if e != nil {
		t.Fatal(e)
	}
	journal.Phase = "opening"
	if e = d.saveRestore(journal); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(filepath.Join(target, first.NodeID, "data", sitecontrol.Manual)); e != nil {
		t.Fatal(e)
	}
	if _, e = d.openRestore(ctx, receipt, first.NodeID, true); e != nil {
		t.Fatal(e)
	}
	state, e = OpenRestoreSet(ctx, target, report.SHA256, report.Manifest.MasterID, factory)
	if e != nil || state.Phase != "opened" {
		t.Fatal(state, e)
	}
}

func TestAtomicOperatorJournalCanAdvancePastRetainedCrashScratch(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "journal.json")
	if e := os.WriteFile(path+".next", []byte("retained crash evidence"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := replaceJSON(path, map[string]string{"phase": "opening"}); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(path)
	var value map[string]string
	if e != nil || json.Unmarshal(raw, &value) != nil || value["phase"] != "opening" {
		t.Fatal(e)
	}
	if raw, e = os.ReadFile(path + ".next"); e != nil || string(raw) != "retained crash evidence" {
		t.Fatal("unrelated retained scratch changed", e)
	}
}
