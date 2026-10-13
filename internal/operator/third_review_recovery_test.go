package operator

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
)

func TestRecoverySetPreparationResumesDurableIntentAndMemberCheckpoints(t *testing.T) {
	for _, checkpoint := range []string{"intent", "all-members-prepared"} {
		t.Run(checkpoint, func(t *testing.T) {
			source, target, report, factory, _ := restoredSetFixture(t)
			state := RestoreSetState{Version: 1, Phase: "preparing_fenced", Source: source, Target: target, ProjectPrefix: "fc-prep", Report: report, Projects: map[string]string{}, Members: map[string]string{}}
			for _, member := range report.Manifest.Members {
				state.Projects[member.NodeID] = "fc-prep-" + member.NodeID
				state.Members[member.NodeID] = "material_verified"
			}
			if checkpoint == "all-members-prepared" {
				prepared, e := PrepareRestoreSet(context.Background(), source, target, report.SHA256, report.Manifest.MasterID, "fc-prep", factory)
				if e != nil {
					t.Fatal(e)
				}
				state = prepared
				state.Phase = "preparing_fenced"
			}
			if e := saveRestoreSet(state); e != nil {
				t.Fatal(e)
			}
			state, e := PrepareRestoreSet(context.Background(), source, target, report.SHA256, report.Manifest.MasterID, "fc-prep", factory)
			if e != nil || state.Phase != "prepared_fenced" {
				t.Fatal(state.Phase, e)
			}
		})
	}
}

func TestRecoverySetActivationResumesVerifiedFollowerCheckpoint(t *testing.T) {
	source, target, report, factory, _ := restoredSetFixture(t)
	ctx := context.Background()
	state, e := PrepareRestoreSet(ctx, source, target, report.SHA256, report.Manifest.MasterID, "fc-act", factory)
	if e != nil {
		t.Fatal(e)
	}
	state.Phase = "activating_fenced"
	if e = saveRestoreSet(state); e != nil {
		t.Fatal(e)
	}
	member := orderedSetMembers(report.Manifest)[0]
	d, r, e := openRestoredMember(ctx, state, member, factory)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = d.activateRestore(ctx, r, member.NodeID, true, true); e != nil {
		t.Fatal(e)
	}
	state, e = ActivateRestoreSet(ctx, target, report.SHA256, report.Manifest.MasterID, true, factory)
	if e != nil || state.Phase != "verified_fenced" {
		t.Fatal(state.Phase, e)
	}
}

func TestRestoreMarkerIntentResumesBeforeAndAfterPublication(t *testing.T) {
	for _, checkpoint := range []string{"before-stage", "partial-stage", "published", "administrator-replaced"} {
		t.Run(checkpoint, func(t *testing.T) {
			source, target, report, factory, _ := restoredSetFixture(t)
			state, e := PrepareRestoreSet(context.Background(), source, target, report.SHA256, report.Manifest.MasterID, "fc-marker", factory)
			if e != nil {
				t.Fatal(e)
			}
			member := report.Manifest.Members[0]
			d, _, e := openRestoredMember(context.Background(), state, member, factory)
			if e != nil {
				t.Fatal(e)
			}
			journal, e := d.restoreState()
			if e != nil {
				t.Fatal(e)
			}
			journal.Phase, journal.OwnManual, journal.ManualStaged = "creating_manual", true, true
			if e = d.saveRestore(journal); e != nil {
				t.Fatal(e)
			}
			data := filepath.Join(target, member.NodeID, "data")
			if checkpoint != "before-stage" {
				content := []byte("manual\n")
				if checkpoint == "partial-stage" {
					content = nil
				}
				if e = os.WriteFile(filepath.Join(data, restoreManualStage), content, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if checkpoint == "published" {
				if e = os.Link(filepath.Join(data, restoreManualStage), filepath.Join(data, sitecontrol.Manual)); e != nil {
					t.Fatal(e)
				}
			}
			if checkpoint == "administrator-replaced" {
				if e = os.WriteFile(filepath.Join(data, sitecontrol.Manual), []byte("manual\n"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			e = d.prepareRestoreManual(context.Background(), data, &journal)
			if checkpoint == "administrator-replaced" {
				if e == nil {
					t.Fatal("administrator marker claimed")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			a, _ := os.Stat(filepath.Join(data, sitecontrol.Manual))
			b, _ := os.Stat(filepath.Join(data, restoreManualStage))
			if !os.SameFile(a, b) {
				t.Fatal("marker ownership inode lost")
			}
		})
	}
}

func TestUpgradeResumeReconcilesPendingBackup(t *testing.T) {
	for _, checkpoint := range []string{"complete", "missing", "partial"} {
		t.Run(checkpoint, func(t *testing.T) {
			d, r, _, plan := upgradeFixture(t)
			ctx := context.Background()
			state, e := d.ApplyUpgrade(ctx, r, plan, plan.SHA256, plan.NodeID, filepath.Join(d.Directory, "backup.tar"), false, fakeEvidence{true}, upgradeImages{})
			if e != nil {
				t.Fatal(e)
			}
			state.Phase, state.BackupSHA = "backup_pending", ""
			if e = d.saveUpgrade(state); e != nil {
				t.Fatal(e)
			}
			if e = replaceJSON(filepath.Join(d.Directory, ReceiptFile), r); e != nil {
				t.Fatal(e)
			}
			images := map[string]map[string]string{}
			for name, image := range r.ServiceImages {
				images[name] = map[string]string{"image": image}
			}
			if e = replaceJSON(filepath.Join(d.Directory, ImagesFile), map[string]any{"services": images}); e != nil {
				t.Fatal(e)
			}
			if checkpoint == "missing" {
				if e = os.Remove(state.BackupFile); e != nil {
					t.Fatal(e)
				}
			}
			if checkpoint == "partial" {
				if e = os.WriteFile(state.BackupFile, []byte("retained incomplete archive"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			state, e = d.ResumeUpgrade(ctx, r, plan.SHA256, plan.NodeID, false, fakeEvidence{true}, upgradeImages{})
			if e != nil || state.Phase != "prepared_fenced" || state.BackupSHA == "" {
				t.Fatal(state.Phase, e)
			}
			if checkpoint == "partial" {
				retained, _ := filepath.Glob(state.BackupFile + ".interrupted-*")
				if len(retained) != 1 {
					t.Fatal("partial archive not retained")
				}
				bytes, _ := os.ReadFile(retained[0])
				if string(bytes) != "retained incomplete archive" {
					t.Fatal("partial archive bytes changed")
				}
			}
		})
	}
}
