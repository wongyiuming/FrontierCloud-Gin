package operator

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
)

func TestSimpleUpgradeOwnsPlanBackupAndOpening(t *testing.T) {
	d, r, runner, p := upgradeFixture(t)
	confirmations := 0
	result, e := d.Upgrade(context.Background(), r, p.Target, "amd64", fakeEvidence{true}, upgradeImages{}, func(preview UpgradePreview) (UpgradeConsent, error) {
		confirmations++
		if preview.Capacity == nil || preview.Capacity.BusinessFilesIncluded || preview.Plan.NodeID != p.NodeID {
			t.Fatal("invalid preview", preview)
		}
		return UpgradeConsent{Approved: true}, nil
	})
	if e != nil || confirmations != 1 || result.Phase != "opened" || !result.BusinessVerified {
		t.Fatal(result, confirmations, e)
	}
	saved, e := d.upgradeState()
	if e != nil || saved.Plan.SHA256 == "" {
		t.Fatal(e)
	}
	plan, e := ReadUpgradePlan(filepath.Join(d.Directory, ".foc-upgrade-plan-"+saved.Plan.SHA256+".json"))
	if e != nil || plan.SHA256 != saved.Plan.SHA256 {
		t.Fatal(e)
	}
	_, current, e := Open(d.Directory)
	if e != nil {
		t.Fatal(e)
	}
	runner.calls = nil
	result, e = d.Upgrade(context.Background(), current, p.Target, "amd64", fakeEvidence{true}, upgradeImages{}, func(UpgradePreview) (UpgradeConsent, error) {
		t.Fatal("already current prompted")
		return UpgradeConsent{}, nil
	})
	if e != nil || result.Phase != "already_current" {
		t.Fatal(result, e)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "maintenance enter") || strings.Contains(call, " up ") {
			t.Fatal("already current changed business", call)
		}
	}
}

func TestSimpleUpgradeRetriesReadyCleanupAndRejectsChangedStage(t *testing.T) {
	for _, contents := range []string{"manual\n", "changed\n"} {
		t.Run(strings.TrimSpace(contents), func(t *testing.T) {
			d, r, runner, p := upgradeFixture(t)
			ctx := context.Background()
			if _, e := d.Upgrade(ctx, r, p.Target, "amd64", fakeEvidence{true}, upgradeImages{}, func(UpgradePreview) (UpgradeConsent, error) {
				return UpgradeConsent{Approved: true}, nil
			}); e != nil {
				t.Fatal(e)
			}
			s, e := d.upgradeState()
			if e != nil {
				t.Fatal(e)
			}
			stage := filepath.Join(runner.data, upgradeManualStage+"-"+s.Plan.SHA256)
			admin := filepath.Join(runner.data, sitecontrol.Manual)
			for name, value := range map[string]string{stage: contents, admin: "manual\n"} {
				if e = os.WriteFile(name, []byte(value), 0600); e != nil {
					t.Fatal(e)
				}
			}
			s.StageCleanupWarning = "retained generated stage requires cleanup"
			if e = d.saveUpgrade(s); e != nil {
				t.Fatal(e)
			}
			_, ready, e := Open(d.Directory)
			if e != nil {
				t.Fatal(e)
			}
			runner.calls = nil
			result, e := d.Upgrade(ctx, ready, p.Target, "amd64", fakeEvidence{true}, upgradeImages{}, func(UpgradePreview) (UpgradeConsent, error) {
				t.Fatal("ready cleanup prompted for a new upgrade")
				return UpgradeConsent{}, nil
			})
			if contents == "manual\n" {
				if e != nil || result.Phase != "already_current" {
					t.Fatal(result, e)
				}
				if _, e = os.Stat(stage); !os.IsNotExist(e) {
					t.Fatal("generated stage retained", e)
				}
				s, e = d.upgradeState()
				if e != nil || s.StageCleanupWarning != "" {
					t.Fatal(s.StageCleanupWarning, e)
				}
			} else {
				if e == nil {
					t.Fatal("changed cleanup evidence accepted")
				}
				value, err := os.ReadFile(stage)
				if err != nil || string(value) != contents {
					t.Fatal("changed stage removed", err)
				}
			}
			if value, err := os.ReadFile(admin); err != nil || string(value) != "manual\n" {
				t.Fatal("administrator maintenance changed", err)
			}
			for _, call := range runner.calls {
				if strings.Contains(call, "maintenance enter") || strings.Contains(call, " up ") || strings.Contains(call, " stop ") {
					t.Fatal("cleanup mutated business services", call)
				}
			}
		})
	}
}

func TestSimpleUpgradeResumesOpenedJournalBeforeReadyReceipt(t *testing.T) {
	d, r, runner, p := upgradeFixture(t)
	ctx := context.Background()
	approve := func(UpgradePreview) (UpgradeConsent, error) { return UpgradeConsent{Approved: true}, nil }
	if _, e := d.Upgrade(ctx, r, p.Target, "amd64", fakeEvidence{true}, upgradeImages{}, approve); e != nil {
		t.Fatal(e)
	}
	s, e := d.upgradeState()
	if e != nil {
		t.Fatal(e)
	}
	_, current, e := Open(d.Directory)
	if e != nil {
		t.Fatal(e)
	}
	// Recreate the durable crash boundary: journal opened, receipt still fenced,
	// public marker removed, generated ownership stage not yet cleaned up.
	current.State = "upgrade_fenced"
	if e = replaceJSON(filepath.Join(d.Directory, ReceiptFile), current); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(runner.data, upgradeManualStage+"-"+s.Plan.SHA256), []byte("manual\n"), 0600); e != nil {
		t.Fatal(e)
	}
	confirmations := 0
	result, e := d.Upgrade(ctx, current, p.Target, "amd64", fakeEvidence{true}, upgradeImages{}, func(preview UpgradePreview) (UpgradeConsent, error) {
		confirmations++
		if preview.ResumePhase != "opened" || preview.Plan.SHA256 != s.Plan.SHA256 || preview.Capacity != nil {
			t.Fatal("opening recovery created another plan/backup", preview)
		}
		return UpgradeConsent{Approved: true}, nil
	})
	if e != nil || result.Phase != "opened" || !result.BusinessVerified || confirmations != 1 {
		t.Fatal(result, confirmations, e)
	}
	_, ready, e := Open(d.Directory)
	if e != nil || ready.State != "ready" || ready.Revision != p.Target {
		t.Fatal(ready, e)
	}
	if result.BackupFile != s.BackupFile || result.BackupSHA != s.BackupSHA {
		t.Fatal("original recovery point changed", result)
	}
}

type simpleUpgradeEvidenceFunc func(context.Context, string) (map[string]any, error)

func (f simpleUpgradeEvidenceFunc) Artifact(ctx context.Context, target string) (map[string]any, error) {
	return f(ctx, target)
}

func TestSimpleUpgradeRefreshesReleasePlanAfterCapacityBeforeConsent(t *testing.T) {
	d, r, runner, p := upgradeFixture(t)
	runner.calls = nil
	proofs := 0
	evidence := simpleUpgradeEvidenceFunc(func(ctx context.Context, target string) (map[string]any, error) {
		proofs++
		if proofs == 2 {
			seen := false
			for _, call := range runner.calls {
				if strings.Contains(call, "context inspect") {
					seen = true
				}
			}
			if !seen {
				t.Fatal("plan refreshed before capacity inspection")
			}
		}
		return (fakeEvidence{true}).Artifact(ctx, target)
	})
	_, e := d.Upgrade(context.Background(), r, p.Target, "amd64", evidence, upgradeImages{}, func(preview UpgradePreview) (UpgradeConsent, error) {
		if proofs != 2 || preview.Capacity == nil || preview.Capacity.Output != filepath.Join(d.Directory, ".foc-before-"+preview.Plan.SHA256+".tar") {
			t.Fatal("consent did not receive refreshed plan and matching capacity", proofs, preview)
		}
		return UpgradeConsent{}, nil
	})
	if e == nil {
		t.Fatal("cancelled upgrade succeeded")
	}
	if _, e = os.Stat(filepath.Join(d.Directory, UpgradeJournal)); !os.IsNotExist(e) {
		t.Fatal("capacity preview published journal", e)
	}
}

func TestSimpleUpgradeCancellationDoesNotPublishPlanOrFreeze(t *testing.T) {
	d, r, runner, p := upgradeFixture(t)
	_, e := d.Upgrade(context.Background(), r, p.Target, "amd64", fakeEvidence{true}, upgradeImages{}, func(UpgradePreview) (UpgradeConsent, error) { return UpgradeConsent{}, nil })
	if e == nil {
		t.Fatal("cancelled upgrade succeeded")
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "maintenance enter") || strings.Contains(call, " stop ") || strings.Contains(call, " pull ") {
			t.Fatal("cancelled upgrade mutated engine", call)
		}
	}
	paths, _ := filepath.Glob(filepath.Join(d.Directory, ".foc-*"))
	if len(paths) != 0 {
		t.Fatal("cancelled upgrade published managed files", paths)
	}
}

func TestSimpleUpgradeResumesPreparedAndRefusesFailedOrOtherTarget(t *testing.T) {
	for _, phase := range []string{"prepared_fenced", "failed_fenced"} {
		t.Run(phase, func(t *testing.T) {
			d, r, _, p := upgradeFixture(t)
			s, e := d.ApplyUpgrade(context.Background(), r, p, p.SHA256, p.NodeID, filepath.Join(d.Directory, "saved.tar"), false, fakeEvidence{true}, upgradeImages{})
			if e != nil {
				t.Fatal(e)
			}
			s.Phase = phase
			if e = d.saveUpgrade(s); e != nil {
				t.Fatal(e)
			}
			_, current, e := Open(d.Directory)
			if e != nil {
				t.Fatal(e)
			}
			approve := func(preview UpgradePreview) (UpgradeConsent, error) {
				if preview.ResumePhase != phase {
					t.Fatal(preview)
				}
				return UpgradeConsent{Approved: true}, nil
			}
			if _, e = d.Upgrade(context.Background(), current, strings.Repeat("c", 40), "amd64", fakeEvidence{true}, upgradeImages{}, approve); e == nil {
				t.Fatal("different target resumed")
			}
			result, e := d.Upgrade(context.Background(), current, p.Target, "amd64", fakeEvidence{true}, upgradeImages{}, approve)
			if phase == "prepared_fenced" && (e != nil || result.Phase != "opened") {
				t.Fatal(result, e)
			}
			if phase == "failed_fenced" && e == nil {
				t.Fatal("failed upgrade automatically reopened")
			}
			if _, e = os.Stat(filepath.Join(d.Directory, "saved.tar")); e != nil {
				t.Fatal("recovery point lost", e)
			}
		})
	}
}
