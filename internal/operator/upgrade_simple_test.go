package operator

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
