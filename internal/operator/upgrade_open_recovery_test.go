package operator

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
)

func TestUpgradeOpenRecoversDurableInterruptedOpeningAndReceiptWindows(t *testing.T) {
	for _, phase := range []string{"activating_fenced", "verified_fenced", "opening", "opened"} {
		for _, markerPresent := range []bool{false, true} {
			if phase == "opened" && markerPresent {
				continue // An unowned new administrator marker is tested below.
			}
			t.Run(phase+map[bool]string{true: "-marker", false: "-removed"}[markerPresent], func(t *testing.T) {
				d, source, runner, plan := upgradeFixture(t)
				ctx := context.Background()
				state, e := d.ApplyUpgrade(ctx, source, plan, plan.SHA256, plan.NodeID, filepath.Join(d.Directory, "recovery.tar"), false, fakeEvidence{true}, upgradeImages{})
				if e != nil {
					t.Fatal(e)
				}
				_, target, e := Open(d.Directory)
				if e != nil {
					t.Fatal(e)
				}
				if phase != "activating_fenced" {
					state, e = d.OpenUpgrade(ctx, target, plan.SHA256, plan.NodeID)
					if e != nil {
						t.Fatal(e)
					}
				}
				// Recreate the durable files left by process loss at each boundary;
				// runtime identity, recovery bytes, schema and images stay unchanged.
				state.Phase = phase
				state.ManualOwned = phase != "opened"
				if e = d.saveUpgrade(state); e != nil {
					t.Fatal(e)
				}
				if e = replaceJSON(filepath.Join(d.Directory, ReceiptFile), target); e != nil {
					t.Fatal(e)
				}
				if markerPresent {
					if e = os.WriteFile(filepath.Join(runner.data, sitecontrol.Manual), []byte("manual\n"), 0600); e != nil {
						t.Fatal(e)
					}
				}
				runner.onFact = func() {
					if _, e := os.Stat(filepath.Join(runner.data, sitecontrol.Manual)); e != nil {
						t.Fatal("opening recovery inspected runtime before restoring public maintenance", e)
					}
				}
				state, e = d.OpenUpgrade(ctx, target, plan.SHA256, plan.NodeID)
				if e != nil || state.Phase != "opened" || state.ManualOwned || !state.BusinessVerified {
					t.Fatal(state, e)
				}
				_, ready, e := Open(d.Directory)
				if e != nil || ready.State != "ready" {
					t.Fatal(ready, e)
				}
				if _, e = d.OpenUpgrade(ctx, ready, plan.SHA256, plan.NodeID); e != nil {
					t.Fatal("successful open replay is not idempotent", e)
				}
			})
		}
	}
}

func TestOpenedUpgradeWithPendingReceiptCannotClaimNewAdministratorMaintenance(t *testing.T) {
	d, source, runner, plan := upgradeFixture(t)
	ctx := context.Background()
	if _, e := d.ApplyUpgrade(ctx, source, plan, plan.SHA256, plan.NodeID, filepath.Join(d.Directory, "recovery.tar"), false, fakeEvidence{true}, upgradeImages{}); e != nil {
		t.Fatal(e)
	}
	_, target, e := Open(d.Directory)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = d.OpenUpgrade(ctx, target, plan.SHA256, plan.NodeID); e != nil {
		t.Fatal(e)
	}
	if e = replaceJSON(filepath.Join(d.Directory, ReceiptFile), target); e != nil {
		t.Fatal(e)
	}
	marker := filepath.Join(runner.data, sitecontrol.Manual)
	if e = os.WriteFile(marker, []byte("manual\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = d.OpenUpgrade(ctx, target, plan.SHA256, plan.NodeID); e == nil {
		t.Fatal("unowned administrator maintenance was reopened")
	}
	if _, e = os.Stat(marker); e != nil {
		t.Fatal("administrator marker lost", e)
	}
}
