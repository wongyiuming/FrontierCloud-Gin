package operator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
)

type restoreFailureRunner struct {
	Runner
	cancel           context.CancelFunc
	stopFails        bool
	cleanupAttempted bool
}

func (r *restoreFailureRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	call := strings.Join(args, " ")
	if strings.Contains(call, "recovery-verify") {
		r.cancel()
		return nil, errors.New("injected restored managed read failure")
	}
	if strings.Contains(call, " stop ") {
		r.cleanupAttempted = ctx.Err() == nil
		if r.stopFails {
			return nil, errors.New("injected unreachable Docker daemon")
		}
	}
	return r.Runner.Run(ctx, name, args...)
}

func TestRestoreActivationFailureVerifiesFenceAfterCallerCancellation(t *testing.T) {
	for _, stopFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "verified-stop", true: "unverified-stop"}[stopFails], func(t *testing.T) {
			source, target, report, factory, _ := restoredSetFixture(t)
			if _, err := PrepareRestoreSet(context.Background(), source, target, report.SHA256, report.Manifest.MasterID, "recovery-failure", factory); err != nil {
				t.Fatal(err)
			}
			member := report.Manifest.Members[0]
			directory := filepath.Join(target, member.NodeID, "deployment")
			d, receipt, err := Open(directory)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runner := &restoreFailureRunner{Runner: factory(directory), cancel: cancel, stopFails: stopFails}
			d.Runner = runner
			state, err := d.activateRestore(ctx, receipt, member.NodeID, true, true)
			want := "failed_fenced"
			if stopFails {
				want = "failed_fence_unverified"
			}
			if err == nil || state.Phase != want || !runner.cleanupAttempted {
				t.Fatal("restore failed to preserve an accurate cancellation-safe fence", state.Phase, err)
			}
			persisted, err := d.restoreState()
			if err != nil || persisted.Phase != want {
				t.Fatal("failure journal lost", err)
			}
			if _, err = os.Stat(filepath.Join(target, member.NodeID, "data", maintenance.Marker)); err != nil {
				t.Fatal("native gate was not durably closed", err)
			}
			if _, err = recovery.CheckSet(context.Background(), source, report.SHA256); err != nil {
				t.Fatal("failure lost recovery material", err)
			}
			if _, err = d.openRestore(context.Background(), receipt, member.NodeID, true); err == nil {
				t.Fatal("failed restore reopened")
			}
		})
	}
}
