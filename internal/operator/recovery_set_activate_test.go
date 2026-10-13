package operator

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
)

type setRestoreRunner struct {
	*upgradeRunner
	directory string
	source    Config
	onRun     func(string)
}

func (r *setRestoreRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	if r.onRun != nil {
		r.onRun(call)
	}
	if strings.Contains(call, " config ") {
		if strings.Contains(call, RecoveredCompose) {
			return os.ReadFile(filepath.Join(r.directory, RecoveredCompose))
		}
		return json.Marshal(r.source)
	}
	return r.upgradeRunner.Run(ctx, name, args...)
}
func restoredSetFixture(t *testing.T) (string, string, recovery.SetReport, RecoveryRunnerFactory, map[string]*setRestoreRunner) {
	t.Helper()
	items, sourceRunners := recoverySetFixture(t)
	ctx := context.Background()
	source := filepath.Join(t.TempDir(), "archives")
	target := filepath.Join(t.TempDir(), "target")
	report, e := BackupSet(ctx, items, source, sourceRunners[0].node, true, false)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = recovery.ApplySet(ctx, source, target, report.SHA256, report.Manifest.MasterID); e != nil {
		t.Fatal(e)
	}
	runners := map[string]*setRestoreRunner{}
	for i, item := range items {
		node := sourceRunners[i].node
		cfg := sourceRunners[i].config
		cfg.Services = map[string]Service{}
		for name, service := range sourceRunners[i].config.Services {
			service.Image = item.Receipt.ServiceImages[name]
			cfg.Services[name] = service
		}
		base := &fakeRunner{config: cfg}
		native := &upgradeRunner{fakeRunner: base, data: filepath.Join(target, node, "data"), node: node, role: sourceRunners[i].role, relations: sourceRunners[i].relations, stopped: true}
		runners[node] = &setRestoreRunner{upgradeRunner: native, directory: filepath.Join(target, node, "deployment"), source: cfg}
	}
	factory := func(directory string) Runner { return runners[filepath.Base(filepath.Dir(directory))] }
	return source, target, report, factory, runners
}
func TestRecoverySetPreparationRejectsChangedAndExtraMaterialBeforeAnyReceipt(t *testing.T) {
	for _, kind := range []string{"changed-media", "added-wal", "wrong-set-marker"} {
		t.Run(kind, func(t *testing.T) {
			source, target, report, runners, _ := restoredSetFixture(t)
			member := report.Manifest.Members[0]
			file := filepath.Join(target, member.NodeID, "data", "media", "music", "actual.mp3")
			switch kind {
			case "added-wal":
				file = filepath.Join(target, member.NodeID, "data", "foreign.db-wal")
			case "wrong-set-marker":
				file = filepath.Join(target, member.NodeID, "deployment", RecoverySetMarker)
			}
			if e := os.WriteFile(file, []byte("unapproved replacement"), 0600); e != nil {
				t.Fatal(e)
			}
			if _, e := PrepareRestoreSet(context.Background(), source, target, report.SHA256, report.Manifest.MasterID, "recover", runners); e == nil {
				t.Fatal("changed material admitted")
			}
			for _, m := range report.Manifest.Members {
				if _, e := os.Stat(filepath.Join(target, m.NodeID, "deployment", RestoreJournal)); !os.IsNotExist(e) {
					t.Fatal("member prepared before whole-set validation", e)
				}
			}
		})
	}
}
func TestRecoverySetActivatesAndOpensMasterLastAfterWholeSetVerification(t *testing.T) {
	source, target, report, factory, runners := restoredSetFixture(t)
	ctx := context.Background()
	state, e := PrepareRestoreSet(ctx, source, target, report.SHA256, report.Manifest.MasterID, "recover", factory)
	if e != nil {
		t.Fatal(e)
	}
	if state.Phase != "prepared_fenced" {
		t.Fatal(state)
	}
	if _, e = OpenRestoreSet(ctx, target, report.SHA256, report.Manifest.MasterID, factory); e == nil {
		t.Fatal("opened before whole-set activation")
	}
	var starts []string
	for node, runner := range runners {
		node := node
		runner.onRun = func(call string) {
			if strings.Contains(call, "maintenance resume") {
				starts = append(starts, node)
			}
		}
	}
	if _, e = ActivateRestoreSet(ctx, target, report.SHA256, report.Manifest.MasterID, false, factory); e == nil {
		t.Fatal("source-offline attestation bypassed")
	}
	state, e = ActivateRestoreSet(ctx, target, report.SHA256, report.Manifest.MasterID, true, factory)
	if e != nil {
		t.Fatal(e)
	}
	if state.Phase != "verified_fenced" || !state.Report.BusinessVerified || len(starts) != 2 || starts[len(starts)-1] != report.Manifest.MasterID {
		t.Fatal(state, starts)
	}
	for _, m := range report.Manifest.Members {
		if _, e = os.Stat(filepath.Join(target, m.NodeID, "data", sitecontrol.Manual)); e != nil {
			t.Fatal("public opening during activation", e)
		}
		d, r, e := Open(filepath.Join(target, m.NodeID, "deployment"))
		if e != nil {
			t.Fatal(e)
		}
		d.Runner = factory(d.Directory)
		if _, e = d.OpenRestore(ctx, r, m.NodeID); e == nil {
			t.Fatal("individual opening bypassed set approval")
		}
	}
	// The final Master verification must see already-open followers; earlier
	// group verification sees all manual gates and does not count as opening.
	masterCheckedLast := false
	runners[report.Manifest.MasterID].onRun = func(call string) {
		if strings.Contains(call, "exec -T web /app/frontiercloud recovery-verify") {
			for _, m := range report.Manifest.Members {
				if m.NodeID != report.Manifest.MasterID {
					if _, e = os.Stat(filepath.Join(target, m.NodeID, "data", sitecontrol.Manual)); os.IsNotExist(e) {
						masterCheckedLast = true
					}
				}
			}
		}
	}
	state, e = OpenRestoreSet(ctx, target, report.SHA256, report.Manifest.MasterID, factory)
	if e != nil {
		t.Fatal(e)
	}
	if state.Phase != "opened" || !masterCheckedLast {
		t.Fatal(state, "Master not opened last")
	}
	for _, m := range report.Manifest.Members {
		if _, e = os.Stat(filepath.Join(target, m.NodeID, "deployment", RecoverySetMarker)); !os.IsNotExist(e) {
			t.Fatal("completed set still blocked", e)
		}
		_, r, e := Open(filepath.Join(target, m.NodeID, "deployment"))
		if e != nil || r.State != "ready" {
			t.Fatal(r, e)
		}
	}
	if _, e = OpenRestoreSet(ctx, target, report.SHA256, report.Manifest.MasterID, factory); e != nil {
		t.Fatal("cleanup/completion retry not idempotent", e)
	}
}
func TestRecoverySetActivationFailureRefencesEveryMemberAndPreservesArchives(t *testing.T) {
	source, target, report, factory, runners := restoredSetFixture(t)
	ctx := context.Background()
	if _, e := PrepareRestoreSet(ctx, source, target, report.SHA256, report.Manifest.MasterID, "recover", factory); e != nil {
		t.Fatal(e)
	}
	runners[report.Manifest.MasterID].fail = "recovery-verify"
	state, e := ActivateRestoreSet(ctx, target, report.SHA256, report.Manifest.MasterID, true, factory)
	if e == nil || state.Phase != "failed_fenced" {
		t.Fatal(state, e)
	}
	for _, m := range report.Manifest.Members {
		if _, e = os.Stat(filepath.Join(target, m.NodeID, "data", maintenance.Marker)); e != nil {
			t.Fatal("partial restoration escaped native fence", e)
		}
		if !runners[m.NodeID].stopped {
			t.Fatal("partial restoration writer still running")
		}
	}
	if _, e = recovery.CheckSet(ctx, source, report.SHA256); e != nil {
		t.Fatal("failure lost approved source set", e)
	}
	if _, e = OpenRestoreSet(ctx, target, report.SHA256, report.Manifest.MasterID, factory); e == nil {
		t.Fatal("failed set opened")
	}
	persisted, e := readRestoreSet(target)
	if e != nil || persisted.Phase != state.Phase {
		t.Fatal("returned failure state differs from durable journal", persisted, e)
	}
}
func TestRecoverySetMarkerCleanupResumesAfterInterrupt(t *testing.T) {
	source, target, report, factory, _ := restoredSetFixture(t)
	ctx := context.Background()
	if _, e := PrepareRestoreSet(ctx, source, target, report.SHA256, report.Manifest.MasterID, "recover", factory); e != nil {
		t.Fatal(e)
	}
	if _, e := ActivateRestoreSet(ctx, target, report.SHA256, report.Manifest.MasterID, true, factory); e != nil {
		t.Fatal(e)
	}
	state, e := OpenRestoreSet(ctx, target, report.SHA256, report.Manifest.MasterID, factory)
	if e != nil {
		t.Fatal(e)
	}
	state.Phase = "opened_cleanup_pending"
	if e = saveRestoreSet(state); e != nil {
		t.Fatal(e)
	}
	state, e = OpenRestoreSet(ctx, target, report.SHA256, report.Manifest.MasterID, factory)
	if e != nil || state.Phase != "opened" {
		t.Fatal(state, e)
	}
	if _, e = OpenRestoreSet(ctx, target, strings.Repeat("0", 64), report.Manifest.MasterID, factory); e == nil || errors.Is(e, os.ErrNotExist) {
		t.Fatal("cleanup accepted wrong approval", e)
	}
}

func TestRecoverySetCancellationStillRefencesAlreadyResumedMembers(t *testing.T) {
	source, target, report, factory, runners := restoredSetFixture(t)
	if _, e := PrepareRestoreSet(context.Background(), source, target, report.SHA256, report.Manifest.MasterID, "recover", factory); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runners[report.Manifest.MasterID].onRun = func(call string) {
		if strings.Contains(call, "maintenance resume") {
			cancel()
		}
	}
	state, e := ActivateRestoreSet(ctx, target, report.SHA256, report.Manifest.MasterID, true, factory)
	if e == nil || state.Phase != "failed_fenced" {
		t.Fatal(state, e)
	}
	for _, m := range report.Manifest.Members {
		if !runners[m.NodeID].stopped {
			t.Fatal("cancellation left a resumed member")
		}
		if _, e = os.Stat(filepath.Join(target, m.NodeID, "data", maintenance.Marker)); e != nil {
			t.Fatal(e)
		}
	}
}
func TestRecoverySetRejectsJournalRosterDriftBeforeActivation(t *testing.T) {
	source, target, report, factory, _ := restoredSetFixture(t)
	state, e := PrepareRestoreSet(context.Background(), source, target, report.SHA256, report.Manifest.MasterID, "recover", factory)
	if e != nil {
		t.Fatal(e)
	}
	state.Report.Manifest.Members[0].Revision = strings.Repeat("f", 40)
	if e = saveRestoreSet(state); e != nil {
		t.Fatal(e)
	}
	if _, e = ActivateRestoreSet(context.Background(), target, report.SHA256, report.Manifest.MasterID, true, factory); e == nil {
		t.Fatal("journal changed an approved archive member")
	}
}
