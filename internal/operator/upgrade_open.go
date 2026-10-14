package operator

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
)

func (d *Deployment) localUpgradeEngine(ctx context.Context, arch string) error {
	raw, e := d.Runner.Run(ctx, "docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}")
	var endpoint string
	if e != nil || json.Unmarshal(raw, &endpoint) != nil || !strings.HasPrefix(endpoint, "unix://") || os.Getenv("DOCKER_HOST") != "" && !strings.HasPrefix(os.Getenv("DOCKER_HOST"), "unix://") {
		return errors.New("upgrade requires this host's local Unix-socket Docker engine")
	}
	raw, e = d.Runner.Run(ctx, "docker", "info", "--format", "{{.Architecture}}")
	if e != nil || Architecture(string(raw)) != arch {
		return errors.New("Docker architecture changed since upgrade planning")
	}
	return nil
}

func upgradeDataRoot(cfg Config) (string, error) {
	web := cfg.Services["web"]
	for _, m := range web.Volumes {
		if m.Type == "bind" && !m.ReadOnly && m.Target == web.Environment["DATA_ROOT"] {
			info, e := os.Lstat(m.Source)
			if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return "", errors.New("recorded native data root is unsafe")
			}
			return m.Source, nil
		}
	}
	return "", errors.New("upgrade requires the recorded local native data root bind")
}

func (d *Deployment) fenceUpgradeFailure(ctx context.Context, cfg Config) bool {
	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	data, e := upgradeDataRoot(cfg)
	if e != nil {
		return false
	}
	gate, e := maintenance.Open(data)
	if e != nil {
		return false
	}
	defer gate.Close()
	// Enter durably sets the marker before waiting for the runtime. Stop the
	// exact deployment services even if draining or Docker acknowledgement fails.
	drainCtx, drainCancel := context.WithTimeout(stopCtx, 5*time.Second)
	_ = gate.Enter(drainCtx, func(context.Context) error { return nil })
	drainCancel()
	var names []string
	for _, name := range sortedServices(serviceImageMap(cfg)) {
		if name != "mysql" {
			names = append(names, name)
		}
	}
	_, e = d.Compose(stopCtx, true, append([]string{"stop"}, names...)...)
	if e != nil {
		return false
	}
	return gate.Inspect(stopCtx, func(ctx context.Context) error { return d.stoppedWriters(ctx) }) == nil
}
func serviceImageMap(cfg Config) map[string]string {
	result := map[string]string{}
	for name, s := range cfg.Services {
		result[name] = s.Image
	}
	return result
}

// OpenUpgrade is a second explicit approval. An interrupted owned opening can
// be rechecked under public maintenance. Failed work, DDL rollback and unrelated
// administrator maintenance are never admitted by that recovery path.
func (d *Deployment) OpenUpgrade(ctx context.Context, r Receipt, approval, node string) (operationResult UpgradeState, operationErr error) {
	var state UpgradeState
	done, e := d.AcquireOperation()
	if e != nil {
		return state, e
	}
	defer func() { operationErr = errors.Join(operationErr, done()) }()
	cfg, e := d.ValidateReceipt(ctx, r)
	if e != nil {
		return state, e
	}
	state, e = d.upgradeState()
	if e != nil {
		return state, e
	}
	prepared := state.Phase == "prepared_fenced"
	recovering := state.Phase == "activating_fenced" || state.Phase == "verified_fenced" || state.Phase == "opening" || state.Phase == "opened"
	ready := state.Phase == "opened" && r.State == "ready"
	if (!prepared && !recovering) || state.Plan.SHA256 != approval || state.Plan.NodeID != node || r.Revision != state.Plan.Target || (r.State != "upgrade_fenced" && !ready) || r.SourceSHA != state.Plan.SourceSHA || r.SelectionHash != state.Previous.SelectionHash || !reflect.DeepEqual(r.ServiceImages, state.Plan.ServiceImages) {
		return state, errors.New("opening requires a prepared upgrade, approved plan digest and exact NodeID")
	}
	if recovering && ((!state.ManualOwned && state.Phase != "opened") || (!state.BusinessVerified && state.Phase != "activating_fenced")) {
		return state, errors.New("interrupted opening lacks owned maintenance or verified business facts")
	}
	stageName := upgradeManualStage + "-" + state.Plan.SHA256
	if ready {
		if state.StageCleanupWarning != "" {
			data, err := upgradeDataRoot(cfg)
			if err != nil {
				return state, err
			}
			root, err := os.OpenRoot(data)
			if err != nil {
				return state, err
			}
			defer root.Close()
			lease, err := sitecontrol.Lease(ctx, root, true)
			if err != nil {
				return state, err
			}
			defer lease()
			if info, err := root.Lstat(stageName); err == nil {
				content, readErr := root.ReadFile(stageName)
				if !info.Mode().IsRegular() || readErr != nil || string(content) != "manual\n" {
					return state, errors.New("recorded stage cleanup evidence changed")
				}
				if err = root.Remove(stageName); err != nil {
					return state, err
				}
			} else if !os.IsNotExist(err) {
				return state, err
			}
			if err = fsutil.SyncDirectory(root, "."); err != nil {
				return state, err
			}
			state.StageCleanupWarning = ""
			return state, d.saveUpgrade(state)
		}
		return state, nil
	}
	if e = d.localUpgradeEngine(ctx, state.Plan.Architecture); e != nil {
		return state, e
	}
	checkRecovery := func() error {
		backup, err := recovery.Check(ctx, state.BackupFile, state.BackupSHA)
		if err != nil || !backup.Verified || backup.Manifest.Scope != upgradeRecoveryScope(state.Plan) || backup.Manifest.NodeID != node || backup.Manifest.Revision != state.Previous.Revision {
			return errors.New("verified original recovery point is no longer available")
		}
		return nil
	}
	var fact RuntimeFact
	if prepared {
		if e = checkRecovery(); e != nil {
			return state, e
		}
		fact, e = d.runtimeFact(ctx)
		if e != nil || fact.NodeID != node || !fact.NativeMaintenance || !fact.Database.LogicalIdle || fact.Database.SchemaGeneration != state.Plan.Generation {
			return state, errors.New("prepared identity or native offline state changed; refused to resume")
		}
	}
	data, e := upgradeDataRoot(cfg)
	if e != nil {
		return state, e
	}
	root, e := os.OpenRoot(data)
	if e != nil {
		return state, e
	}
	defer root.Close()
	lease, e := sitecontrol.Lease(ctx, root, true)
	if e != nil {
		return state, e
	}
	defer lease()
	// An interrupted opening may already have removed its public marker. Restore
	// that gate before archive hashing or runtime inspection can take significant
	// time. A prepared operation cannot claim a preexisting administrator marker.
	_, markerErr := root.Lstat(sitecontrol.Manual)
	markerPresent := markerErr == nil
	if !os.IsNotExist(markerErr) && !markerPresent {
		return state, errors.New("public maintenance cannot be inspected")
	}
	if markerPresent {
		raw, err := readRegular(filepath.Join(data, sitecontrol.Manual), 32)
		if prepared || !state.ManualOwned || !state.ManualStaged || err != nil || string(raw) != "manual\n" {
			return state, errors.New("existing manual maintenance is not owned by this upgrade")
		}
	}
	if _, e = root.Lstat(sitecontrol.ForceOpen); !os.IsNotExist(e) {
		return state, errors.New("existing force-open state requires separate administrator review")
	}
	priorPhase := state.Phase
	if !state.ManualStaged {
		if _, err := root.Lstat(stageName); !os.IsNotExist(err) {
			return state, errors.New("unowned upgrade marker scratch exists")
		}
	}
	state.ManualOwned = true
	state.ManualStaged = true
	state.Phase = "activating_fenced"
	fail := func(message string) (UpgradeState, error) {
		state.Phase = "failed_fenced"
		if !d.fenceUpgradeFailure(ctx, cfg) {
			state.Phase = "failed_fence_unverified"
		}
		state.Failure = message
		_ = d.saveUpgrade(state)
		return state, errors.New(message + "; public maintenance and recovery materials retained; no automatic rollback")
	}
	if e = d.saveUpgrade(state); e != nil {
		return fail("activation intent could not be persisted")
	}
	if e = ensureStagedManual(root, stageName, prepared || priorPhase == "activating_fenced"); e != nil {
		return fail("owned staged public maintenance could not be restored")
	}
	if recovering {
		if e = checkRecovery(); e != nil {
			return fail("original recovery point verification failed during opening recovery")
		}
		fact, e = d.runtimeFact(ctx)
		if e != nil || fact.NodeID != node || !fact.Database.LogicalIdle || fact.Database.SchemaGeneration != state.Plan.Generation || (fact.NativeMaintenance && priorPhase != "activating_fenced") {
			return fail("interrupted target identity/schema or independent native maintenance changed")
		}
	}
	if fact.NativeMaintenance {
		if _, e = d.Compose(ctx, true, "run", "--rm", "--no-deps", "-T", "web", "maintenance", "resume"); e != nil {
			return fail("native target resume failed")
		}
	}
	var resident []string
	for _, name := range sortedServices(r.ServiceImages) {
		if !strings.HasSuffix(name, "-init") {
			resident = append(resident, name)
		}
	}
	if _, e = d.Compose(ctx, true, append([]string{"up", "-d", "--no-build", "--pull", "never", "--no-deps", "--wait", "--wait-timeout", "120"}, resident...)...); e != nil {
		return fail("target services did not become ready")
	}
	if _, e = d.Compose(ctx, true, "exec", "-T", "web", "/app/frontiercloud", "recovery-verify"); e != nil {
		return fail("running target managed business read verification failed")
	}
	rawFact, e := d.Compose(ctx, true, "exec", "-T", "web", "/app/frontiercloud", "operator-status")
	if e != nil || json.Unmarshal(rawFact, &fact) != nil || fact.NodeID != node || fact.NativeMaintenance || !fact.Database.LogicalIdle || fact.Database.SchemaGeneration != state.Plan.Generation {
		return fail("running target identity/schema changed")
	}
	if _, e = d.Compose(ctx, true, "exec", "-T", "web", "/app/frontiercloud", "healthcheck"); e != nil {
		return fail("running target application/database readiness failed")
	}
	// Persist verification before removing the public gate. A crash before or
	// during opening never leaves a receipt that ordinary restart can advance.
	state.BusinessVerified = true
	state.Phase = "verified_fenced"
	if e = d.saveUpgrade(state); e != nil {
		return fail("verification could not be persisted")
	}
	// This intent admits a retry on either side of durable marker removal.
	// Only after rechecking the same target may it finish journal/receipt writes.
	state.Phase = "opening"
	if e = d.saveUpgrade(state); e != nil {
		return fail("public opening intent could not be persisted")
	}
	raw, e := readRegular(filepath.Join(data, sitecontrol.Manual), 32)
	if e != nil || string(raw) != "manual\n" {
		return fail("public maintenance changed during activation")
	}
	stage, stageErr := root.Lstat(stageName)
	marker, markerErr := root.Lstat(sitecontrol.Manual)
	if stageErr != nil || markerErr != nil || !os.SameFile(stage, marker) {
		return fail("administrator maintenance replaced upgrade marker")
	}
	if e = root.Remove(sitecontrol.Manual); e != nil {
		return fail("public maintenance could not be removed")
	}
	if e = fsutil.SyncDirectory(root, "."); e != nil {
		return fail("public opening durability failed")
	}
	state.ManualOwned = false
	state.Phase = "opened"
	if e = d.saveUpgrade(state); e != nil {
		return fail("opening journal could not be persisted")
	}
	r.State = "ready"
	if e = replaceJSON(filepath.Join(d.Directory, ReceiptFile), r); e != nil {
		return fail("ready deployment receipt could not be persisted")
	}
	if cleanupErr := errors.Join(root.Remove(stageName), fsutil.SyncDirectory(root, ".")); cleanupErr != nil {
		state.StageCleanupWarning = "ready deployment retained; generated upgrade ownership stage cleanup requires operator attention: " + stageName
		if e = d.saveUpgrade(state); e != nil {
			return state, e
		}
	}
	return state, nil
}
