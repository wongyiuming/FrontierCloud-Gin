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

// OpenUpgrade is a second explicit approval. It never opens failed/interrupted
// work, reverts DDL, rewrites an old identity or overrides prior maintenance.
func (d *Deployment) OpenUpgrade(ctx context.Context, r Receipt, approval, node string) (UpgradeState, error) {
	var state UpgradeState
	done, e := d.AcquireOperation()
	if e != nil {
		return state, e
	}
	defer done()
	cfg, e := d.ValidateReceipt(ctx, r)
	if e != nil {
		return state, e
	}
	state, e = d.upgradeState()
	if e != nil {
		return state, e
	}
	if state.Phase != "prepared_fenced" || state.Plan.SHA256 != approval || state.Plan.NodeID != node || r.Revision != state.Plan.Target || r.State != "upgrade_fenced" || r.SourceSHA != state.Plan.SourceSHA || r.SelectionHash != state.Previous.SelectionHash || !reflect.DeepEqual(r.ServiceImages, state.Plan.ServiceImages) {
		return state, errors.New("opening requires a prepared upgrade, approved plan digest and exact NodeID")
	}
	if e = d.localUpgradeEngine(ctx, state.Plan.Architecture); e != nil {
		return state, e
	}
	backup, e := recovery.Check(ctx, state.BackupFile, state.BackupSHA)
	if e != nil || !backup.Verified || backup.Manifest.NodeID != node || backup.Manifest.Revision != state.Previous.Revision {
		return state, errors.New("verified original recovery point is no longer available")
	}
	fact, e := d.runtimeFact(ctx)
	if e != nil || fact.NodeID != node || !fact.NativeMaintenance || !fact.Database.LogicalIdle || fact.Database.SchemaGeneration != state.Plan.Generation {
		return state, errors.New("prepared identity or native offline state changed; refused to resume")
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
	// Preserve administrator maintenance; a separate change is required for it.
	if _, e = root.Lstat(sitecontrol.Manual); !os.IsNotExist(e) {
		return state, errors.New("existing manual maintenance is not owned by this upgrade")
	}
	if _, e = root.Lstat(sitecontrol.ForceOpen); !os.IsNotExist(e) {
		return state, errors.New("existing force-open state requires separate administrator review")
	}
	f, e := root.OpenFile(sitecontrol.Manual, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return state, e
	}
	e = fsutil.InheritOwner(f, root)
	if e == nil {
		_, e = f.WriteString("manual\n")
	}
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close(), fsutil.SyncDirectory(root, "."))
	if e != nil {
		return state, e
	}
	state.ManualOwned = true
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
	if _, e = d.Compose(ctx, true, "run", "--rm", "--no-deps", "-T", "web", "maintenance", "resume"); e != nil {
		return fail("native target resume failed")
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
	raw, e := readRegular(filepath.Join(data, sitecontrol.Manual), 32)
	if e != nil || string(raw) != "manual\n" {
		return fail("public maintenance changed during activation")
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
	return state, nil
}
