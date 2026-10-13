package operator

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
)

func upgradeTargetReceipt(state UpgradeState) Receipt {
	next := state.Previous
	next.Revision = state.Plan.Target
	next.SourceSHA = state.Plan.SourceSHA
	next.Images = state.Plan.Images
	next.ServiceImages = state.Plan.ServiceImages
	next.State = "upgrade_fenced"
	return next
}

func checkUpgradeRecovery(ctx context.Context, state UpgradeState) (bool, error) {
	report, e := recovery.Check(ctx, state.BackupFile, state.BackupSHA)
	return e == nil && report.Verified && report.Manifest.NodeID == state.Plan.NodeID && report.Manifest.Revision == state.Previous.Revision && report.Manifest.SchemaGeneration == state.Plan.FromGeneration, e
}

func (d *Deployment) prepareUpgradeLocked(ctx context.Context, cfg Config, state UpgradeState) (UpgradeState, error) {
	p := state.Plan
	var e error
	fail := func(message string) (UpgradeState, error) {
		state.Phase = "failed_fenced"
		if !d.fenceUpgradeFailure(ctx, cfg) {
			state.Phase = "failed_fence_unverified"
		}
		state.Failure = message
		_ = d.saveUpgrade(state)
		return state, errors.New(message + "; original recovery point retained; no automatic DDL rollback")
	}
	// Publish complete next receipt and image lock while all writers remain
	// stopped. Any crash between them is detected by ValidateReceipt.
	next := upgradeTargetReceipt(state)
	locked := map[string]map[string]string{}
	for name, image := range p.ServiceImages {
		locked[name] = map[string]string{"image": image}
	}
	state.Phase = "switching_fenced"
	if e = d.saveUpgrade(state); e != nil {
		return fail("switch intent could not be persisted")
	}
	if e = replaceJSON(filepath.Join(d.Directory, ImagesFile), map[string]any{"services": locked}); e != nil {
		return fail("target image lock publication failed")
	}
	if e = replaceJSON(filepath.Join(d.Directory, ReceiptFile), next); e != nil {
		return fail("target receipt publication failed")
	}
	if _, e = d.ValidateReceipt(ctx, next); e != nil {
		return fail("target deployment binding failed")
	}
	state.Phase = "preparing_fenced"
	if e = d.saveUpgrade(state); e != nil {
		return fail("preparation intent could not be persisted")
	}
	existing, existingErr := d.runtimeFact(ctx)
	prepare := []string{"run", "--rm", "--no-deps", "-T", "web", "prepare-release", "--confirm-generation", strconv.Itoa(p.Generation)}
	if p.FromGeneration != p.Generation && !(existingErr == nil && existing.NodeID == p.NodeID && existing.NativeMaintenance && existing.Database.LogicalIdle && existing.Database.SchemaGeneration == p.Generation) {
		prepare = append(prepare, "--from-generation", strconv.Itoa(p.FromGeneration), "--confirm-node-id", p.NodeID, "--backup-sha256", state.BackupSHA)
	}
	if _, e = d.Compose(ctx, true, prepare...); e != nil {
		return fail("target schema preparation failed")
	}
	fact, e := d.runtimeFact(ctx)
	if e != nil || fact.NodeID != p.NodeID || !fact.NativeMaintenance || !fact.Database.LogicalIdle || fact.Database.SchemaGeneration != p.Generation {
		return fail("target identity/schema verification failed")
	}
	if _, e = d.Compose(ctx, true, "run", "--rm", "--no-deps", "-T", "web", "recovery-verify"); e != nil {
		return fail("target managed business read verification failed")
	}
	state.Phase = "prepared_fenced"
	if e = d.saveUpgrade(state); e != nil {
		return fail("prepared upgrade journal persistence failed")
	}
	return state, nil
}
