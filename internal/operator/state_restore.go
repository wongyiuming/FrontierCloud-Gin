package operator

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
)

// StateRestoreCheck requires an intact deployment binding, not an upgrade
// journal. It never freezes a writer or grants fresh-machine recovery authority.
func (d *Deployment) StateRestoreCheck(ctx context.Context, r Receipt, input, expected string) (recovery.Report, Receipt, error) {
	report, e := recovery.Check(ctx, input, expected)
	var source Receipt
	if e != nil || expected == "" || report.Manifest.Scope != recovery.UpgradeStateScope {
		return report, source, errors.New("verified state archive with trusted checksum required")
	}
	if len(report.Manifest.Missing) != 1 || len(report.Manifest.Relations) != 0 {
		return report, source, errors.New("ordinary state restore refuses missing related-node state; coordinated recovery or explicit peer-fencing evidence is required")
	}
	raw, e := recovery.ReadStateFile(ctx, input, expected, "deployment/"+ReceiptFile)
	if e != nil {
		return report, source, e
	}
	if json.Unmarshal(raw, &source) != nil || source.Version != 1 || source.State != "ready" || source.Revision != report.Manifest.Revision || source.Database != report.Manifest.Database || source.Role != r.Role || source.Database != r.Database || source.Project != r.Project || source.SelectionHash != r.SelectionHash || !equalStrings(source.Files, r.Files) {
		return report, source, errors.New("state archive differs from retained deployment identity or mounts")
	}
	if _, e = d.ValidateReceipt(ctx, r); e != nil {
		return report, source, e
	}
	if fact, err := d.capacityFact(ctx); err == nil && fact.NodeID != report.Manifest.NodeID {
		return report, source, errors.New("current node identity differs from state archive")
	}
	return report, source, nil
}

// RestoreState requires explicit acceptance of state loss since capture. It
// retains current state before restoring and never copies business media.
func (d *Deployment) RestoreState(ctx context.Context, r Receipt, input, expected, node, directory string, offline, stateLoss, freeze, external bool) (UpgradeState, error) {
	var result UpgradeState
	if !offline || !stateLoss || expected == "" || node == "" || directory == "" {
		return result, errors.New("state restore requires archive checksum, exact NodeID, retained mounts, source-offline and state-loss confirmations")
	}
	if recorded, e := d.upgradeState(); e == nil && recorded.Plan.StateRestore && recorded.BackupSHA == expected && recorded.Plan.NodeID == node && (recorded.Phase == "restoring_state" || recorded.Phase == "failed_fenced") {
		if freeze {
			cfg, err := d.Config(ctx, true)
			if err != nil {
				return result, err
			}
			if !d.fenceUpgradeFailure(ctx, cfg) {
				return result, errors.New("state restore retry could not establish native fencing")
			}
		}
		return d.recoverState(ctx, r, recorded.Plan.SHA256, node, expected, directory, external, true)
	}
	if _, e := safeRecoveryDirectory(directory, false); e != nil {
		return result, e
	}
	done, e := d.AcquireOperation()
	if e != nil {
		return result, e
	}
	report, source, e := d.StateRestoreCheck(ctx, r, input, expected)
	if e != nil {
		_ = done()
		return result, e
	}
	if r.State != "ready" || report.Manifest.NodeID != node || r.Database == "mysql" && !external {
		_ = done()
		return result, errors.New("ready matching deployment, exact archive NodeID and any MySQL external-writer confirmation required")
	}
	if old, e := d.upgradeState(); e == nil {
		if old.Phase != "opened" {
			_ = done()
			return result, errors.New("an existing incomplete upgrade must be reconciled before ordinary state restoration")
		}
		if e = exclusiveJSONOrSame(filepath.Join(d.Directory, ".fc-prior-upgrade-"+old.Plan.SHA256+".json"), old); e != nil {
			_ = done()
			return result, e
		}
	} else if !os.IsNotExist(e) {
		_ = done()
		return result, e
	}
	cfg, e := d.ValidateReceipt(ctx, r)
	if e != nil {
		_ = done()
		return result, e
	}
	if freeze && !d.fenceUpgradeFailure(ctx, cfg) {
		_ = done()
		return result, errors.New("state restoration could not independently stop and fence the retained deployment")
	}
	if e = d.stoppedWriters(ctx); e != nil {
		_ = done()
		return result, e
	}
	input, e = filepath.Abs(input)
	if e != nil {
		_ = done()
		return result, e
	}
	p := UpgradePlan{Version: 1, NodeID: node, Project: r.Project, Role: r.Role, Database: r.Database, From: r.Revision, Target: r.Revision, SourceSHA: r.SourceSHA, ReceiptSHA: upgradeHash(r), Architecture: "amd64", Generation: report.Manifest.SchemaGeneration, FromGeneration: report.Manifest.SchemaGeneration, ServiceImages: r.ServiceImages, Images: r.Images, RecoveryScope: recovery.UpgradeStateScope, StateRestore: true}
	arch, e := d.Runner.Run(ctx, "docker", "info", "--format", "{{.Architecture}}")
	if e != nil {
		_ = done()
		return result, e
	}
	p.Architecture = Architecture(string(arch))
	p.SHA256 = p.digest()
	result = UpgradeState{Version: 1, Phase: "failed_fenced", Plan: p, Previous: source, BackupFile: input, BackupSHA: expected, Failure: "explicit ordinary state restoration; state loss accepted"}
	if e = d.saveUpgrade(result); e != nil {
		_ = done()
		return result, e
	}
	r.State = "upgrade_fenced"
	if e = replaceJSON(filepath.Join(d.Directory, ReceiptFile), r); e != nil {
		_ = done()
		return result, e
	}
	if e = done(); e != nil {
		return result, e
	}
	return d.recoverState(ctx, r, p.SHA256, node, expected, directory, external, true)
}

func safeRecoveryDirectory(directory string, existing bool) (string, error) {
	if directory == "" {
		return "", errors.New("private recovery directory required")
	}
	abs, e := filepath.Abs(directory)
	if e != nil {
		return "", e
	}
	inspect := filepath.Dir(abs)
	if existing {
		inspect = abs
	}
	info, e := os.Lstat(inspect)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("recovery parent must be an existing real directory")
	}
	real, e := filepath.EvalSymlinks(inspect)
	if e != nil || filepath.Clean(real) != filepath.Clean(inspect) {
		return "", errors.New("symlinked recovery ancestors are refused")
	}
	return abs, nil
}
