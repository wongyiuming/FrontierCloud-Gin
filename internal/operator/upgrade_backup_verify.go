package operator

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
)

var errRecordedBackupMismatch = errors.New("backup does not match the archive and source identity recorded in the current upgrade journal")

// VerifyRecordedUpgradeBackup uses the current upgrade journal's independent
// checksum when input names its archive. A matched path cannot fall back to
// unpinned verification after a mismatch. This never authorizes activation.
func (d *Deployment) VerifyRecordedUpgradeBackup(ctx context.Context, input string) (report recovery.Report, matched bool, err error) {
	if d == nil || ctx == nil || input == "" {
		return report, false, nil
	}
	name, err := filepath.Abs(input)
	if err != nil {
		return report, false, nil
	}
	state, err := d.upgradeState()
	if err != nil || state.BackupFile != name || state.Plan.StateRestore || state.Plan.RecoveryOf != "" {
		return report, false, nil
	}
	p, source := state.Plan, state.Previous
	if state.BackupSHA == "" || p.Version != 1 || p.Role != d.Role || p.Project != d.Project ||
		source.Role != p.Role || source.Database != p.Database || source.Project != p.Project || source.State != "ready" ||
		!release.ValidSHA(p.From) || source.Revision != p.From || p.ReceiptSHA != upgradeHash(source) {
		return report, true, errRecordedBackupMismatch
	}
	report, err = recovery.Check(ctx, name, state.BackupSHA)
	if err != nil && p.Role == "master" && p.Database == "sqlite" && p.RecoveryScope == recovery.UpgradeStateScope {
		report, err = recovery.CheckTreeArchiveAuthenticated(ctx, name, state.BackupSHA)
	}
	m := report.Manifest
	roleMatches := p.Role == "master" && (m.Role == "Master" || m.Role == "Standalone") || p.Role == "storage" && m.Role == "Follower"
	if err != nil || !report.Verified || !roleMatches || m.Scope != upgradeRecoveryScope(p) || m.Database != p.Database || m.NodeID != p.NodeID || m.Revision != p.From || m.SchemaGeneration != p.FromGeneration {
		return recovery.Report{}, true, errRecordedBackupMismatch
	}
	current, err := d.upgradeState()
	if err != nil || current.BackupFile != name || current.Plan.SHA256 != p.SHA256 || current.BackupSHA != state.BackupSHA || upgradeHash(current.Previous) != p.ReceiptSHA {
		return recovery.Report{}, true, errRecordedBackupMismatch
	}
	return report, true, nil
}
