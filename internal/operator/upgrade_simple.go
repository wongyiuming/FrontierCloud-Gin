package operator

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
)

// UpgradePreview is one consent boundary for preparation and subsequent opening.
// A MySQL approval additionally attests that external writers are stopped.
type UpgradePreview struct {
	Plan        UpgradePlan     `json:"plan"`
	Capacity    *BackupCapacity `json:"capacity,omitempty"`
	ResumePhase string          `json:"resume_phase,omitempty"`
}
type UpgradeConsent struct{ Approved, ExternalWritersStopped bool }
type UpgradeResult struct {
	Phase            string `json:"phase"`
	Revision         string `json:"revision"`
	NodeID           string `json:"node_id"`
	Generation       int    `json:"schema_generation"`
	BackupFile       string `json:"backup_file,omitempty"`
	BackupSHA        string `json:"backup_sha256,omitempty"`
	BusinessVerified bool   `json:"managed_read_verified"`
}

func simpleUpgradeResult(s UpgradeState) UpgradeResult {
	return UpgradeResult{Phase: s.Phase, Revision: s.Plan.Target, NodeID: s.Plan.NodeID, Generation: s.Plan.Generation, BackupFile: s.BackupFile, BackupSHA: s.BackupSHA, BusinessVerified: s.BusinessVerified}
}

// Upgrade reuses the approved plan/apply/resume/open gates. Managed plan files
// are audit evidence, never implicit approval. Failed recovery is not automatic.
func (d *Deployment) Upgrade(ctx context.Context, r Receipt, target, arch string, evidence Evidence, images Images, confirm func(UpgradePreview) (UpgradeConsent, error)) (UpgradeResult, error) {
	if !release.ValidSHA(target) || confirm == nil {
		return UpgradeResult{}, errors.New("upgrade requires an explicit published revision and consent")
	}
	state, e := d.upgradeState()
	pending := e == nil && state.Phase != "opened"
	if e != nil && !os.IsNotExist(e) {
		return UpgradeResult{}, e
	}
	var preview UpgradePreview
	var output string
	if pending {
		if state.Plan.Target != target || state.Plan.StateRestore || state.Plan.RecoveryOf != "" || state.Plan.RecoveryScope != recovery.UpgradeStateScope {
			return UpgradeResult{}, errors.New("unfinished operation has a different target or recovery scope; preserve its journal")
		}
		switch state.Phase {
		case "backup_pending", "backed_up_fenced", "switching_fenced", "preparing_fenced", "prepared_fenced", "activating_fenced", "verified_fenced", "opening":
		default:
			return UpgradeResult{}, errors.New("failed upgrade requires explicit recovery; automatic upgrade will not reopen or roll back it")
		}
		preview = UpgradePreview{Plan: state.Plan, ResumePhase: state.Phase}
	} else {
		if r.Revision == target {
			if r.State != "ready" {
				return UpgradeResult{}, errors.New("current revision is not ready; complete its recorded recovery")
			}
			if _, e = d.ValidateReceipt(ctx, r); e != nil {
				return UpgradeResult{}, e
			}
			fact, err := d.upgradeFact(ctx, r)
			if err != nil {
				return UpgradeResult{}, err
			}
			return UpgradeResult{Phase: "already_current", Revision: target, NodeID: fact.NodeID, Generation: fact.Database.SchemaGeneration}, nil
		}
		plan, err := d.PlanUpgrade(ctx, r, target, arch, evidence, images)
		if err != nil {
			return UpgradeResult{}, err
		}
		output = filepath.Join(d.Directory, ".foc-before-"+plan.SHA256+".tar")
		capacity, err := d.UpgradeBackupCapacity(ctx, r, output)
		if err != nil {
			return UpgradeResult{}, err
		}
		if !capacity.Fits {
			return UpgradeResult{}, errors.New("upgrade state backup capacity insufficient; business files are excluded")
		}
		preview = UpgradePreview{Plan: plan, Capacity: &capacity}
	}
	consent, e := confirm(preview)
	if e != nil {
		return UpgradeResult{}, e
	}
	if !consent.Approved {
		return UpgradeResult{}, errors.New("upgrade cancelled; no upgrade stage executed")
	}
	if preview.Plan.Database == "mysql" && !consent.ExternalWritersStopped {
		return UpgradeResult{}, errors.New("MySQL upgrade requires confirmation that external writers are stopped")
	}
	if e = ctx.Err(); e != nil {
		return UpgradeResult{}, e
	}
	if pending {
		switch state.Phase {
		case "backup_pending", "backed_up_fenced", "switching_fenced", "preparing_fenced":
			state, e = d.ResumeUpgrade(ctx, r, preview.Plan.SHA256, preview.Plan.NodeID, consent.ExternalWritersStopped, evidence, images)
		}
	} else {
		// The operator controls this path and keeps the plan beside its recovery file.
		if e = exclusiveJSONOrSame(filepath.Join(d.Directory, ".foc-upgrade-plan-"+preview.Plan.SHA256+".json"), preview.Plan); e != nil {
			return UpgradeResult{}, e
		}
		state, e = d.ApplyUpgrade(ctx, r, preview.Plan, preview.Plan.SHA256, preview.Plan.NodeID, output, consent.ExternalWritersStopped, evidence, images)
	}
	if e != nil {
		return simpleUpgradeResult(state), e
	}
	_, current, e := Open(d.Directory)
	if e != nil {
		return simpleUpgradeResult(state), e
	}
	state, e = d.OpenUpgrade(ctx, current, preview.Plan.SHA256, preview.Plan.NodeID)
	return simpleUpgradeResult(state), e
}
