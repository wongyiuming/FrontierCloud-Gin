package operator

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

// ResumeUpgrade reconciles only a previously approved, backed-up switch. It
// restores the native fence before network proof checks or repairing metadata.
func (d *Deployment) ResumeUpgrade(ctx context.Context, receipt Receipt, approval, node string, external bool, evidence Evidence, images Images) (UpgradeState, error) {
	done, e := d.AcquireOperation()
	if e != nil {
		return UpgradeState{}, e
	}
	defer done()
	state, e := d.upgradeState()
	if e != nil {
		return state, e
	}
	p := state.Plan
	if (state.Phase != "backed_up_fenced" && state.Phase != "switching_fenced" && state.Phase != "preparing_fenced" && state.Phase != "prepared_fenced") || approval != p.SHA256 || node != p.NodeID || state.BackupSHA == "" || p.digest() != approval {
		return state, errors.New("resume requires a durable approved switch and its original recovery point")
	}
	if state.Previous.Database == "mysql" && !external {
		return state, errors.New("MySQL resume requires external-writers-stopped confirmation")
	}
	next := upgradeTargetReceipt(state)
	if !reflect.DeepEqual(receipt, state.Previous) && !reflect.DeepEqual(receipt, next) {
		return state, errors.New("receipt is outside the recorded source/target switch")
	}
	cfg, e := d.Config(ctx, false)
	if e != nil || cfg.Name != p.Project || selectionHash(cfg) != state.Previous.SelectionHash {
		return state, errors.New("source configuration changed; interrupted switch cannot be resumed")
	}
	raw, e := readRegular(filepath.Join(d.Directory, ImagesFile), 1<<20)
	if e != nil {
		return state, e
	}
	value, e := protocol.ParseStrictJSON(raw, 1<<20)
	if e != nil {
		return state, e
	}
	var lock struct {
		Services map[string]map[string]string `json:"services"`
	}
	object, validObject := value.(map[string]any)
	if json.Unmarshal(raw, &lock) != nil || !validObject || len(object) != 1 || len(lock.Services) != len(p.ServiceImages) {
		return state, errors.New("unknown interrupted image lock")
	}
	for name, fields := range lock.Services {
		_, known := p.ServiceImages[name]
		if !known || len(fields) != 1 || fields["image"] == "" || (fields["image"] != state.Previous.ServiceImages[name] && fields["image"] != p.ServiceImages[name]) {
			return state, errors.New("image lock contains unapproved switch fields")
		}
	}
	if e = d.localUpgradeEngine(ctx, p.Architecture); e != nil {
		return state, e
	}
	if !d.fenceUpgradeFailure(ctx, cfg) {
		state.Phase = "failed_fence_unverified"
		_ = d.saveUpgrade(state)
		return state, errors.New("interrupted switch could not be independently fenced")
	}
	verified, e := checkUpgradeRecovery(ctx, state)
	if e != nil || !verified {
		return state, errors.New("original recovery point is unavailable; switch remains fenced")
	}
	source, components, services, e := d.targetImages(ctx, state.Previous, p.Target, p.Architecture, evidence, images)
	if e != nil || source != p.SourceSHA || !reflect.DeepEqual(components, p.Images) || !reflect.DeepEqual(services, p.ServiceImages) {
		return state, errors.New("recorded target publication proof changed; switch remains fenced")
	}
	for _, name := range sortedServices(p.ServiceImages) {
		if _, e = d.Runner.Run(ctx, "docker", "pull", p.ServiceImages[name]); e != nil {
			return state, errors.New("approved target image is unavailable; switch remains fenced")
		}
	}
	return d.prepareUpgradeLocked(ctx, cfg, state)
}
