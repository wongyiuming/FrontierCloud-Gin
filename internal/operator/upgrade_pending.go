package operator

import (
	"encoding/json"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
	"os"
	"path/filepath"
)

// PendingUpgradeRouting reads only the versioned routing envelope. It does not
// authorize mutations: the matching backend must verify the complete original
// journal/digest, including fields unknown to a different operator generation.
func (d *Deployment) PendingUpgradeRouting(r Receipt) (string, int, error) {
	raw, err := readRegular(filepath.Join(d.Directory, UpgradeJournal), 2<<20)
	if os.IsNotExist(err) {
		return "", 0, nil
	}
	if err != nil {
		return "", 0, err
	}
	if _, err = protocol.ParseStrictJSON(raw, 2<<20); err != nil {
		return "", 0, err
	}
	var envelope struct {
		Version int    `json:"version"`
		Phase   string `json:"phase"`
		Plan    struct {
			Target     string `json:"target_revision"`
			Generation int    `json:"schema_generation"`
		} `json:"plan"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.Version != 1 || envelope.Phase == "" || !release.ValidSHA(envelope.Plan.Target) || envelope.Plan.Generation < 1 || envelope.Plan.Generation > 999999999 {
		return "", 0, errors.New("invalid upgrade routing envelope; preserve its journal")
	}
	if envelope.Phase == "opened" && r.State != "upgrade_fenced" {
		return "", 0, nil
	}
	return envelope.Plan.Target, envelope.Plan.Generation, nil
}

// PendingUpgradeTarget keeps a parameterless retry bound to its original plan.
func (d *Deployment) PendingUpgradeTarget(r Receipt) (string, error) {
	s, err := d.upgradeState()
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if s.Phase != "opened" || r.State == "upgrade_fenced" {
		return s.Plan.Target, nil
	}
	return "", nil
}

// PendingUpgradeLocalOpen identifies phases whose original local opening gates
// already contain the release proof. It does not authorize or open the runtime.
func (d *Deployment) PendingUpgradeLocalOpen(r Receipt) (bool, error) {
	s, err := d.upgradeState()
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if s.Phase == "opened" && r.State != "upgrade_fenced" {
		return false, nil
	}
	switch s.Phase {
	case "prepared_fenced", "activating_fenced", "verified_fenced", "opening", "opened":
		return true, nil
	}
	return false, nil
}
