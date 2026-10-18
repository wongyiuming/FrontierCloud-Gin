package operator

import "os"

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
