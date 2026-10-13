package operator

import (
	"context"
	"errors"
	"os"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
)

const restoreManualStage = ".fc-restore-manual"

// A retained staged inode distinguishes our marker from administrator manual
// maintenance, including interruption after publication but before checkpoint.
func (d *Deployment) prepareRestoreManual(ctx context.Context, data string, state *RestoreState) error {
	root, e := os.OpenRoot(data)
	if e != nil {
		return e
	}
	defer root.Close()
	done, e := sitecontrol.Lease(ctx, root, true)
	if e != nil {
		return e
	}
	defer done()
	if !state.ManualStaged {
		if _, e = root.Lstat(sitecontrol.Manual); e == nil {
			return nil
		} else if !os.IsNotExist(e) {
			return e
		}
		if _, e = root.Lstat(restoreManualStage); !os.IsNotExist(e) {
			return errors.New("unowned restore marker scratch exists")
		}
		state.OwnManual, state.ManualStaged, state.Phase = true, true, "creating_manual"
		if e = d.saveRestore(*state); e != nil {
			return e
		}
	}
	return ensureStagedManual(root, restoreManualStage, state.Phase == "creating_manual")
}
