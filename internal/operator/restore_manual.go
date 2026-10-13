package operator

import (
	"context"
	"errors"
	"os"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
	"path/filepath"
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
			return errors.New("administrator maintenance must be cleared separately before restore activation")
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

func (d *Deployment) cleanupRestoreStage(ctx context.Context, state RestoreState) (RestoreState, error) {
	if !state.ManualStaged {
		return state, nil
	}
	root, e := os.OpenRoot(filepath.Join(filepath.Dir(d.Directory), "data"))
	if e != nil {
		return state, e
	}
	defer root.Close()
	done, e := sitecontrol.Lease(ctx, root, true)
	if e != nil {
		return state, e
	}
	defer done()
	if info, err := root.Lstat(restoreManualStage); err == nil {
		content, readErr := root.ReadFile(restoreManualStage)
		if !info.Mode().IsRegular() || readErr != nil || string(content) != "manual\n" {
			return state, errors.New("recorded restore stage cleanup evidence changed")
		}
		if e = root.Remove(restoreManualStage); e != nil {
			return state, e
		}
	} else if !os.IsNotExist(err) {
		return state, err
	}
	if e = fsutil.SyncDirectory(root, "."); e != nil {
		return state, e
	}
	state.StageCleanupWarning = ""
	return state, d.saveRestore(state)
}
