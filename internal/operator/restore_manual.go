package operator

import (
	"context"
	"errors"
	"os"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
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
	released := false
	defer func() {
		if !released {
			done()
		}
	}()
	manual, e := root.Lstat(sitecontrol.Manual)
	if state.ManualStaged {
		stage, err := root.Lstat(restoreManualStage)
		if os.IsNotExist(err) && os.IsNotExist(e) {
			f, createErr := root.OpenFile(restoreManualStage, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if createErr != nil {
				return createErr
			}
			createErr = fsutil.InheritOwner(f, root)
			if createErr == nil {
				_, createErr = f.WriteString("manual\n")
			}
			if createErr == nil {
				createErr = f.Sync()
			}
			createErr = errors.Join(createErr, f.Close(), fsutil.SyncDirectory(root, "."))
			if createErr != nil {
				return createErr
			}
			stage, err = root.Lstat(restoreManualStage)
		}
		if err != nil || !stage.Mode().IsRegular() {
			return errors.New("restore marker creation evidence changed")
		}
		content, err := root.ReadFile(restoreManualStage)
		if err == nil && string(content) != "manual\n" && state.Phase == "creating_manual" && os.IsNotExist(e) {
			f, err := root.OpenFile(restoreManualStage, os.O_WRONLY, 0)
			if err != nil {
				return err
			}
			actual, err := f.Stat()
			if err == nil && !os.SameFile(stage, actual) {
				err = errors.New("staged inode changed")
			}
			if err == nil {
				err = f.Truncate(0)
			}
			if err == nil {
				_, err = f.WriteString("manual\n")
			}
			if err == nil {
				err = f.Sync()
			}
			err = errors.Join(err, f.Close())
			if err != nil {
				return err
			}
			content = []byte("manual\n")
		}
		if err != nil || string(content) != "manual\n" {
			return errors.New("restore staged marker bytes changed")
		}
		if e == nil {
			if !os.SameFile(stage, manual) {
				return errors.New("administrator maintenance replaced staged restore marker")
			}
			return nil
		}
		if !os.IsNotExist(e) {
			return e
		}
		if e = root.Link(restoreManualStage, sitecontrol.Manual); e != nil {
			return e
		}
		return fsutil.SyncDirectory(root, ".")
	}
	if e == nil {
		return nil
	}
	if !os.IsNotExist(e) {
		return e
	}
	if _, err := root.Lstat(restoreManualStage); !os.IsNotExist(err) {
		return errors.New("unowned restore marker scratch exists")
	}
	state.OwnManual = true
	state.ManualStaged = true
	state.Phase = "creating_manual"
	if e = d.saveRestore(*state); e != nil {
		return e
	}
	// Release the lease before entering the recorded intent path again.
	done()
	released = true
	return d.prepareRestoreManual(ctx, data, state)
}
