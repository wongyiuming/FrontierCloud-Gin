package operator

import (
	"errors"
	"os"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
)

// The caller holds the site lease and has durably recorded the unique staged
// marker intent. A separate same-text administrator inode is never adopted.
func ensureStagedManual(root *os.Root, name string, repair bool) error {
	manual, markerErr := root.Lstat(sitecontrol.Manual)
	stage, e := root.Lstat(name)
	if os.IsNotExist(e) {
		if !os.IsNotExist(markerErr) {
			return errors.New("unowned maintenance exists before staged publication")
		}
		f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		err = fsutil.InheritOwner(f, root)
		if err == nil {
			_, err = f.WriteString("manual\n")
		}
		if err == nil {
			err = f.Sync()
		}
		err = errors.Join(err, f.Close(), fsutil.SyncDirectory(root, "."))
		if err != nil {
			return err
		}
		stage, e = root.Lstat(name)
	}
	if e != nil || !stage.Mode().IsRegular() {
		return errors.New("staged marker inode changed")
	}
	content, e := root.ReadFile(name)
	if e == nil && string(content) != "manual\n" && repair && os.IsNotExist(markerErr) {
		f, err := root.OpenFile(name, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		actual, err := f.Stat()
		if err == nil && !os.SameFile(stage, actual) {
			err = errors.New("staged inode changed while opening")
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
	if e != nil || string(content) != "manual\n" {
		return errors.New("staged marker bytes changed")
	}
	if markerErr == nil {
		if !os.SameFile(stage, manual) {
			return errors.New("administrator maintenance replaced staged operator marker")
		}
		return nil
	}
	if !os.IsNotExist(markerErr) {
		return markerErr
	}
	if e = root.Link(name, sitecontrol.Manual); e != nil {
		return e
	}
	return fsutil.SyncDirectory(root, ".")
}
