package operator

import (
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"os"
	"path/filepath"
)

const OperationLock = ".fc-operation.lock"

var ErrOperationRelease = errors.New("host-operation lock release failed; completed state is retained; inspect the operation lock before another mutation")

// A crashed host operation requires explicit review rather than automatic
// takeover. Read-only commands never create this directory or clear it.
func (d *Deployment) AcquireOperation() (func() error, error) {
	lock := filepath.Join(d.Directory, OperationLock)
	if e := os.Mkdir(lock, 0700); e != nil {
		return nil, errors.New("another host operation is active or interrupted; inspect the operation lock before continuing")
	}
	owned, e := os.Lstat(lock)
	if e != nil {
		return nil, errors.New("host-operation lock ownership could not be inspected; preserve the lock for explicit review")
	}
	return func() error {
		root, e := os.OpenRoot(d.Directory)
		if e != nil {
			return ErrOperationRelease
		}
		defer root.Close()
		current, e := root.Lstat(OperationLock)
		if e != nil || !os.SameFile(owned, current) {
			return ErrOperationRelease
		}
		if e = root.Remove(OperationLock); e != nil {
			return ErrOperationRelease
		}
		if e = fsutil.SyncDirectory(root, "."); e != nil {
			return ErrOperationRelease
		}
		return nil
	}, nil
}
