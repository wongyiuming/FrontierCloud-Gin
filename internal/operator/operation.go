package operator

import (
	"errors"
	"os"
	"path/filepath"
)

const OperationLock = ".fc-operation.lock"

// A crashed host operation requires explicit review rather than automatic
// takeover. Read-only commands never create this directory or clear it.
func (d *Deployment) AcquireOperation() (func(), error) {
	lock := filepath.Join(d.Directory, OperationLock)
	if e := os.Mkdir(lock, 0700); e != nil {
		return nil, errors.New("another host operation is active or interrupted; inspect the operation lock before continuing")
	}
	return func() { _ = os.Remove(lock) }, nil
}
