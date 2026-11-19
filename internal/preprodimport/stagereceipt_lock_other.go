//go:build !unix

package preprodimport

import (
	"errors"
	"os"
)

// Unsupported platforms fail closed until native locking and ACL checks exist.
func lockStageReceipt(*os.File) error { return errors.New("stage receipt locking unsupported") }
