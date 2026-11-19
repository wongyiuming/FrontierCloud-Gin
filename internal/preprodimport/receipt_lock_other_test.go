//go:build !unix

package preprodimport

import (
	"errors"
	"os"
)

func lockStage(*os.File) error { return errors.New("native stage locking unsupported") }
