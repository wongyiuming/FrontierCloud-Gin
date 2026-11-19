//go:build unix

package preprodimport

import (
	"os"
	"syscall"
)

func lockStageReceipt(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}
