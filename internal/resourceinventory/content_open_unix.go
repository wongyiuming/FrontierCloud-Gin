//go:build !windows

package resourceinventory

import (
	"golang.org/x/sys/unix"
	"os"
)

// A pathname replaced by a FIFO must not block the observation worker before
// fstat can reject it. Regular-file reads retain normal kernel behavior.
func openContentFile(root *os.Root, name string) (*os.File, error) {
	return openContentChecked(root, name, os.O_RDONLY|unix.O_NONBLOCK)
}
