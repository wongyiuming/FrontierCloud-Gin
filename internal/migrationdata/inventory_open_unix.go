//go:build !windows

package migrationdata

import (
	"golang.org/x/sys/unix"
	"os"
)

func openInventoryFile(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|unix.O_NONBLOCK, 0)
}
