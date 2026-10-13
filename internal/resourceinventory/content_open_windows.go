package resourceinventory

import "os"

// Root confinement and the pre/post inode/type checks apply on Windows;
// device/named-pipe namespace paths are excluded by ContentAt path validation.
func openContentFile(root *os.Root, name string) (*os.File, error) {
	return openContentChecked(root, name, os.O_RDONLY)
}
