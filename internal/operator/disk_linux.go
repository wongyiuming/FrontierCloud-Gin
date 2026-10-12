//go:build linux

package operator

import "syscall"

func diskFree(path string) (uint64, error) {
	var s syscall.Statfs_t
	err := syscall.Statfs(path, &s)
	return s.Bavail * uint64(s.Bsize), err
}
