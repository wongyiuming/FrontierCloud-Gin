//go:build linux

package operator

import (
	"os"
	"strconv"
	"syscall"
)

func diskAllocated(info os.FileInfo) uint64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Blocks < 0 || stat.Nlink != 1 {
		return 0
	}
	return uint64(stat.Blocks) * 512
}

func diskFilesystem(path string) (string, error) {
	var s syscall.Stat_t
	err := syscall.Stat(path, &s)
	return strconv.FormatUint(uint64(s.Dev), 10), err
}

func diskFree(path string) (uint64, error) {
	var s syscall.Statfs_t
	err := syscall.Statfs(path, &s)
	return s.Bavail * uint64(s.Bsize), err
}
