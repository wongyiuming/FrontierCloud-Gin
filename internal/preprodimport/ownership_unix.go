//go:build unix

package preprodimport

import (
	"os"
	"syscall"
)

func privateOwned(info os.FileInfo, dir bool) bool {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.IsDir() != dir {
		return false
	}
	if !dir && !info.Mode().IsRegular() {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}
