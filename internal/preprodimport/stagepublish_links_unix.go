//go:build linux || darwin

package preprodimport

import (
	"os"
	"syscall"
)

func stagePublishLinkCount(info os.FileInfo) (uint64, bool) {
	if info == nil {
		return 0, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(stat.Nlink), true
}
