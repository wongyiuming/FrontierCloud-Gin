//go:build linux

package recovery

import (
	"os"
	"syscall"
)

func archiveSourceMetadataEqual(a, b os.FileInfo) bool {
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink && x.Ctim == y.Ctim
}

func archiveSourceMetadataDifference(a, b os.FileInfo) string {
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	if !xok || !yok {
		return "stat"
	}
	if x.Uid != y.Uid {
		return "uid"
	}
	if x.Gid != y.Gid {
		return "gid"
	}
	if x.Nlink != y.Nlink {
		return "nlink"
	}
	if x.Ctim != y.Ctim {
		return "ctime"
	}
	return "unknown"
}
