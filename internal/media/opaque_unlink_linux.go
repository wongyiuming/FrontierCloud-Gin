//go:build linux

package media

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// Only a single-link file can be certified absent by unlinking this path.
// A retained staging hard link would otherwise preserve the object bytes.
func opaqueSingleLink(info os.FileInfo) bool {
	return opaqueExactLinks(info, 1)
}

func opaqueExactLinks(info os.FileInfo, links uint64) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Nlink) == links
}

func sameOpaqueDeleteFile(a, b os.FileInfo) bool { return sameRecoveryOpaqueFile(a, b) }

func openOpaqueDeleteFile(root *os.Root, name string) (*os.File, error) {
	dir, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func unlinkOpaqueFile(root *os.Root, name string) error {
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return unix.Unlinkat(int(dir.Fd()), name, 0)
}

func opaqueDirectoryIdentity(info os.FileInfo) (uint64, uint64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() {
		return 0, 0, false
	}
	return uint64(stat.Dev), stat.Ino, true
}
