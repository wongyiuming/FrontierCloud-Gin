//go:build linux

package sealedtree

import (
	"os"
	"path"
	"strings"

	"golang.org/x/sys/unix"
)

// blobParent pins every component below the controlled root without following
// symlinks. The caller retains the returned directory until the operation ends.
func blobParent(root *os.Root, name string) (*os.File, string, error) {
	dir, leaf := path.Split(name)
	if leaf == "" || leaf == "." || leaf == ".." {
		return nil, "", ErrBlobIncomplete
	}
	f, err := root.Open(".")
	if err != nil {
		return nil, "", err
	}
	for _, component := range strings.Split(strings.TrimSuffix(dir, "/"), "/") {
		if component == "" {
			continue
		}
		if component == "." || component == ".." {
			f.Close()
			return nil, "", ErrBlobIncomplete
		}
		fd, e := unix.Openat(int(f.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		f.Close()
		if e != nil {
			return nil, "", e
		}
		f = os.NewFile(uintptr(fd), component)
	}
	return f, leaf, nil
}
func blobOpen(root *os.Root, name string, flags int, mode os.FileMode) (*os.File, error) {
	dir, leaf, err := blobParent(root, name)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), leaf, flags|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), leaf), nil
}
func blobLink(root *os.Root, source, target string, expected os.FileInfo, allowExisting bool) error {
	sd, sl, err := blobParent(root, source)
	if err != nil {
		return ErrBlobIncomplete
	}
	defer sd.Close()
	td, tl, err := blobParent(root, target)
	if err != nil {
		return ErrBlobIncomplete
	}
	defer td.Close()
	srcfd, err := unix.Openat(int(sd.Fd()), sl, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrBlobIncomplete
	}
	sf := os.NewFile(uintptr(srcfd), sl)
	defer sf.Close()
	si, err := sf.Stat()
	if err != nil || !si.Mode().IsRegular() || !os.SameFile(expected, si) {
		return ErrBlobIncomplete
	}
	err = unix.Linkat(int(sd.Fd()), sl, int(td.Fd()), tl, 0)
	created := err == nil
	if err != nil && !(allowExisting && err == unix.EEXIST) {
		return ErrBlobIncomplete
	}
	dstfd, err := unix.Openat(int(td.Fd()), tl, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrBlobIncomplete
	}
	df := os.NewFile(uintptr(dstfd), tl)
	defer df.Close()
	di, err := df.Stat()
	if err != nil || !di.Mode().IsRegular() {
		return ErrBlobIncomplete
	}
	if created && !os.SameFile(expected, di) {
		return ErrBlobIncomplete
	}
	// Both pinned directories must still be the directories reachable through
	// the controlled root before this operation can be acknowledged.
	for _, entry := range []struct {
		name string
		held *os.File
	}{{source, sd}, {target, td}} {
		current, _, e := blobParent(root, entry.name)
		if e != nil {
			return ErrBlobIncomplete
		}
		a, e1 := entry.held.Stat()
		b, e2 := current.Stat()
		current.Close()
		if e1 != nil || e2 != nil || !os.SameFile(a, b) {
			return ErrBlobIncomplete
		}
	}
	if td.Sync() != nil {
		return ErrBlobIncomplete
	}
	return nil
}
