//go:build linux

package sealedtree

import (
	"os"
	"path"
	"strings"

	"golang.org/x/sys/unix"
)

// localLegacySource retains a no-follow handle for every path component.
// Check compares each held inode with the still-named child under its held
// parent, so replacing an ancestor or leaf fails before the SQL commit.
type localLegacySource struct {
	files []*os.File
	names []string
}

// LegacyOwnerSource pins every path component without following symlinks.
// Authorization remains the responsibility of the paired Owner operation.
type LegacyOwnerSource = localLegacySource

func OpenLegacyOwnerSource(root *os.Root, name string) (*LegacyOwnerSource, error) {
	return openLocalLegacySource(root, name)
}

func openLocalLegacySource(root *os.Root, name string) (*localLegacySource, error) {
	if root == nil || name == "" || name != path.Clean(name) || strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\\\x00") {
		return nil, ErrInvalid
	}
	parts := strings.Split(name, "/")
	for _, part := range parts {
		if part == "" || strings.HasPrefix(part, ".") {
			return nil, ErrInvalid
		}
	}
	base, err := root.Open(".")
	if err != nil {
		return nil, ErrBlobIncomplete
	}
	s := &localLegacySource{files: []*os.File{base}, names: parts}
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		fd, e := unix.Openat(int(s.files[len(s.files)-1].Fd()), part, flags, 0)
		if e != nil {
			s.Close()
			return nil, ErrBlobIncomplete
		}
		s.files = append(s.files, os.NewFile(uintptr(fd), "local-legacy-source"))
	}
	if err = s.Check(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *localLegacySource) File() *os.File {
	if s == nil || len(s.files) == 0 {
		return nil
	}
	return s.files[len(s.files)-1]
}

func (s *localLegacySource) Check() error {
	if s == nil || len(s.files) != len(s.names)+1 || len(s.names) == 0 {
		return ErrBlobIncomplete
	}
	for i, name := range s.names {
		var held, named unix.Stat_t
		if unix.Fstat(int(s.files[i+1].Fd()), &held) != nil || unix.Fstatat(int(s.files[i].Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || held.Dev != named.Dev || held.Ino != named.Ino || held.Mode != named.Mode {
			return ErrBlobIncomplete
		}
		if i < len(s.names)-1 && held.Mode&unix.S_IFMT != unix.S_IFDIR || i == len(s.names)-1 && held.Mode&unix.S_IFMT != unix.S_IFREG {
			return ErrBlobIncomplete
		}
	}
	return nil
}

func (s *localLegacySource) Close() {
	if s == nil {
		return
	}
	for i := len(s.files) - 1; i >= 0; i-- {
		_ = s.files[i].Close()
	}
	s.files = nil
}
