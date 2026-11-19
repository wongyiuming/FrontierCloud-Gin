//go:build linux

package selectedupload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"strings"

	"golang.org/x/sys/unix"
)

// operationParent retains a no-follow directory descriptor for each removal.
// Only the caller's generated stage/blob paths may be passed here.
func operationParent(root *os.Root, name string) (*os.File, string, error) {
	dir, leaf := path.Split(name)
	if leaf == "" || leaf == "." || leaf == ".." {
		return nil, "", errOperationLease
	}
	current, err := root.Open(".")
	if err != nil {
		return nil, "", err
	}
	for _, component := range strings.Split(strings.TrimSuffix(dir, "/"), "/") {
		if component == "" || component == "." || component == ".." {
			current.Close()
			return nil, "", errOperationLease
		}
		fd, e := unix.Openat(int(current.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		current.Close()
		if e != nil {
			return nil, "", e
		}
		current = os.NewFile(uintptr(fd), component)
	}
	return current, leaf, nil
}

func removeOperationPath(ctx context.Context, root *os.Root, name string, expectedDigest string, expectedSize int64) error {
	parent, leaf, err := operationParent(root, name)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return errOperationLease
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), leaf, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return errOperationLease
	}
	file := os.NewFile(uintptr(fd), leaf)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errOperationLease
	}
	if expectedDigest != "" {
		if info.Size() != expectedSize {
			return errOperationLease
		}
		hash := sha256.New()
		n, e := io.CopyBuffer(hash, io.LimitReader(&cancelReader{ctx: ctx, source: file}, expectedSize+1), make([]byte, 64<<10))
		if e != nil || n != expectedSize || hex.EncodeToString(hash.Sum(nil)) != expectedDigest {
			return errOperationLease
		}
	}
	var named, opened unix.Stat_t
	if unix.Fstat(int(file.Fd()), &opened) != nil || unix.Fstatat(int(parent.Fd()), leaf, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || opened.Dev != named.Dev || opened.Ino != named.Ino || named.Mode&unix.S_IFMT != unix.S_IFREG || ctx.Err() != nil {
		return errOperationLease
	}
	checkParent := func() bool {
		reopened, _, e := operationParent(root, name)
		if e != nil {
			return false
		}
		defer reopened.Close()
		a, e1 := parent.Stat()
		b, e2 := reopened.Stat()
		return e1 == nil && e2 == nil && os.SameFile(a, b)
	}
	if !checkParent() || unix.Unlinkat(int(parent.Fd()), leaf, 0) != nil || parent.Sync() != nil || !checkParent() || ctx.Err() != nil {
		return errOperationLease
	}
	return nil
}

type cancelReader struct {
	ctx    context.Context
	source io.Reader
}

func (r *cancelReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.source.Read(p)
}
