//go:build linux

package preprodimport

// This unregistered local sampler models the read-only part of a future SSH
// collector. It does not sign, transfer, mutate or publish an object. Short
// shared locks protect only opening and rechecking; byte hashing happens after
// releasing the source-wide lock. A cooperative writer, filesystem that can
// mutate an open inode without a detectable version change, or another node
// may invalidate the observation. It is not an atomic snapshot or an import
// authorization, and it has never been run against production.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const sourceLockName = ".media-mutation.lock"

type sourceFileObservation struct {
	SHA256           string
	Size             int64
	Device, Inode    uint64
	MtimeNS, CtimeNS int64
}

func statSourceFile(info fs.FileInfo) (sourceFileObservation, error) {
	var out sourceFileObservation
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return out, invalid("source file type")
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || s.Ino == 0 || s.Nlink != 1 {
		return out, invalid("source file identity")
	}
	out.Size = info.Size()
	out.Device = uint64(s.Dev)
	out.Inode = s.Ino
	out.MtimeNS = s.Mtim.Sec*1e9 + s.Mtim.Nsec
	out.CtimeNS = s.Ctim.Sec*1e9 + s.Ctim.Nsec
	return out, nil
}

// sourceShortLease opens only an existing regular lock file, fails on inode
// replacement and never creates a lock. Caller must release immediately after
// open/stat; it must not read object bytes while this lease is held.
func sourceShortLease(ctx context.Context, root *os.Root) (func(), error) {
	if ctx == nil || root == nil {
		return nil, invalid("source lock")
	}
	if !filepath.IsAbs(root.Name()) || filepath.Clean(root.Name()) != root.Name() {
		return nil, invalid("source root")
	}
	rootPath, err := os.Lstat(root.Name())
	if err != nil || !rootPath.IsDir() || rootPath.Mode()&os.ModeSymlink != 0 {
		return nil, invalid("source root")
	}
	rootOpened, err := root.Stat(".")
	if err != nil || !os.SameFile(rootPath, rootOpened) {
		return nil, invalid("source root replaced")
	}
	before, err := root.Lstat(sourceLockName)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, invalid("source lock unavailable")
	}
	file, err := root.OpenFile(sourceLockName, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, invalid("source lock unavailable")
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		file.Close()
		return nil, invalid("source lock replaced")
	}
	deadline := time.NewTimer(250 * time.Millisecond)
	defer deadline.Stop()
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			file.Close()
			return nil, invalid("source lock unavailable")
		}
		select {
		case <-ctx.Done():
			file.Close()
			return nil, ctx.Err()
		case <-deadline.C:
			file.Close()
			return nil, invalid("source lock busy")
		case <-time.After(10 * time.Millisecond):
		}
	}
	current, err := root.Lstat(sourceLockName)
	if err != nil || !os.SameFile(opened, current) || ctx.Err() != nil {
		syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		file.Close()
		return nil, invalid("source lock replaced")
	}
	return func() { syscall.Flock(int(file.Fd()), syscall.LOCK_UN); file.Close() }, nil
}

// sourcePathFile resolves every parent without following a symlink and retains
// the parent roots. The caller compares each resolved directory on re-open.
func sourcePathFile(root *os.Root, name string) (*os.File, []fs.FileInfo, []*os.Root, error) {
	if root == nil || !fs.ValidPath(name) || name == "." || strings.HasPrefix(name, "/") {
		return nil, nil, nil, invalid("source object path")
	}
	parts := strings.Split(name, "/")
	if len(parts) < 2 || (parts[0] != "music" && parts[0] != "vido" && parts[0] != "lyrics") {
		return nil, nil, nil, invalid("source object path")
	}
	current := root
	roots := make([]*os.Root, 0, len(parts))
	infos := make([]fs.FileInfo, 0, len(parts))
	closeRoots := func() {
		for i := len(roots) - 1; i >= 0; i-- {
			roots[i].Close()
		}
	}
	for _, part := range parts[:len(parts)-1] {
		info, err := current.Lstat(part)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			closeRoots()
			return nil, nil, nil, invalid("source object parent")
		}
		next, err := current.OpenRoot(part)
		if err != nil {
			closeRoots()
			return nil, nil, nil, invalid("source object parent")
		}
		opened, err := next.Stat(".")
		if err != nil || !os.SameFile(info, opened) {
			next.Close()
			closeRoots()
			return nil, nil, nil, invalid("source object parent changed")
		}
		roots = append(roots, next)
		infos = append(infos, info)
		current = next
	}
	leaf := parts[len(parts)-1]
	before, err := current.Lstat(leaf)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		closeRoots()
		return nil, nil, nil, invalid("source object file")
	}
	// Fail if O_NOATIME is unavailable or unauthorized rather than altering
	// source metadata as a side effect of a supposedly read-only sample.
	file, err := current.OpenFile(leaf, os.O_RDONLY|syscall.O_NOATIME|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		closeRoots()
		return nil, nil, nil, invalid("source object file")
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		file.Close()
		closeRoots()
		return nil, nil, nil, invalid("source object file changed")
	}
	infos = append(infos, before)
	return file, infos, roots, nil
}

func closeSourceRoots(roots []*os.Root) {
	for i := len(roots) - 1; i >= 0; i-- {
		roots[i].Close()
	}
}

// sampleSourceObject requires a caller deadline and a bounded transfer rate.
// It computes only a candidate digest. It rejects missing locks, changed
// directory/file identity, size, mtime, ctime and hardlinks. Even on success,
// same-attribute ABA, uncooperative writers and cross-node changes remain hard
// gates; this result must not authorize real preproduction import on its own.
func sampleSourceObject(ctx context.Context, root *os.Root, name string, expected, rate int64) (sourceFileObservation, error) {
	var empty sourceFileObservation
	if ctx == nil || root == nil || expected < 0 || expected > 10*1024*1024*1024 || rate <= 0 || rate > 4*1024*1024 {
		return empty, invalid("source sample limits")
	}
	if _, ok := ctx.Deadline(); !ok {
		return empty, invalid("source sample deadline")
	}
	release, err := sourceShortLease(ctx, root)
	if err != nil {
		return empty, err
	}
	file, parts, roots, err := sourcePathFile(root, name)
	if err != nil {
		release()
		return empty, err
	}
	opened, err := file.Stat()
	before, e := statSourceFile(opened)
	release()
	defer file.Close()
	defer closeSourceRoots(roots)
	if err != nil || e != nil || before.Size != expected {
		return empty, invalid("source sample identity")
	}
	h := sha256.New()
	limit := &limiter{start: time.Now(), rate: rate}
	n, err := io.CopyBuffer(h, checkedReader{ctx, io.LimitReader(file, expected+1), limit}, make([]byte, 64*1024))
	if err != nil || n != expected || ctx.Err() != nil {
		return empty, invalid("source sample read")
	}
	release, err = sourceShortLease(ctx, root)
	if err != nil {
		return empty, err
	}
	defer release()
	afterInfo, err := file.Stat()
	after, e := statSourceFile(afterInfo)
	if err != nil || e != nil || before != after {
		return empty, invalid("source sample changed")
	}
	again, againParts, againRoots, err := sourcePathFile(root, name)
	if err != nil {
		return empty, err
	}
	defer again.Close()
	defer closeSourceRoots(againRoots)
	if len(parts) != len(againParts) {
		return empty, invalid("source sample changed")
	}
	for i := range parts {
		if !os.SameFile(parts[i], againParts[i]) {
			return empty, invalid("source sample changed")
		}
	}
	finalInfo, err := again.Stat()
	final, e := statSourceFile(finalInfo)
	if err != nil || e != nil || before != final || ctx.Err() != nil {
		return empty, invalid("source sample changed")
	}
	before.SHA256 = hex.EncodeToString(h.Sum(nil))
	return before, nil
}
