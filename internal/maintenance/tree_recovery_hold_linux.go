//go:build linux

package maintenance

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"syscall"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"golang.org/x/sys/unix"
)

// VerifyTreeRecoveryHoldBinding checks the runtime-owned marker while the host
// holds the native control and runtime leases.
func (g *Gate) VerifyTreeRecoveryHoldBinding(ctx context.Context, binding string) error {
	return g.checkTreeRecoveryHoldBinding(ctx, binding, true)
}

// InspectTreeRecoveryHoldBinding observes the already durable hold during
// read-only work under the native control and runtime leases.
func (g *Gate) InspectTreeRecoveryHoldBinding(ctx context.Context, binding string) error {
	return g.checkTreeRecoveryHoldBinding(ctx, binding, false)
}

func (g *Gate) checkTreeRecoveryHoldBinding(ctx context.Context, binding string, sync bool) error {
	if g == nil || g.root == nil || ctx == nil || !validTreeRecoveryBinding(binding) {
		return ErrState
	}
	check := func() error {
		opened, err := g.root.Stat(".")
		current, pathErr := os.Lstat(g.root.Name())
		if err != nil || pathErr != nil || !current.IsDir() || !os.SameFile(opened, current) {
			return ErrState
		}
		return ctx.Err()
	}
	return g.verifyTreeRecoveryHold(ctx, []byte(treeRecoveryHoldPrefix+binding+"\n"), check, sync)
}

func (g *Gate) verifyTreeRecoveryHold(ctx context.Context, expected []byte, check func() error, sync bool) error {
	root, err := g.root.Stat(".")
	if err != nil {
		return err
	}
	owner, ok := root.Sys().(*syscall.Stat_t)
	if !ok {
		return ErrState
	}
	private := func(info os.FileInfo) bool {
		if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return false
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		return ok && st.Nlink == 1 && st.Uid == owner.Uid && st.Gid == owner.Gid
	}
	info, err := g.root.Lstat(TreeRecoveryHold)
	if err != nil || !private(info) || info.Size() != int64(len(expected)) {
		return ErrState
	}
	f, err := g.root.Open(TreeRecoveryHold)
	if err != nil {
		return ErrState
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !private(opened) || !os.SameFile(info, opened) {
		return ErrState
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(len(expected))+1))
	if err != nil || !bytes.Equal(raw, expected) || ctx.Err() != nil || check() != nil {
		return ErrState
	}
	// If an earlier invocation failed after linking, establish durability
	// before permitting the outer coordinator to advance its own journal.
	if sync {
		if err = f.Sync(); err != nil {
			return err
		}
		if err = fsutil.SyncDirectory(g.root, "."); err != nil {
			return err
		}
	}
	after, err := f.Stat()
	current, pathErr := g.root.Lstat(TreeRecoveryHold)
	beforeStat, beforeOK := opened.Sys().(*syscall.Stat_t)
	if err != nil || pathErr != nil || !private(after) || !private(current) ||
		!os.SameFile(opened, after) || !os.SameFile(opened, current) ||
		after.Size() != opened.Size() || current.Size() != opened.Size() ||
		!after.ModTime().Equal(opened.ModTime()) || !current.ModTime().Equal(opened.ModTime()) || !beforeOK {
		return ErrState
	}
	for _, v := range []os.FileInfo{after, current} {
		st, ok := v.Sys().(*syscall.Stat_t)
		if !ok || st.Ctim != beforeStat.Ctim {
			return ErrState
		}
	}
	return check()
}

func (g *Gate) publishTreeRecoveryHold(ctx context.Context, raw []byte, check func() error) error {
	if _, err := g.root.Lstat(TreeRecoveryHold); err == nil {
		return g.verifyTreeRecoveryHold(ctx, raw, check, true)
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrState
	}
	dir, err := g.root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), ".", unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err // No unsafe named-file fallback on unsupported filesystems.
	}
	f := os.NewFile(uintptr(fd), "anonymous-tree-recovery-hold")
	defer f.Close()
	if err = fsutil.InheritOwner(f, g.root); err != nil {
		return err
	}
	if n, e := f.Write(raw); e != nil {
		return e
	} else if n != len(raw) {
		return io.ErrShortWrite
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if ctx.Err() != nil || check() != nil {
		return ErrState
	}
	proc := "/proc/self/fd/" + strconv.Itoa(fd)
	if err = unix.Linkat(unix.AT_FDCWD, proc, int(dir.Fd()), TreeRecoveryHold, unix.AT_SYMLINK_FOLLOW); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return g.verifyTreeRecoveryHold(ctx, raw, check, true)
		}
		return err
	}
	opened, err := f.Stat()
	named, namedErr := g.root.Lstat(TreeRecoveryHold)
	if err != nil || namedErr != nil || !privateSingleLink(opened) || !privateSingleLink(named) || opened.Mode().Perm() != 0600 || named.Mode().Perm() != 0600 || !os.SameFile(opened, named) {
		return ErrState
	}
	if err = dir.Sync(); err != nil {
		return err
	}
	return g.verifyTreeRecoveryHold(ctx, raw, check, true)
}
