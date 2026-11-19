//go:build linux

package migrationdata

import (
	"context"
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// RetireAnchor removes the private staging link after durable target commit.
// The caller holds the Owner, operation and volume leases and rechecks the
// exact committed authority in authorizeCommitted. The final blob survives.
func (t *OpaqueMediaTransfer) RetireAnchor(ctx context.Context, authorizeCommitted func() error) (OpaqueMediaProgress, error) {
	var held *os.File
	defer func() {
		if held != nil {
			held.Close()
		}
	}()
	var proof os.FileInfo
	var stage string
	verify := func(c Checkpoint, name string, exists bool) error {
		stage = name
		var err error
		held, err = t.openOpaqueBlob()
		if err != nil {
			return err
		}
		before, err := held.Stat()
		if err != nil {
			return err
		}
		if err := t.checkOpaqueAnchor(stage, exists, before); err != nil {
			return err
		}
		proof, err = verifyCheckpointFile(ctx, c, held)
		if err == nil && !sameCheckpointFile(proof, before) {
			return ErrState
		}
		return err
	}
	recheck := func(exists bool) error {
		if err := authorizeCommitted(); err != nil {
			return err
		}
		blob, err := t.openOpaqueBlob()
		if err != nil {
			return err
		}
		defer blob.Close()
		current, err := blob.Stat()
		if err != nil {
			return err
		}
		if !sameCheckpointFile(current, proof) {
			return ErrState
		}
		return t.checkOpaqueAnchor(stage, exists, current)
	}
	return opaqueMediaProgress(t.receiver.retireAnchor(ctx, t.spec, authorizeCommitted, verify, recheck))
}

// CancelPublication recovers an interrupted target installation only when the
// caller can still prove the exact target has no committed Owner or Master
// authority. The caller holds the same leases required for Publish and
// rechecks that proof in authorizeUnpublished. A published receipt is final.
func (t *OpaqueMediaTransfer) CancelPublication(ctx context.Context, authorizeUnpublished func() error) (OpaqueMediaProgress, error) {
	if authorizeUnpublished == nil {
		return OpaqueMediaProgress{}, ErrState
	}
	unlink := func(stage string, proof os.FileInfo) error {
		if err := authorizeUnpublished(); err != nil {
			return err
		}
		dir, leaf, err := t.openOpaqueBlobParent()
		if err != nil {
			return err
		}
		defer dir.Close()
		blob, err := openOpaqueBlobEntry(dir, leaf)
		if errors.Is(err, os.ErrNotExist) {
			if err := t.checkOpaqueStage(stage, proof, 1); err != nil {
				return err
			}
			// A previous attempt may have stopped just after unlinking.
			return dir.Sync()
		}
		if err != nil {
			return err
		}
		defer blob.Close()
		current, err := blob.Stat()
		if err != nil {
			return err
		}
		if !sameCheckpointFile(current, proof) || !opaqueFileLinks(current, 2) {
			return ErrState
		}
		if err := t.checkOpaqueStage(stage, proof, 2); err != nil {
			return err
		}
		var named unix.Stat_t
		if err := unix.Fstatat(int(dir.Fd()), leaf, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		inode := current.Sys().(*syscall.Stat_t)
		if named.Mode != unix.S_IFREG|0600 || named.Ino != inode.Ino || uint64(named.Dev) != uint64(inode.Dev) {
			return ErrState
		}
		if err := unix.Unlinkat(int(dir.Fd()), leaf, 0); err != nil {
			return err
		}
		return dir.Sync()
	}
	return opaqueMediaProgress(t.receiver.cancelPublication(ctx, t.spec, authorizeUnpublished, unlink, t.confirmOpaqueCancellation))
}

func (t *OpaqueMediaTransfer) checkOpaqueAnchor(stage string, exists bool, final os.FileInfo) error {
	if exists {
		if !opaqueFileLinks(final, 2) {
			return ErrState
		}
		return t.checkOpaqueStage(stage, final, 2)
	}
	if !opaqueFileLinks(final, 1) {
		return ErrState
	}
	_, err := t.receiver.root.Lstat(stage)
	if !errors.Is(err, os.ErrNotExist) {
		return ErrState
	}
	return nil
}

func (t *OpaqueMediaTransfer) checkOpaqueStage(stage string, proof os.FileInfo, links uint64) error {
	info, err := t.receiver.root.Lstat(stage)
	if err != nil || !sameCheckpointFile(info, proof) || !opaqueFileLinks(info, links) {
		return ErrState
	}
	return nil
}

func opaqueFileLinks(info os.FileInfo, count uint64) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode() == 0600 && uint64(stat.Nlink) == count
}

func (t *OpaqueMediaTransfer) confirmOpaqueCancellation(stage string, stageAbsent bool) error {
	dir, leaf, err := t.openOpaqueBlobParent()
	if err != nil {
		return err
	}
	defer dir.Close()
	if leaf != "" {
		var entry unix.Stat_t
		err := unix.Fstatat(int(dir.Fd()), leaf, &entry, unix.AT_SYMLINK_NOFOLLOW)
		if !errors.Is(err, os.ErrNotExist) {
			return ErrState
		}
	}
	info, err := t.receiver.root.Lstat(stage)
	if stageAbsent && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if stageAbsent || err != nil || !opaqueFileLinks(info, 1) {
		return ErrState
	}
	return nil
}

func (t *OpaqueMediaTransfer) openOpaqueBlob() (*os.File, error) {
	parent, leaf, err := t.openOpaqueBlobParent()
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	return openOpaqueBlobEntry(parent, leaf)
}

// Derive the canonical opaque locator from the authenticated target blob ID.
// Walk one component at a time without following symlinks. A missing parent
// returns the nearest existing directory with an empty leaf.
func (t *OpaqueMediaTransfer) openOpaqueBlobParent() (*os.File, string, error) {
	id := t.spec.ObjectID
	dir, err := t.receiver.root.Open(".")
	if err != nil {
		return nil, "", err
	}
	for _, name := range []string{"objects", id[:2], id[2:4]} {
		fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, os.ErrNotExist) {
			return dir, "", nil
		}
		dir.Close()
		if err != nil {
			return nil, "", err
		}
		dir = os.NewFile(uintptr(fd), name)
	}
	return dir, id + ".blob", nil
}

func openOpaqueBlobEntry(parent *os.File, leaf string) (*os.File, error) {
	if leaf == "" {
		return nil, os.ErrNotExist
	}
	fd, err := unix.Openat(int(parent.Fd()), leaf, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), leaf), nil
}
