//go:build linux

package media

import (
	"context"
	"errors"
	"os"
	"syscall"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"golang.org/x/sys/unix"
)

// ClearOpaqueMasterLocalDeletionStage drops only the authenticated completed
// publication's extra link. It leaves the published inode in place. Removing
// the last link requires the separate ciphertext proof and durable journal.
func (s *Service) ClearOpaqueMasterLocalDeletionStage(ctx context.Context, owner store.OwnerControlLease, publication string, p sealedtree.Placement, authorize func(context.Context) error) error {
	if p.State != "active" || p.Encryption == nil || p.Encryption.Validate() != nil || p.Encryption.CiphertextSize != p.Bytes {
		return store.ErrNodeState
	}
	return s.withMasterLocalDeleteVolume(ctx, owner, p.OwnerID, authorize, func(_ string, check func() error) error {
		return s.removeOpaquePublicationLink(ctx, publication, p.BlobID, p.Bytes, authorize, check)
	})
}

// The caller holds the actual exclusive volume lease and has independently
// authenticated the exact completed publication, its Owner and the deletion.
func (s *Service) removeOpaquePublicationLink(ctx context.Context, publication, blobID string, bytes int64, authorize func(context.Context) error, volumeCheck func() error) error {
	if !ownedObjectID.MatchString(publication) || !ownedObjectID.MatchString(blobID) || publication == blobID ||
		bytes <= 0 || bytes > 10*store.GiB || authorize == nil || volumeCheck == nil {
		return store.ErrNodeState
	}
	before, err := s.root.Lstat("staging")
	if errors.Is(err, os.ErrNotExist) {
		if err = volumeCheck(); err != nil {
			return err
		}
		return authorize(ctx)
	}
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return store.ErrNodeState
	}
	dir, err := s.root.OpenRoot("staging")
	if err != nil {
		return store.ErrNodeState
	}
	defer dir.Close()
	handle, err := dir.Open(".")
	if err != nil {
		return store.ErrNodeState
	}
	defer handle.Close()
	check := func() error {
		opened, openedErr := handle.Stat()
		current, currentErr := s.root.Lstat("staging")
		if openedErr != nil || currentErr != nil || !current.IsDir() || !os.SameFile(before, opened) ||
			!os.SameFile(before, current) || volumeCheck() != nil {
			return store.ErrNodeState
		}
		return nil
	}
	stageName := publication + ".part"
	stage, err := dir.Lstat(stageName)
	if errors.Is(err, os.ErrNotExist) {
		// An earlier attempt may have unlinked this name before fsync.
		if check() != nil || handle.Sync() != nil || check() != nil {
			return store.ErrNodeState
		}
		return authorize(ctx)
	}
	if err != nil || !stage.Mode().IsRegular() || stage.Size() != bytes || check() != nil {
		return store.ErrNodeState
	}
	parent, err := openOpaqueBlobParent(s.root, blobID)
	if err != nil {
		return err
	}
	defer parent.Close()
	blobName := blobID + ".blob"
	if err = authorize(ctx); err != nil {
		return err
	}
	blob, blobErr := parent.Leaf().Lstat(blobName)
	currentStage, stageErr := dir.Lstat(stageName)
	if blobErr != nil || stageErr != nil || !blob.Mode().IsRegular() || !currentStage.Mode().IsRegular() || blob.Size() != bytes ||
		!os.SameFile(stage, currentStage) || !os.SameFile(stage, blob) || parent.Check() != nil || check() != nil {
		return store.ErrNodeState
	}
	info, ok := blob.Sys().(*syscall.Stat_t)
	if !ok || info.Nlink != 2 {
		return store.ErrNodeState
	}
	if err = unix.Unlinkat(int(handle.Fd()), stageName, 0); err != nil {
		return err
	}
	current, err := parent.Leaf().Lstat(blobName)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(blob, current) || !opaqueSingleLink(current) ||
		handle.Sync() != nil || parent.Check() != nil || check() != nil {
		return store.ErrNodeState
	}
	return authorize(ctx)
}
