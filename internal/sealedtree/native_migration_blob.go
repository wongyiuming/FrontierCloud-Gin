//go:build linux

package sealedtree

import (
	"context"
	"errors"
	"os"
	"path"
	"regexp"
	"syscall"

	"golang.org/x/sys/unix"
)

var nativeMigrationStageName = regexp.MustCompile(`^\.migration-data-[a-f0-9]{32}-[a-f0-9]{64}\.part$`)

// InstallVerifiedMigrationBlob links the target's verified private stage into
// its opaque object store without copying bytes. The caller holds the Owner
// policy, migration operation and volume write leases. It supplies the same
// open file and stat used to verify the bytes under its durable publishing
// intent. The caller keeps custody of the stage for recovery and cleanup.
// This method does not authorize a read or register an Owner alias.
func (p *BlobPublisher) InstallVerifiedMigrationBlob(ctx context.Context, stageName, blobID string, size int64, verified *os.File, proof os.FileInfo) error {
	if p == nil || p.root == nil || ctx == nil || verified == nil || proof == nil ||
		!nativeMigrationStageName.MatchString(stageName) || size < 0 || size > maxObjectBytes {
		return ErrInvalid
	}
	dest, err := BlobPath(blobID)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	held, err := verified.Stat()
	if err != nil || !matchesMigrationBlob(held, proof, size) {
		return ErrBlobIncomplete
	}
	stage, err := migrationBlobInfo(p.root, stageName)
	if err != nil || !matchesMigrationBlob(stage, proof, size) || verified.Sync() != nil {
		return ErrBlobIncomplete
	}
	for _, directory := range []string{"objects", path.Join("objects", blobID[:2]), path.Dir(dest)} {
		if err := ensureMigrationBlobDirectory(p.root, directory); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err := migrationBlobInfo(p.root, dest)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if !migrationBlobLinks(stage, 1) || blobLink(p.root, stageName, dest, held, false) != nil {
			return ErrBlobIncomplete
		}
	case err != nil || !matchesMigrationBlob(current, proof, size):
		return ErrBlobIncomplete
	}
	stage, err = migrationBlobInfo(p.root, stageName)
	current, targetErr := migrationBlobInfo(p.root, dest)
	if err != nil || targetErr != nil || !matchesMigrationBlob(stage, proof, size) || !matchesMigrationBlob(current, proof, size) ||
		!migrationBlobLinks(stage, 2) || !migrationBlobLinks(current, 2) {
		return ErrBlobIncomplete
	}
	// Replay also syncs the final directory: the previous process may have
	// stopped immediately after linking the inode.
	parent, _, err := blobParent(p.root, dest)
	if err != nil {
		return ErrBlobIncomplete
	}
	defer parent.Close()
	if err := parent.Sync(); err != nil {
		return ErrBlobIncomplete
	}
	return ctx.Err()
}

func migrationBlobInfo(root *os.Root, name string) (os.FileInfo, error) {
	f, err := blobOpen(root, name, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Stat()
}

func matchesMigrationBlob(info, proof os.FileInfo, size int64) bool {
	return info.Mode() == 0600 && proof.Mode() == 0600 && info.Size() == size && proof.Size() == size &&
		os.SameFile(info, proof) && info.ModTime().Equal(proof.ModTime())
}

func migrationBlobLinks(info os.FileInfo, count uint64) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Nlink) == count
}

func ensureMigrationBlobDirectory(root *os.Root, name string) error {
	parent, leaf, err := blobParent(root, name)
	if err != nil {
		return ErrBlobIncomplete
	}
	defer parent.Close()
	if err = unix.Mkdirat(int(parent.Fd()), leaf, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return ErrBlobIncomplete
	}
	var stat unix.Stat_t
	if err = unix.Fstatat(int(parent.Fd()), leaf, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFDIR || parent.Sync() != nil {
		return ErrBlobIncomplete
	}
	return nil
}
