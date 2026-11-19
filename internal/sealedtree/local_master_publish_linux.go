//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"reflect"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sourceauth"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// ErrLocalImportReconcile reports an authenticated historical commit, not
// current source/target availability or permission to remove the old file.
var ErrLocalImportReconcile = errors.New("local import committed; reconciliation required")

// publishLocalMasterLegacyOffline implements the narrow Master Local video
// publication phase. It is not registered as a command or runtime route.
// Default/independently owned lyric files, remote Owners and S3 remain closed
// pending their own complete evidence. Original files and rows are retained.
func publishLocalMasterLegacyOffline(ctx context.Context, gate *maintenance.Gate, dataRoot, databasePath string, s *SQLStore, treeRoot, mediaRoot *os.Root, ownerFence *ownerfence.Fence, nodeVault *vault.Vault, masterID, operation string) error {
	if ctx == nil || gate == nil || s == nil || treeRoot == nil || mediaRoot == nil || ownerFence == nil || nodeVault == nil || !s.valid() || !lowerHex(masterID, 32) || !hexID(operation) {
		return ErrInvalid
	}
	return withLocalMasterScope(ctx, gate, dataRoot, databasePath, s, treeRoot, mediaRoot, ownerFence, nodeVault, masterID, func(scope *localMasterScope) error {
		return publishLocalMasterHeld(scope, operation)
	})
}

// publishLocalMasterHeld preserves the scope for the entire publication.
func publishLocalMasterHeld(scope *localMasterScope, operation string) error {
	if scope == nil || scope.ctx == nil || scope.s == nil || scope.mediaRoot == nil || scope.guard == nil || scope.checkFences == nil || !hexID(operation) {
		return ErrInvalid
	}
	held, s, mediaRoot, masterID, guard := scope.ctx, scope.s, scope.mediaRoot, scope.masterID, scope.guard

	tx, e := s.db.BeginTx(held, nil)
	if e != nil {
		return e
	}
	if e = guard(tx); e != nil {
		tx.Rollback()
		return e
	}
	committed, e := s.completed(held, tx, operation)
	if e != nil {
		tx.Rollback()
		return e
	}
	if committed {
		tx.Rollback()
		return ErrLocalImportReconcile
	}
	before, entry, placement, sourcePath, e := s.localMasterPendingSource(held, tx, operation, masterID)
	if e == nil {
		e = guard(tx)
	}
	if rollback := tx.Rollback(); e == nil && rollback != nil {
		e = rollback
	}
	if e != nil {
		return e
	}
	facts, e := s.tree.OpenFacts(*before.facts)
	if e != nil {
		return e
	}
	var defaultPinned *localLegacySource
	var defaultInfo os.FileInfo
	if facts.InternalDefaultLyric != nil {
		defaultPinned, e = openLocalLegacySource(mediaRoot, "lyrics/default.lrc")
		if e != nil {
			return e
		}
		defer defaultPinned.Close()
		defaultInfo, e = defaultPinned.File().Stat()
		if e != nil || !defaultInfo.Mode().IsRegular() || defaultInfo.Size() != int64(len(sourceauth.DefaultLyricContent)) {
			return ErrBlobIncomplete
		}
		raw, err := io.ReadAll(io.LimitReader(&contextReader{ctx: held, r: defaultPinned.File()}, int64(len(sourceauth.DefaultLyricContent))+1))
		if err != nil || !bytes.Equal(raw, []byte(sourceauth.DefaultLyricContent)) || defaultPinned.Check() != nil {
			return ErrBlobIncomplete
		}
	}
	checkDefault := func() error {
		if defaultPinned == nil {
			return nil
		}
		current, err := defaultPinned.File().Stat()
		if err != nil || defaultPinned.Check() != nil || !os.SameFile(defaultInfo, current) || current.Size() != defaultInfo.Size() || !current.ModTime().Equal(defaultInfo.ModTime()) {
			return ErrBlobIncomplete
		}
		return nil
	}
	pinned, e := openLocalLegacySource(mediaRoot, sourcePath)
	if e != nil {
		return e
	}
	defer pinned.Close()
	source := pinned.File()
	heldInfo, e := source.Stat()
	if e != nil || !heldInfo.Mode().IsRegular() || heldInfo.Size() != placement.Bytes {
		return ErrBlobIncomplete
	}
	verifySource := func() error {
		if _, e = source.Seek(0, io.SeekStart); e != nil {
			return ErrBlobIncomplete
		}
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(&contextReader{ctx: held, r: source}, placement.Bytes+1))
		if err != nil || n != placement.Bytes || !hmac.Equal([]byte(hex.EncodeToString(h.Sum(nil))), []byte(placement.SHA256)) {
			return ErrBlobIncomplete
		}
		a, err := source.Stat()
		if err != nil || !os.SameFile(heldInfo, a) || a.Size() != heldInfo.Size() || !a.ModTime().Equal(heldInfo.ModTime()) {
			return ErrBlobIncomplete
		}
		if err := pinned.Check(); err != nil {
			return ErrBlobIncomplete
		}
		return nil
	}
	if e = verifySource(); e != nil {
		return e
	}
	if e = checkLocalOpaqueStage(mediaRoot, operation, placement.BlobID, placement.Bytes); e != nil {
		return e
	}
	if _, e = source.Seek(0, io.SeekStart); e != nil {
		return ErrBlobIncomplete
	}
	pub, e := NewBlobPublisher(mediaRoot)
	if e != nil {
		return e
	}
	if e = pub.Stage(held, operation, placement.BlobID, placement.Bytes, placement.SHA256, source); e != nil {
		return e
	}
	if e = checkLocalOpaqueDirectories(mediaRoot, placement.BlobID); e != nil {
		return e
	}
	if e = verifySource(); e != nil {
		return e
	}
	if scope.checkFences() != nil || checkDefault() != nil {
		return ErrFenceRequired
	}
	if e = pub.PublishStaged(held, operation, placement.BlobID, placement.Bytes, placement.SHA256); e != nil {
		return e
	}
	if e = checkLocalOpaqueDirectories(mediaRoot, placement.BlobID); e != nil {
		return e
	}
	destination, e := BlobPath(placement.BlobID)
	if e != nil {
		return e
	}
	destinationInfo, e := mediaRoot.Lstat(destination)
	if e != nil || !destinationInfo.Mode().IsRegular() || destinationInfo.Mode()&os.ModeSymlink != 0 {
		return ErrBlobIncomplete
	}
	// Retain the no-follow target and all of its parent directory handles
	// through the metadata commit. A checked pathname alone is not an
	// authorization to commit if another process replaces an inode.
	target, e := openLocalLegacySource(mediaRoot, destination)
	if e != nil {
		return e
	}
	defer target.Close()
	targetInfo, e := target.File().Stat()
	if e != nil || !targetInfo.Mode().IsRegular() || targetInfo.Size() != placement.Bytes {
		return ErrBlobIncomplete
	}
	hash := sha256.New()
	n, e := io.Copy(hash, io.LimitReader(&contextReader{ctx: held, r: target.File()}, placement.Bytes+1))
	if e != nil || n != placement.Bytes || !hmac.Equal([]byte(hex.EncodeToString(hash.Sum(nil))), []byte(placement.SHA256)) || target.Check() != nil {
		return ErrBlobIncomplete
	}
	tx, e = s.db.BeginTx(held, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = guard(tx); e != nil {
		return e
	}
	after, entry2, placement2, path2, e := s.localMasterPendingSource(held, tx, operation, masterID)
	if e != nil || !samePending(before, after) || entry != entry2 || !reflect.DeepEqual(placement, placement2) || sourcePath != path2 {
		return ErrConflict
	}
	current, e := source.Stat()
	if e != nil || pinned.Check() != nil || !os.SameFile(heldInfo, current) || current.Size() != heldInfo.Size() || !current.ModTime().Equal(heldInfo.ModTime()) {
		return ErrBlobIncomplete
	}
	currentTarget, e := target.File().Stat()
	if e != nil || target.Check() != nil || !os.SameFile(targetInfo, currentTarget) || currentTarget.Size() != targetInfo.Size() || !currentTarget.ModTime().Equal(targetInfo.ModTime()) {
		return ErrBlobIncomplete
	}
	commitPending := before
	if entry.Kind == "audio" {
		commitPending, e = s.sealLocalLyricPendingTx(held, tx, after, entry)
		if e != nil {
			return e
		}
	}
	if e = s.finalizePendingTx(held, tx, operation, commitPending, entry, placement); e != nil {
		return e
	}
	if e = guard(tx); e != nil {
		return e
	}
	lastSource, sourceErr := source.Stat()
	lastTarget, targetErr := target.File().Stat()
	if sourceErr != nil || targetErr != nil || pinned.Check() != nil || target.Check() != nil || checkDefault() != nil || !os.SameFile(heldInfo, lastSource) || !os.SameFile(targetInfo, lastTarget) || lastSource.Size() != heldInfo.Size() || lastTarget.Size() != targetInfo.Size() || !lastSource.ModTime().Equal(heldInfo.ModTime()) || !lastTarget.ModTime().Equal(targetInfo.ModTime()) {
		return ErrBlobIncomplete
	}
	return tx.Commit()
}

// Existing complete stages are reverified by BlobPublisher, and must not be
// charged for another copy. In both cases retain the normal physical reserve.
func checkLocalOpaqueStage(root *os.Root, operation, blob string, size int64) error {
	if root == nil || size < 0 || !hexID(operation) || !hexID(blob) {
		return ErrInvalid
	}
	if err := checkLocalOpaqueDirectories(root, blob); err != nil {
		return err
	}
	stage, err := stagePath(operation)
	if err != nil {
		return err
	}
	info, err := root.Lstat(stage)
	existing := err == nil
	if existing && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != size) {
		return ErrBlobIncomplete
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrBlobIncomplete
	}
	_, free, err := fsutil.DiskUsage(root)
	if err != nil || free < store.PhysicalReserve || !existing && size > free-store.PhysicalReserve {
		return ErrBlobIncomplete
	}
	return nil
}

func checkLocalOpaqueDirectories(root *os.Root, blob string) error {
	if root == nil || !hexID(blob) {
		return ErrInvalid
	}
	for _, name := range []string{"staging", "objects", path.Join("objects", blob[:2]), path.Join("objects", blob[:2], blob[2:4])} {
		info, err := root.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrBlobIncomplete
		}
	}
	destination, err := BlobPath(blob)
	if err != nil {
		return err
	}
	info, err := root.Lstat(destination)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrBlobIncomplete
	}
	return nil
}
