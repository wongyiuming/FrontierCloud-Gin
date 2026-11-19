//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sourceauth"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

var errLocalImportVerified = errors.New("local import already verified")

// verifyLocalCommittedTx rechecks current source facts and actual target bytes;
// a historical completion receipt alone is not proof of present availability.
// The caller holds maintenance, owner and tree fences for the whole check.
func (s *SQLStore) verifyLocalCommittedTx(ctx context.Context, tx *sql.Tx, mediaRoot *os.Root, masterID, mediaID, sourcePath string, size int64, digest string) (PreparedFile, error) {
	var result PreparedFile
	record, entry, err := s.recordByID(ctx, tx, mediaID)
	if err != nil {
		return result, err
	}
	facts, _, err := s.factsFor(ctx, tx, entry, record.ObjectIndex)
	if err != nil {
		return result, err
	}
	placement, err := s.placementFor(ctx, tx, entry, record.ObjectIndex)
	if err != nil {
		return result, err
	}
	path, err := s.localMasterSourceEvidence(ctx, tx, entry, placement, facts, masterID)
	if err != nil || path != sourcePath || placement.Bytes != size || !hmac.Equal([]byte(placement.SHA256), []byte(digest)) {
		return result, ErrConflict
	}
	blobIndex, err := s.tree.BlobIndex(placement.BlobID)
	if err != nil {
		return result, err
	}
	var count int
	if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_operation_ids WHERE completed=1 AND object_index=? AND blob_index=?`, record.ObjectIndex, blobIndex).Scan(&count) != nil || count != 1 {
		return result, ErrConflict
	}
	var op string
	if tx.QueryRowContext(ctx, `SELECT operation_id FROM sealed_tree_operation_ids WHERE completed=1 AND object_index=? AND blob_index=?`, record.ObjectIndex, blobIndex).Scan(&op) != nil {
		return result, ErrConflict
	}
	complete, err := s.completed(ctx, tx, op)
	if err != nil || !complete {
		return result, ErrConflict
	}
	if entry.Kind == "audio" && (facts.LyricResolution == nil || facts.LyricResolution.OperationID != op) {
		return result, ErrConflict
	}
	targetPath, err := BlobPath(placement.BlobID)
	if err != nil {
		return result, err
	}
	target, err := openLocalLegacySource(mediaRoot, targetPath)
	if err != nil {
		return result, err
	}
	defer target.Close()
	info, err := target.File().Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != size {
		return result, ErrBlobIncomplete
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(&contextReader{ctx: ctx, r: target.File()}, size+1))
	after, statErr := target.File().Stat()
	if err != nil || statErr != nil || n != size || target.Check() != nil || !os.SameFile(info, after) || after.Size() != size || !after.ModTime().Equal(info.ModTime()) || !hmac.Equal([]byte(hex.EncodeToString(h.Sum(nil))), []byte(digest)) {
		return result, ErrBlobIncomplete
	}
	if facts.InternalDefaultLyric != nil {
		lrc, e := openLocalLegacySource(mediaRoot, "lyrics/default.lrc")
		if e != nil {
			return result, e
		}
		defer lrc.Close()
		before, e := lrc.File().Stat()
		if e != nil || !before.Mode().IsRegular() || before.Size() != int64(len(sourceauth.DefaultLyricContent)) {
			return result, ErrBlobIncomplete
		}
		raw, e := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, r: lrc.File()}, int64(len(sourceauth.DefaultLyricContent))+1))
		after, e2 := lrc.File().Stat()
		if e != nil || e2 != nil || lrc.Check() != nil || !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) || !bytes.Equal(raw, []byte(sourceauth.DefaultLyricContent)) {
			return result, ErrBlobIncomplete
		}
	}
	return PreparedFile{OperationID: op, BlobID: placement.BlobID, ReadAlias: placement.ReadAlias}, nil
}

// prepareLocalMasterOffline binds local directory facts and a pending placement
// to the actual held source bytes, in one fenced SQLite transaction. Existing
// pending operations are recovered by object ID and must still match the same
// source. This private phase does not constitute a full migration or cutover.
func prepareLocalMasterOffline(ctx context.Context, gate *maintenance.Gate, dataRoot, databasePath string, s *SQLStore, treeRoot, mediaRoot *os.Root, ownerFence *ownerfence.Fence, nodeVault *vault.Vault, masterID, mediaID string) (PreparedFile, error) {
	var result PreparedFile
	verified := false
	if ctx == nil || gate == nil || s == nil || treeRoot == nil || mediaRoot == nil || ownerFence == nil || nodeVault == nil || !s.valid() || !lowerHex(masterID, 32) || !hexID(mediaID) {
		return result, ErrInvalid
	}
	err := withLocalMasterScope(ctx, gate, dataRoot, databasePath, s, treeRoot, mediaRoot, ownerFence, nodeVault, masterID, func(scope *localMasterScope) error {
		var e error
		result, verified, e = prepareLocalMasterHeld(scope, mediaID)
		return e
	})
	if err == nil && verified {
		return result, errLocalImportVerified
	}
	if err != nil {
		return PreparedFile{}, err
	}
	return result, nil
}

// prepareLocalMasterHeld is callable only while the shared offline scope is held.
func prepareLocalMasterHeld(scope *localMasterScope, mediaID string) (result PreparedFile, verified bool, err error) {
	if scope == nil || scope.ctx == nil || scope.s == nil || scope.mediaRoot == nil || scope.guard == nil || !hexID(mediaID) {
		return result, false, ErrInvalid
	}
	held, s, mediaRoot, masterID, guard := scope.ctx, scope.s, scope.mediaRoot, scope.masterID, scope.guard
	err = func() error {
		tx, e := s.db.BeginTx(held, nil)
		if e != nil {
			return e
		}
		if e = guard(tx); e != nil {
			tx.Rollback()
			return e
		}
		var sourcePath, kind, ownerID string
		var size int64
		e = tx.QueryRowContext(held, `SELECT media_path,object_kind,storage_member_id,size_bytes FROM global_media_objects WHERE media_id=? AND state='active'`, mediaID).Scan(&sourcePath, &kind, &ownerID, &size)
		if errors.Is(e, sql.ErrNoRows) {
			e = tx.QueryRowContext(held, `SELECT media_path,object_kind FROM media_objects WHERE media_id=?`, mediaID).Scan(&sourcePath, &kind)
			if e == nil && kind == "lyric" && sourcePath != "lyrics/default.lrc" {
				ownerID = masterID
				size = -1
			} else if e == nil {
				e = ErrConflict
			}
		}
		if e == nil && (ownerID != masterID || kind != "audio" && kind != "video" && kind != "lyric" || size < -1 || size > maxObjectBytes) {
			e = ErrConflict
		}
		if e == nil {
			e = guard(tx)
		}
		if rollback := tx.Rollback(); e == nil && rollback != nil {
			e = rollback
		}
		if e != nil {
			return e
		}
		source, e := openLocalLegacySource(mediaRoot, sourcePath)
		if e != nil {
			return e
		}
		defer source.Close()
		info, e := source.File().Stat()
		if e == nil && size == -1 {
			size = info.Size()
		}
		if e != nil || !info.Mode().IsRegular() || size < 0 || size > maxObjectBytes || info.Size() != size {
			return ErrBlobIncomplete
		}
		h := sha256.New()
		n, e := io.Copy(h, io.LimitReader(&contextReader{ctx: held, r: source.File()}, size+1))
		if e != nil || n != size || source.Check() != nil {
			return ErrBlobIncomplete
		}
		digest := hex.EncodeToString(h.Sum(nil))
		tx, e = s.db.BeginTx(held, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		if e = guard(tx); e != nil {
			return e
		}
		current, e := source.File().Stat()
		if e != nil || source.Check() != nil || !os.SameFile(info, current) || current.Size() != info.Size() || !current.ModTime().Equal(info.ModTime()) {
			return ErrBlobIncomplete
		}
		index, e := s.tree.ObjectIndex(mediaID)
		if e != nil {
			return e
		}
		var op string
		e = tx.QueryRowContext(held, `SELECT operation_id FROM sealed_tree_pending_files WHERE object_index=?`, index).Scan(&op)
		if e == nil {
			_, entry, placement, p, e := s.localMasterPendingSource(held, tx, op, masterID)
			if e != nil || entry.ObjectID != mediaID || p != sourcePath || placement.Bytes != size || !hmac.Equal([]byte(placement.SHA256), []byte(digest)) {
				return ErrConflict
			}
			result = PreparedFile{OperationID: op, BlobID: placement.BlobID, ReadAlias: placement.ReadAlias}
		} else if errors.Is(e, sql.ErrNoRows) {
			_, _, existing := s.recordByID(held, tx, mediaID)
			if existing == nil {
				result, e = s.verifyLocalCommittedTx(held, tx, mediaRoot, masterID, mediaID, sourcePath, size, digest)
				if e != nil {
					return e
				}
				if e = guard(tx); e != nil {
					return e
				}
				current, e = source.File().Stat()
				if e != nil || source.Check() != nil || !os.SameFile(info, current) || current.Size() != info.Size() || !current.ModTime().Equal(info.ModTime()) {
					return ErrBlobIncomplete
				}
				if e = tx.Rollback(); e != nil {
					return e
				}
				verified = true
				return nil
			}
			if !errors.Is(existing, sql.ErrNoRows) {
				return existing
			}
			result, e = s.prepareLocalMasterTx(held, tx, masterID, mediaID, size, digest)
			if e != nil {
				return e
			}
			_, entry, placement, p, e := s.localMasterPendingSource(held, tx, result.OperationID, masterID)
			if e != nil || entry.ObjectID != mediaID || p != sourcePath || placement.Bytes != size || !hmac.Equal([]byte(placement.SHA256), []byte(digest)) {
				return ErrConflict
			}
		} else {
			return e
		}
		if e = guard(tx); e != nil {
			return e
		}
		current, e = source.File().Stat()
		if e != nil || source.Check() != nil || !os.SameFile(info, current) || current.Size() != info.Size() || !current.ModTime().Equal(info.ModTime()) {
			return ErrBlobIncomplete
		}
		return tx.Commit()
	}()
	return
}

// migrateLocalMasterObjectOffline preserves the durable operation ID on a
// publication failure. The caller must perform final set/Owner reconciliation
// before treating a historical completion receipt as current availability.
func migrateLocalMasterObjectOffline(ctx context.Context, gate *maintenance.Gate, dataRoot, databasePath string, s *SQLStore, treeRoot, mediaRoot *os.Root, ownerFence *ownerfence.Fence, nodeVault *vault.Vault, masterID, mediaID string) (PreparedFile, error) {
	var p PreparedFile
	err := withLocalMasterScope(ctx, gate, dataRoot, databasePath, s, treeRoot, mediaRoot, ownerFence, nodeVault, masterID, func(scope *localMasterScope) error {
		var verified bool
		var err error
		p, verified, err = prepareLocalMasterHeld(scope, mediaID)
		if err != nil || verified {
			return err
		}
		return publishLocalMasterHeld(scope, p.OperationID)
	})
	return p, err
}
