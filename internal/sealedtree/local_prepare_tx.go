package sealedtree

import (
	"context"
	"database/sql"
	"errors"
	"path"
	"strings"
)

// prepareLocalMasterTx creates missing source-derived directory facts and one
// fresh pending file on the caller's single SQLite transaction. Only the
// private offline coordinator may call it after hashing a no-follow held local
// source under maintenance, Owner and tree fences; size/digest are not an
// externally supplied authorization. It neither publishes nor activates data.
func (s *SQLStore) prepareLocalMasterTx(ctx context.Context, tx treeQuery, master, mediaID string, size int64, digest string) (PreparedFile, error) {
	var empty PreparedFile
	if !s.valid() || ctx == nil || tx == nil || !lowerHex(master, 32) || !hexID(mediaID) || size < 0 || size > maxObjectBytes || !hexID(digest) {
		return empty, ErrInvalid
	}
	var sourcePath, kind, owner, native, etag, state, locator, memberKind, transport string
	var oldSize, created, updated int64
	err := tx.QueryRowContext(ctx, `SELECT g.media_path,g.object_kind,g.storage_member_id,g.object_id,g.size_bytes,g.etag,g.state,g.created_at,g.updated_at,g.path_locator,m.member_kind,m.transport FROM global_media_objects g JOIN cluster_storage_members m ON m.member_id=g.storage_member_id WHERE g.media_id=?`, mediaID).Scan(&sourcePath, &kind, &owner, &native, &oldSize, &etag, &state, &created, &updated, &locator, &memberKind, &transport)
	if errors.Is(err, sql.ErrNoRows) {
		if tx.QueryRowContext(ctx, `SELECT media_path,object_kind,path_locator FROM media_objects WHERE media_id=?`, mediaID).Scan(&sourcePath, &kind, &locator) != nil || kind != "lyric" || sourcePath == "lyrics/default.lrc" || !strings.HasPrefix(sourcePath, "lyrics/") {
			return empty, ErrConflict
		}
		var conflicts int
		if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM global_media_objects WHERE media_id=? OR media_path=?`, mediaID, sourcePath).Scan(&conflicts) != nil || conflicts != 0 || tx.QueryRowContext(ctx, `SELECT member_kind,transport FROM cluster_storage_members WHERE member_id=?`, master).Scan(&memberKind, &transport) != nil {
			return empty, ErrConflict
		}
		owner, native, state, oldSize = master, mediaID, "active", size
		err = nil
	}
	if err != nil || (kind != "audio" && kind != "video" && kind != "lyric") || owner != master || native != mediaID || oldSize != size || state != "active" || memberKind != "MasterLocal" || transport != "Local" || locator != localLegacyLocator(sourcePath) || kind == "audio" && !strings.HasPrefix(sourcePath, "music/") || kind == "video" && !strings.HasPrefix(sourcePath, "vido/") || sourcePath != path.Clean(sourcePath) || strings.ContainsAny(sourcePath, "\\\x00") {
		return empty, ErrConflict
	}
	parts := strings.Split(sourcePath, "/")
	if len(parts) < 2 || len(parts) > 128 {
		return empty, ErrInvalid
	}
	parent, err := s.ensureLegacyDirectoryPathTx(ctx, tx, strings.Join(parts[:len(parts)-1], "/"))
	if err != nil {
		return empty, err
	}
	entry := Entry{ParentID: parent, ObjectID: mediaID, Kind: kind, Name: parts[len(parts)-1]}
	facts, err := s.readLocalLegacyFacts(ctx, tx, entry, sourcePath, true)
	if err != nil {
		return empty, err
	}
	encryption, err := readLocalLegacyEncryption(ctx, tx, native)
	if err != nil {
		return empty, err
	}
	blob, err := NewBlobID()
	if err != nil {
		return empty, err
	}
	alias, err := NewBlobID()
	if err != nil {
		return empty, err
	}
	op, err := NewBlobID()
	if err != nil {
		return empty, err
	}
	placement := Placement{ObjectID: mediaID, NativeObjectID: native, OwnerID: master, BlobID: blob, ReadAlias: alias, Bytes: size, SHA256: digest, ETag: etag, State: state, CreatedAt: created, UpdatedAt: updated, Encryption: encryption}
	if op == blob || op == alias || op == mediaID || !validPlacement(placement) {
		return empty, ErrInvalid
	}
	name, err := s.tree.Seal(parent, mediaID, kind, entry.Name, 1)
	if err != nil {
		return empty, err
	}
	loc, err := s.tree.SealPlacement(placement, 1)
	if err != nil || loc.ObjectIndex != name.ObjectIndex {
		return empty, ErrInvalid
	}
	sealedFacts, err := s.tree.SealFacts(facts, 1)
	if err != nil || sealedFacts.ObjectIndex != name.ObjectIndex {
		return empty, ErrInvalid
	}
	if err = s.prepareFileTx(ctx, tx, entry, placement, &facts, name, loc, &sealedFacts, op); err != nil {
		return empty, err
	}
	return PreparedFile{OperationID: op, BlobID: blob, ReadAlias: alias}, nil
}

// ensureLegacyDirectoryPathTx imports or authenticates every old directory and
// its direct visibility facts in the caller's fenced transaction. The caller
// must establish source ownership and authorize the full source path first.
func (s *SQLStore) ensureLegacyDirectoryPathTx(ctx context.Context, tx treeQuery, dirPath string) (string, error) {
	if !s.valid() || ctx == nil || tx == nil || dirPath == "" || dirPath != path.Clean(dirPath) || strings.ContainsAny(dirPath, "\\\x00") {
		return "", ErrInvalid
	}
	parts := strings.Split(dirPath, "/")
	if len(parts) < 1 || len(parts) >= 128 {
		return "", ErrInvalid
	}
	parent := s.rootID
	for i, component := range parts {
		if !validComponent(component) {
			return "", ErrInvalid
		}
		oldPath := strings.Join(parts[:i+1], "/")
		group, e := s.tree.ParentIndex(parent)
		if e != nil {
			return "", e
		}
		lookup, e := s.tree.Lookup(parent, component)
		if e != nil {
			return "", e
		}
		record, e := scanRecord(tx.QueryRowContext(ctx, `SELECT object_index,parent_index,lookup_tag,revision,encryption_id,sealed FROM sealed_tree_records WHERE parent_index=? AND lookup_tag=?`, group, lookup))
		if errors.Is(e, sql.ErrNoRows) {
			var existingID, oldKind, oldLocator string
			e = tx.QueryRowContext(ctx, `SELECT media_id,object_kind,path_locator FROM media_objects WHERE media_path=?`, oldPath).Scan(&existingID, &oldKind, &oldLocator)
			if e == nil {
				if oldKind != "directory" || !hexID(existingID) || oldLocator != localLegacyLocator(oldPath) {
					return "", ErrConflict
				}
			} else if errors.Is(e, sql.ErrNoRows) {
				existingID, e = NewBlobID()
				if e != nil {
					return "", e
				}
			} else {
				return "", e
			}
			dir := Entry{ParentID: parent, ObjectID: existingID, Kind: "directory", Name: component}
			facts, e := s.readLocalLegacyFacts(ctx, tx, dir, oldPath, false)
			if e != nil {
				return "", e
			}
			r, e := s.tree.Seal(dir.ParentID, dir.ObjectID, dir.Kind, dir.Name, 1)
			if e != nil {
				return "", e
			}
			f, e := s.tree.SealFacts(facts, 1)
			if e != nil || f.ObjectIndex != r.ObjectIndex {
				return "", ErrInvalid
			}
			if e = s.createDirectoryTx(ctx, tx, dir, &facts, r, &f); e != nil {
				return "", e
			}
			parent = dir.ObjectID
		} else {
			if e != nil || verifyNameReservation(ctx, tx, record) != nil {
				return "", ErrConflict
			}
			dir, e := s.tree.Open(parent, record)
			if e != nil || dir.Name != component || dir.Kind != "directory" {
				return "", ErrConflict
			}
			facts, _, e := s.factsFor(ctx, tx, dir, record.ObjectIndex)
			if e != nil || s.compareLocalLegacyFacts(ctx, tx, dir, facts, oldPath, false) != nil {
				return "", ErrConflict
			}
			parent = dir.ObjectID
		}
	}
	return parent, nil
}
