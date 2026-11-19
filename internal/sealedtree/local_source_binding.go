package sealedtree

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"reflect"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

func readLocalLegacyEncryption(ctx context.Context, tx treeQuery, native string) (*mediacrypto.Metadata, error) {
	var descriptor sql.NullString
	var fileID string
	err := tx.QueryRowContext(ctx, `SELECT file_id,descriptor_json FROM media_encryption WHERE object_kind='media' AND object_id=?`, native).Scan(&fileID, &descriptor)
	if errors.Is(err, sql.ErrNoRows) || err == nil && !descriptor.Valid {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var decoded mediacrypto.Metadata
	if json.Unmarshal([]byte(descriptor.String), &decoded) != nil || decoded.Validate() != nil || decoded.FileID != fileID {
		return nil, ErrInvalid
	}
	return &decoded, nil
}

func localLegacyLocator(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

// localMasterPendingSource binds a pending encrypted-tree entry to the legacy
// Master Local records in the caller's SQLite transaction. It never accepts a
// caller's asserted source path, owner or metadata as evidence. It is only an
// import check, not physical publication or permission to start the runtime.
// Only the real Master Local Owner is supported; independently owned lyrics
// require their own Owner publication evidence.
func (s *SQLStore) localMasterPendingSource(ctx context.Context, tx treeQuery, operation, master string) (pendingFile, Entry, Placement, string, error) {
	var empty pendingFile
	if !s.valid() || ctx == nil || tx == nil || !hexID(operation) || !lowerHex(master, 32) {
		return empty, Entry{}, Placement{}, "", ErrInvalid
	}
	pending, entry, placement, err := s.pending(ctx, tx, operation)
	if err != nil || pending.facts == nil || (entry.Kind != "video" && entry.Kind != "audio" && entry.Kind != "lyric") {
		return empty, Entry{}, Placement{}, "", ErrInvalid
	}
	facts, err := s.tree.OpenFacts(*pending.facts)
	if err != nil || !factsCompatiblePending(entry, facts) || facts.PendingSelectedUpload != nil || facts.PendingPlaceholder != nil || facts.Revocation != nil || facts.HiddenProof != nil || facts.LyricResolution != nil || entry.Kind != "audio" && (facts.Lyric != nil || facts.InternalDefaultLyric != nil) {
		return empty, Entry{}, Placement{}, "", ErrInvalid
	}
	legacyPath, err := s.localMasterSourceEvidence(ctx, tx, entry, placement, facts, master)
	if err != nil {
		return empty, Entry{}, Placement{}, "", err
	}
	return pending, entry, placement, legacyPath, nil
}

// localMasterSourceEvidence checks the same legacy rows against either a
// pending entry or an already published tree entry in the caller's fenced tx.
func (s *SQLStore) localMasterSourceEvidence(ctx context.Context, tx treeQuery, entry Entry, placement Placement, facts Facts, master string) (string, error) {
	if !s.valid() || ctx == nil || tx == nil || !lowerHex(master, 32) || (entry.Kind != "video" && entry.Kind != "audio" && entry.Kind != "lyric") || !factsCompatiblePending(entry, facts) || facts.PendingSelectedUpload != nil || facts.PendingPlaceholder != nil || facts.Revocation != nil || facts.HiddenProof != nil || entry.Kind != "audio" && (facts.Lyric != nil || facts.InternalDefaultLyric != nil) {
		return "", ErrInvalid
	}
	if facts.LyricResolution != nil {
		if entry.Kind != "audio" || facts.LyricResolution.Origin != "local" {
			return "", ErrInvalid
		}
		expected, e := s.localLyricEvidence(facts)
		if e != nil || !hmac.Equal([]byte(expected), []byte(facts.LyricResolution.Evidence)) {
			return "", ErrInvalid
		}
		facts.LyricResolution = nil
	}
	var err error
	var mediaID, owner, native, legacyPath, kind, etag, state, memberKind, transport, locator string
	var size, created, updated int64
	if entry.Kind == "lyric" {
		// Legacy user-managed lyrics are local Master media_objects, not
		// global_media_objects; never invent a remote owner or legacy ETag.
		mediaID, native, owner = entry.ObjectID, entry.ObjectID, master
		if tx.QueryRowContext(ctx, `SELECT media_path,object_kind FROM media_objects WHERE media_id=?`, mediaID).Scan(&legacyPath, &kind) != nil || kind != "lyric" || tx.QueryRowContext(ctx, `SELECT member_kind,transport FROM cluster_storage_members WHERE member_id=?`, master).Scan(&memberKind, &transport) != nil || memberKind != "MasterLocal" || transport != "Local" || placement.OwnerID != master || placement.NativeObjectID != native || placement.State != "active" || placement.ETag != "" || placement.CreatedAt != 0 || placement.UpdatedAt != 0 {
			return "", ErrConflict
		}
		var conflicting int
		if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM global_media_objects WHERE media_id=? OR media_path=?`, mediaID, legacyPath).Scan(&conflicting) != nil || conflicting != 0 {
			return "", ErrConflict
		}
	} else {
		err = tx.QueryRowContext(ctx, `SELECT g.media_id,g.storage_member_id,g.object_id,g.media_path,g.path_locator,g.object_kind,g.size_bytes,g.etag,g.state,g.created_at,g.updated_at,m.member_kind,m.transport FROM global_media_objects g JOIN cluster_storage_members m ON m.member_id=g.storage_member_id WHERE g.media_id=?`, entry.ObjectID).Scan(&mediaID, &owner, &native, &legacyPath, &locator, &kind, &size, &etag, &state, &created, &updated, &memberKind, &transport)
		if err != nil || locator != localLegacyLocator(legacyPath) || mediaID != entry.ObjectID || native != placement.NativeObjectID || owner != master || placement.OwnerID != master || kind != entry.Kind || size != placement.Bytes || etag != placement.ETag || state != "active" || placement.State != state || placement.CreatedAt != created || placement.UpdatedAt != updated || memberKind != "MasterLocal" || transport != "Local" {
			return "", ErrConflict
		}
	}
	// The current native Master implementation uses the same object identity
	// for local publication. Ambiguous historical mappings require separate
	// reconciliation; never infer an owner/path from a matching filename.
	if native != mediaID || entry.Kind == "video" && !strings.HasPrefix(legacyPath, "vido/") || entry.Kind == "audio" && !strings.HasPrefix(legacyPath, "music/") || entry.Kind == "lyric" && (!strings.HasPrefix(legacyPath, "lyrics/") || legacyPath == "lyrics/default.lrc") || legacyPath != path.Clean(legacyPath) || strings.ContainsAny(legacyPath, "\\\x00") {
		return "", ErrConflict
	}
	actualPath, err := s.pathInTransaction(ctx, tx, entry)
	if err != nil || actualPath != legacyPath {
		return "", ErrConflict
	}
	if err = s.compareLocalLegacyFacts(ctx, tx, entry, facts, legacyPath, true); err != nil {
		return "", err
	}
	var descriptor sql.NullString
	var fileID string
	err = tx.QueryRowContext(ctx, `SELECT file_id,descriptor_json FROM media_encryption WHERE object_kind='media' AND object_id=?`, native).Scan(&fileID, &descriptor)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	var encryption *mediacrypto.Metadata
	if err == nil && descriptor.Valid {
		var decoded mediacrypto.Metadata
		if json.Unmarshal([]byte(descriptor.String), &decoded) != nil || decoded.Validate() != nil || decoded.FileID != fileID {
			return "", ErrInvalid
		}
		encryption = &decoded
	}
	if !reflect.DeepEqual(encryption, placement.Encryption) {
		return "", ErrConflict
	}
	var lyricCount int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM media_lyric_links WHERE media_id=?`, mediaID).Scan(&lyricCount); err != nil || entry.Kind == "video" && lyricCount != 0 || entry.Kind == "audio" && lyricCount > 1 {
		return "", ErrConflict
	}
	// Check each ancestor's identity and direct hidden row. Looking only at
	// the leaf or only at currently visible entries loses inherited rules.
	current := entry.ParentID
	seen := map[string]bool{entry.ObjectID: true}
	for depth := 0; current != s.rootID && depth < 128; depth++ {
		if seen[current] {
			return "", ErrInvalid
		}
		seen[current] = true
		record, parent, e := s.recordByID(ctx, tx, current)
		if e != nil || parent.Kind != "directory" {
			return "", ErrInvalid
		}
		parentFacts, _, e := s.factsFor(ctx, tx, parent, record.ObjectIndex)
		if e != nil {
			return "", e
		}
		parentPath, e := s.pathInTransaction(ctx, tx, parent)
		if e != nil || s.compareLocalLegacyFacts(ctx, tx, parent, parentFacts, parentPath, false) != nil {
			return "", ErrConflict
		}
		current = parent.ParentID
	}
	if current != s.rootID || ctx.Err() != nil {
		return "", ErrConflict
	}
	return legacyPath, nil
}

// compareLocalLegacyFacts preserves absent and explicit-zero rows separately.
// Directories lacking an old media_objects row may have received a new tree
// ID, but any existing old ID must match exactly.
func (s *SQLStore) readLocalLegacyFacts(ctx context.Context, tx treeQuery, entry Entry, legacyPath string, requireObject bool) (Facts, error) {
	expected := Facts{ObjectID: entry.ObjectID}
	var id, kind, created, updated, locator string
	var pathCount int
	if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM media_objects WHERE media_path=?`, legacyPath).Scan(&pathCount) != nil || pathCount > 1 {
		return Facts{}, ErrConflict
	}
	err := tx.QueryRowContext(ctx, `SELECT media_id,object_kind,created_at,updated_at,path_locator FROM media_objects WHERE media_path=?`, legacyPath).Scan(&id, &kind, &created, &updated, &locator)
	if err == nil {
		if pathCount != 1 || locator != localLegacyLocator(legacyPath) || id != entry.ObjectID || kind != entry.Kind {
			return Facts{}, ErrConflict
		}
		expected.Object = &ObjectFact{CreatedAt: created, UpdatedAt: updated}
	} else if !errors.Is(err, sql.ErrNoRows) || requireObject {
		return Facts{}, ErrConflict
	}
	var hidden int64
	var hiddenUpdated string
	err = tx.QueryRowContext(ctx, `SELECT hidden,updated_at FROM media_visibility WHERE relative_path=?`, legacyPath).Scan(&hidden, &hiddenUpdated)
	if err == nil {
		expected.Visibility = &VisibilityFact{Hidden: hidden, UpdatedAt: hiddenUpdated}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return Facts{}, err
	}
	if entry.Kind == "audio" {
		var trackPath, lyricID, lyricPath, lyricCreated, lyricUpdated string
		err = tx.QueryRowContext(ctx, `SELECT media_path,lyric_id,lyric_path,created_at,updated_at FROM media_lyric_links WHERE media_id=?`, entry.ObjectID).Scan(&trackPath, &lyricID, &lyricPath, &lyricCreated, &lyricUpdated)
		if err == nil {
			if trackPath != legacyPath {
				return Facts{}, ErrConflict
			}
			var actualPath, actualKind, actualLocator string
			if tx.QueryRowContext(ctx, `SELECT media_path,object_kind,path_locator FROM media_objects WHERE media_id=?`, lyricID).Scan(&actualPath, &actualKind, &actualLocator) != nil || actualPath != lyricPath || actualKind != "lyric" || actualLocator != localLegacyLocator(actualPath) {
				return Facts{}, ErrConflict
			}
			if lyricPath == "lyrics/default.lrc" {
				var descriptor sql.NullString
				e := tx.QueryRowContext(ctx, `SELECT descriptor_json FROM media_encryption WHERE object_kind='media' AND object_id=?`, lyricID).Scan(&descriptor)
				if e != nil && !errors.Is(e, sql.ErrNoRows) || e == nil && descriptor.Valid {
					return Facts{}, ErrConflict
				}
				expected.InternalDefaultLyric = &DefaultLyricFact{LegacyMediaPath: trackPath, DefaultLyricID: lyricID, CreatedAt: lyricCreated, UpdatedAt: lyricUpdated}
			} else {
				expected.Lyric = &LyricFact{LegacyMediaPath: trackPath, LyricID: lyricID, LegacyLyricPath: lyricPath, CreatedAt: lyricCreated, UpdatedAt: lyricUpdated}
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return Facts{}, err
		}
	}
	var playbackPath, playbackCreated, playbackUpdated string
	var score, preference int64
	err = tx.QueryRowContext(ctx, `SELECT media_path,play_score,preference,created_at,updated_at FROM media_playback_stats WHERE media_id=?`, entry.ObjectID).Scan(&playbackPath, &score, &preference, &playbackCreated, &playbackUpdated)
	if err == nil {
		if playbackPath != legacyPath {
			return Facts{}, ErrConflict
		}
		expected.Playback = &PlaybackFact{LegacyMediaPath: playbackPath, PlayScore: score, Preference: preference, CreatedAt: playbackCreated, UpdatedAt: playbackUpdated}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return Facts{}, err
	}
	return expected, nil
}

func (s *SQLStore) compareLocalLegacyFacts(ctx context.Context, tx treeQuery, entry Entry, actual Facts, legacyPath string, requireObject bool) error {
	expected, err := s.readLocalLegacyFacts(ctx, tx, entry, legacyPath, requireObject)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, expected) {
		return ErrConflict
	}
	return nil
}

// sealLocalLyricPendingTx runs only after localMasterPendingSource rechecked the
// actual old relation and ancestry in this same fenced write transaction. It
// generates and permanently reserves a fresh facts nonce before replacing the
// pending record; a transaction rollback restores the former pending state.
func (s *SQLStore) sealLocalLyricPendingTx(ctx context.Context, tx treeQuery, pending pendingFile, entry Entry) (pendingFile, error) {
	if entry.Kind != "audio" || pending.facts == nil {
		return pending, ErrInvalid
	}
	facts, err := s.tree.OpenFacts(*pending.facts)
	if err != nil || facts.LyricResolution != nil {
		return pending, ErrInvalid
	}
	state := "none"
	if facts.Lyric != nil {
		state = "explicit"
	}
	if facts.InternalDefaultLyric != nil {
		state = "default"
	}
	facts.LyricResolution = &LyricResolutionFact{Origin: "local", State: state, OperationID: pending.op}
	evidence, err := s.localLyricEvidence(facts)
	if err != nil {
		return pending, err
	}
	facts.LyricResolution.Evidence = evidence
	sealed, err := s.tree.SealFacts(facts, pending.facts.Revision)
	if err != nil {
		return pending, err
	}
	id, err := FactsEncryptionID(sealed)
	if err != nil {
		return pending, err
	}
	if _, err = reserveID(ctx, tx, id); err != nil {
		return pending, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE sealed_tree_pending_facts SET encryption_id=?,sealed=? WHERE operation_id=? AND object_index=? AND revision=? AND encryption_id=? AND sealed=?`, id, sealed.Sealed, pending.op, pending.facts.ObjectIndex, pending.facts.Revision, pending.factsID, pending.facts.Sealed)
	if err != nil {
		return pending, err
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return pending, ErrConflict
	}
	oldMAC := pending.mac
	pending.facts = &sealed
	pending.factsID = id
	pending.mac = s.pendingMAC(pending)
	result, err = tx.ExecContext(ctx, `UPDATE sealed_tree_pending_files SET operation_mac=? WHERE operation_id=? AND operation_mac=?`, pending.mac, pending.op, oldMAC)
	if err != nil {
		return pending, err
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return pending, ErrConflict
	}
	return pending, nil
}
