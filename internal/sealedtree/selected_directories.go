package sealedtree

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

// EnsureSelectedDirectories creates missing directories for an authenticated
// new upload or the system roots in one fenced transaction. Callers must hold
// the runtime gate and validate the upload layout before invoking it. Existing records and
// their names/facts are authenticated; a file occupying a component fails.
// Newly committed empty directories do not imply that an upload succeeded.
func (s *SQLStore) EnsureSelectedDirectories(ctx context.Context, path string) (string, error) {
	return s.ensureSelectedDirectories(ctx, path, false)
}

// PrepareSelectedHiddenDirectory creates the final directory and its directly
// hidden facts atomically. An existing visible final directory is never changed.
func (s *SQLStore) PrepareSelectedHiddenDirectory(ctx context.Context, path string) error {
	_, err := s.ensureSelectedDirectories(ctx, path, true)
	return err
}

func (s *SQLStore) ensureSelectedDirectories(ctx context.Context, path string, hiddenFinal bool) (string, error) {
	if !s.valid() || ctx == nil || len(path) > 4096 || !utf8.ValidString(path) || utf8.RuneCountInString(path) > 1024 {
		return "", ErrInvalid
	}
	parts := strings.Split(path, "/")
	mediaPath := len(parts) <= 3 && (parts[0] == "music" || parts[0] == "vido")
	lyricPath := len(parts) >= 1 && len(parts) <= 3 && parts[0] == "lyrics"
	if !mediaPath && !lyricPath {
		return "", ErrInvalid
	}
	// Never allow this operation to hide one of the shared system roots.
	if hiddenFinal && (len(parts) < 2 || parts[0] != "music" && parts[0] != "vido") {
		return "", ErrInvalid
	}
	for _, part := range parts {
		if !validComponent(part) {
			return "", ErrInvalid
		}
	}
	release, err := s.acquireMutation(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if err = s.lockIndexedWriter(ctx, tx); err != nil {
		return "", err
	}
	if err = s.verifyRoot(ctx, tx); err != nil {
		return "", err
	}
	parent := s.rootID
	for index, part := range parts {
		group, e := s.tree.ParentIndex(parent)
		if e != nil {
			return "", e
		}
		lookup, e := s.tree.Lookup(parent, part)
		if e != nil {
			return "", e
		}
		// A pending file cannot also become a directory. The records and
		// pending tables have separate uniqueness constraints.
		var pending int
		if e = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_pending_files WHERE parent_index=? AND lookup_tag=?`, group, lookup).Scan(&pending); e != nil {
			return "", e
		}
		if pending != 0 {
			return "", ErrConflict
		}
		record, e := scanRecord(tx.QueryRowContext(ctx, `SELECT object_index,parent_index,lookup_tag,revision,encryption_id,sealed FROM sealed_tree_records WHERE parent_index=? AND lookup_tag=?`, group, lookup))
		if e == nil {
			if e = verifyNameReservation(ctx, tx, record); e != nil {
				return "", e
			}
			entry, _, e := s.visibleListEntry(ctx, tx, parent, record)
			if e != nil {
				return "", e
			}
			if entry.Name != part || entry.Kind != "directory" {
				return "", ErrConflict
			}
			if hiddenFinal && index == len(parts)-1 {
				facts, _, factErr := s.factsFor(ctx, tx, entry, record.ObjectIndex)
				if factErr != nil || facts.Visibility == nil || facts.Visibility.Hidden != 1 {
					return "", ErrConflict
				}
			}
			parent = entry.ObjectID
			continue
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return "", e
		}
		id, e := NewBlobID()
		if e != nil {
			return "", e
		}
		entry := Entry{ParentID: parent, ObjectID: id, Kind: "directory", Name: part}
		facts := Facts{ObjectID: id}
		if hiddenFinal && index == len(parts)-1 {
			facts.Visibility = &VisibilityFact{Hidden: 1, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		}
		sealed, e := s.tree.Seal(parent, id, entry.Kind, part, 1)
		if e != nil {
			return "", e
		}
		sealedFacts, e := s.tree.SealFacts(facts, 1)
		if e != nil || sealedFacts.ObjectIndex != sealed.ObjectIndex {
			return "", ErrInvalid
		}
		if e = s.createDirectoryTx(ctx, tx, entry, &facts, sealed, &sealedFacts); e != nil {
			return "", e
		}
		parent = id
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return parent, nil
}
