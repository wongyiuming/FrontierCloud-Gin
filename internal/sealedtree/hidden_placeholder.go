package sealedtree

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"unicode/utf8"
)

// StageHiddenDirectoryRuleForImport records an orphan directory hide in
// encrypted internal placeholders. Missing path components are never listed,
// even with include_hidden. This isolated import primitive does not authorize
// a migration or publish a real directory; the caller must have authenticated
// the complete source and hold all deployment gates. It refuses to hide an
// existing real directory because that needs full owner-grant revocation.
// Subtree delete/unhide and product import/writer wiring are not implemented.
func (s *SQLStore) StageHiddenDirectoryRuleForImport(ctx context.Context, path, updatedAt string) (string, error) {
	if !s.valid() || ctx == nil || path == "" || len(path) > 4096 || !utf8.ValidString(path) || utf8.RuneCountInString(path) > 1024 || !factText(updatedAt, 128, false) {
		return "", ErrInvalid
	}
	parts := strings.Split(path, "/")
	if len(parts) < 2 || len(parts) > 4 || (parts[0] != "music" && parts[0] != "vido" && parts[0] != "lyrics") {
		return "", ErrInvalid
	}
	for _, part := range parts {
		if !validComponent(part) || strings.HasPrefix(part, ".") || strings.Contains(part, ":") {
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
	for i, name := range parts {
		parentIndex, e := s.tree.ParentIndex(parent)
		if e != nil {
			return "", ErrInvalid
		}
		lookup, e := s.tree.Lookup(parent, name)
		if e != nil {
			return "", ErrInvalid
		}
		r, e := scanRecord(tx.QueryRowContext(ctx, `SELECT object_index,parent_index,lookup_tag,revision,encryption_id,sealed FROM sealed_tree_records WHERE parent_index=? AND lookup_tag=?`, parentIndex, lookup))
		if errors.Is(e, sql.ErrNoRows) {
			id, e := NewBlobID()
			if e != nil || id == parent || id == s.rootID {
				return "", ErrInvalid
			}
			entry := Entry{ParentID: parent, ObjectID: id, Kind: "directory", Name: name}
			facts := Facts{ObjectID: id, InternalPlaceholder: true}
			if i == len(parts)-1 {
				facts.Visibility = &VisibilityFact{Hidden: 1, UpdatedAt: updatedAt}
			}
			if e = s.insertPlaceholder(ctx, tx, entry, facts); e != nil {
				return "", e
			}
			parent = id
			continue
		}
		if e != nil || verifyNameReservation(ctx, tx, r) != nil {
			return "", ErrInvalid
		}
		entry, e := s.tree.Open(parent, r)
		if e != nil || entry.Kind != "directory" || entry.Name != name {
			return "", ErrConflict
		}
		facts, revision, e := s.factsFor(ctx, tx, entry, r.ObjectIndex)
		if e != nil || facts.Revocation != nil {
			return "", ErrInvalid
		}
		if i == len(parts)-1 {
			if !facts.InternalPlaceholder {
				return "", ErrConflict
			}
			if facts.Visibility == nil || facts.Visibility.Hidden != 1 || facts.Visibility.UpdatedAt != updatedAt {
				facts.Visibility = &VisibilityFact{Hidden: 1, UpdatedAt: updatedAt}
				if e = s.updatePlaceholderFacts(ctx, tx, entry, r, facts, revision); e != nil {
					return "", e
				}
			}
		}
		parent = entry.ObjectID
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return parent, nil
}

// PromoteHiddenPlaceholderForImport turns one staged internal directory into
// a real tree directory without discarding its hide rule. Its parent must
// already be real; caller must reconcile any legacy identity and metadata.
// This remains an isolated import primitive, not a product create operation.
func (s *SQLStore) PromoteHiddenPlaceholderForImport(ctx context.Context, objectID string, expectedRevision int64, facts Facts) error {
	if !s.valid() || ctx == nil || !hexID(objectID) || facts.ObjectID != objectID || facts.InternalPlaceholder || facts.InternalPromotedPlaceholder || expectedRevision < 1 || expectedRevision == int64(^uint64(0)>>1) {
		return ErrInvalid
	}
	release, err := s.acquireMutation(ctx)
	if err != nil {
		return err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.lockIndexedWriter(ctx, tx); err != nil {
		return err
	}
	if err = s.verifyRoot(ctx, tx); err != nil {
		return err
	}
	record, entry, err := s.recordByID(ctx, tx, objectID)
	if err != nil || entry.Kind != "directory" {
		return ErrInvalid
	}
	if _, err = s.listingAncestorAnchor(ctx, tx, entry.ParentID, true); err != nil {
		return err
	}
	old, revision, err := s.factsFor(ctx, tx, entry, record.ObjectIndex)
	if err != nil {
		return ErrConflict
	}
	if !old.InternalPlaceholder {
		if !old.InternalPromotedPlaceholder || revision != expectedRevision+1 || facts.Visibility != nil && !reflect.DeepEqual(facts.Visibility, old.Visibility) {
			return ErrConflict
		}
		facts.Visibility = old.Visibility
		facts.InternalPromotedPlaceholder = true
		if !reflect.DeepEqual(old, facts) {
			return ErrConflict
		}
		return nil // exact recovery; do not advance the tree generation
	}
	if revision != expectedRevision {
		return ErrConflict
	}
	if facts.Visibility != nil && !reflect.DeepEqual(facts.Visibility, old.Visibility) {
		return ErrConflict
	}
	facts.Visibility = old.Visibility
	facts.InternalPromotedPlaceholder = true
	if !factsCompatible(entry, facts) || facts.Revocation != nil || facts.HiddenProof != nil {
		return ErrInvalid
	}
	sealed, err := s.tree.SealFacts(facts, revision+1)
	if err != nil {
		return err
	}
	id, err := FactsEncryptionID(sealed)
	if err != nil {
		return err
	}
	if _, err = reserveID(ctx, tx, id); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE sealed_tree_facts SET revision=?,encryption_id=?,sealed=? WHERE object_index=? AND revision=?`, sealed.Revision, id, sealed.Sealed, record.ObjectIndex, revision)
	if err != nil {
		return ErrConflict
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return ErrConflict
	}
	if err = s.listingRemove(ctx, tx, entry, record, listingInternal); err != nil {
		return err
	}
	if err = s.listingAdd(ctx, tx, entry, record, listingClass(&facts)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) insertPlaceholder(ctx context.Context, tx treeQuery, entry Entry, facts Facts) error {
	if !factsCompatible(entry, facts) || !facts.InternalPlaceholder {
		return ErrInvalid
	}
	name, err := s.tree.Seal(entry.ParentID, entry.ObjectID, entry.Kind, entry.Name, 1)
	if err != nil {
		return err
	}
	sealed, err := s.tree.SealFacts(facts, 1)
	if err != nil || sealed.ObjectIndex != name.ObjectIndex {
		return ErrInvalid
	}
	nameID, err := reserveEncryptionID(ctx, tx, name)
	if err != nil {
		return err
	}
	factsID, err := FactsEncryptionID(sealed)
	if err != nil {
		return err
	}
	if _, err = reserveID(ctx, tx, factsID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_records(object_index,parent_index,lookup_tag,revision,encryption_id,sealed) VALUES(?,?,?,?,?,?)`, name.ObjectIndex, name.ParentIndex, name.Lookup, name.Revision, nameID, name.Sealed); err != nil {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_facts(object_index,revision,encryption_id,sealed) VALUES(?,?,?,?)`, sealed.ObjectIndex, sealed.Revision, factsID, sealed.Sealed); err != nil {
		return ErrConflict
	}
	if err = s.listingAdd(ctx, tx, entry, name, listingInternal); err != nil {
		return err
	}
	for _, class := range []int{listingHidden, listingVisibleGroup, listingInternal} {
		if err = s.createListingGroup(ctx, tx, entry.ObjectID, class); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLStore) updatePlaceholderFacts(ctx context.Context, tx treeQuery, entry Entry, record Record, facts Facts, revision int64) error {
	if revision < 1 || revision == int64(^uint64(0)>>1) || !factsCompatible(entry, facts) || !facts.InternalPlaceholder {
		return ErrInvalid
	}
	sealed, err := s.tree.SealFacts(facts, revision+1)
	if err != nil {
		return err
	}
	id, err := FactsEncryptionID(sealed)
	if err != nil {
		return err
	}
	if _, err = reserveID(ctx, tx, id); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE sealed_tree_facts SET revision=?,encryption_id=?,sealed=? WHERE object_index=? AND revision=?`, sealed.Revision, id, sealed.Sealed, record.ObjectIndex, revision)
	if err != nil {
		return ErrConflict
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return ErrConflict
	}
	return s.listingAdjust(ctx, tx, s.listingClassGroup(entry.ParentID, listingInternal), 0)
}
