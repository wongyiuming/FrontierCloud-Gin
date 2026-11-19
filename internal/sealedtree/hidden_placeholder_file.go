package sealedtree

import (
	"context"
	"database/sql"
	"reflect"
)

// placeholderForFile authenticates the old orphan rule and proves that the
// placeholder is a leaf, including pending children and all index groups.
// Caller owns the SQL transaction and the tree read or write fence.
func (s *SQLStore) placeholderForFile(ctx context.Context, tx treeQuery, id string, target Entry) (Record, Entry, Facts, PlaceholderTransition, error) {
	var empty PlaceholderTransition
	r, ghost, err := s.recordByID(ctx, tx, id)
	if err != nil || ghost.Kind != "directory" || ghost.ParentID != target.ParentID || ghost.Name != target.Name || ghost.ObjectID == target.ObjectID || target.Kind == "directory" {
		return Record{}, Entry{}, Facts{}, empty, ErrConflict
	}
	if _, err = s.listingAncestorAnchor(ctx, tx, ghost.ParentID, true); err != nil {
		return Record{}, Entry{}, Facts{}, empty, err
	}
	facts, revision, err := s.factsFor(ctx, tx, ghost, r.ObjectIndex)
	if err != nil || !facts.InternalPlaceholder || facts.Visibility == nil || facts.Visibility.Hidden != 1 {
		return Record{}, Entry{}, Facts{}, empty, ErrConflict
	}
	nameID, err := EncryptionID(r)
	if err != nil {
		return Record{}, Entry{}, Facts{}, empty, ErrInvalid
	}
	var factsID string
	if tx.QueryRowContext(ctx, `SELECT encryption_id FROM sealed_tree_facts WHERE object_index=?`, r.ObjectIndex).Scan(&factsID) != nil || !hexID(factsID) {
		return Record{}, Entry{}, Facts{}, empty, ErrInvalid
	}
	parentIndex, err := s.tree.ParentIndex(ghost.ObjectID)
	if err != nil {
		return Record{}, Entry{}, Facts{}, empty, ErrInvalid
	}
	var n int
	if tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM sealed_tree_records WHERE parent_index=?)+(SELECT COUNT(*) FROM sealed_tree_pending_files WHERE parent_index=?)`, parentIndex, parentIndex).Scan(&n) != nil || n != 0 {
		return Record{}, Entry{}, Facts{}, empty, ErrConflict
	}
	for _, class := range []int{listingHidden, listingVisibleGroup, listingInternal} {
		group := s.listingClassGroup(ghost.ObjectID, class)
		count, _, e := s.listingSummary(ctx, tx, group)
		if e != nil || count != 0 || tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_listing WHERE group_tag=?`, group).Scan(&n) != nil || n != 1 {
			return Record{}, Entry{}, Facts{}, empty, ErrInvalid
		}
	}
	return r, ghost, facts, PlaceholderTransition{ObjectID: id, NameEncryptionID: nameID, FactsEncryptionID: factsID, NameRevision: r.Revision, FactsRevision: revision}, nil
}

func (s *SQLStore) validatePendingPlaceholder(ctx context.Context, tx treeQuery, entry Entry, facts Facts) (Record, Entry, error) {
	if facts.PendingPlaceholder == nil {
		return Record{}, Entry{}, ErrInvalid
	}
	r, ghost, old, actual, err := s.placeholderForFile(ctx, tx, facts.PendingPlaceholder.ObjectID, entry)
	if err != nil || actual != *facts.PendingPlaceholder || !reflect.DeepEqual(old.Visibility, facts.Visibility) {
		return Record{}, Entry{}, ErrConflict
	}
	return r, ghost, nil
}

// PrepareFileForHiddenRuleWithFreshLocators converts an orphan rule to an
// authenticated pending file while leaving the old rule intact. No bytes are
// visible or authorized. Source identity, quota and owner publication remain
// independent gates; this method is not registered in a product route.
func (s *SQLStore) PrepareFileForHiddenRuleWithFreshLocators(ctx context.Context, placeholderID string, entry Entry, placement Placement, facts Facts) (PreparedFile, error) {
	if !s.valid() || ctx == nil || !hexID(placeholderID) || placement.BlobID != "" || placement.ReadAlias != "" || facts.PendingPlaceholder != nil || facts.Revocation != nil || !factsCompatible(entry, facts) {
		return PreparedFile{}, ErrInvalid
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		return PreparedFile{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		lease.Release()
		return PreparedFile{}, err
	}
	if err = s.verifyRoot(ctx, tx); err != nil {
		tx.Rollback()
		lease.Release()
		return PreparedFile{}, err
	}
	_, _, old, marker, err := s.placeholderForFile(ctx, tx, placeholderID, entry)
	if err == nil && facts.Visibility != nil && !reflect.DeepEqual(facts.Visibility, old.Visibility) {
		err = ErrConflict
	}
	if err == nil {
		err = tx.Commit()
	} else {
		tx.Rollback()
	}
	if err == nil {
		err = lease.Check(ctx)
	}
	lease.Release()
	if err != nil {
		return PreparedFile{}, err
	}
	facts.Visibility, facts.PendingPlaceholder = old.Visibility, &marker
	blob, err := NewBlobID()
	if err != nil {
		return PreparedFile{}, err
	}
	alias, err := NewBlobID()
	if err != nil {
		return PreparedFile{}, err
	}
	placement.BlobID, placement.ReadAlias = blob, alias
	op, err := s.prepareFile(ctx, entry, placement, &facts)
	if err != nil {
		return PreparedFile{}, err
	}
	return PreparedFile{OperationID: op, BlobID: blob, ReadAlias: alias}, nil
}

func (s *SQLStore) removePendingPlaceholder(ctx context.Context, tx treeQuery, entry Entry, facts Facts) error {
	record, ghost, err := s.validatePendingPlaceholder(ctx, tx, entry, facts)
	if err != nil {
		return err
	}
	if err = s.listingRemove(ctx, tx, ghost, record, listingInternal); err != nil {
		return err
	}
	for _, class := range []int{listingHidden, listingVisibleGroup, listingInternal} {
		group := s.listingClassGroup(ghost.ObjectID, class)
		key := s.listingKey(group, listingSentinel)
		result, e := tx.ExecContext(ctx, `DELETE FROM sealed_tree_listing WHERE index_key=? AND group_tag=? AND lookup_tag=?`, key, group, listingSentinel)
		if e != nil {
			return ErrConflict
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			return ErrConflict
		}
	}
	marker := facts.PendingPlaceholder
	result, err := tx.ExecContext(ctx, `DELETE FROM sealed_tree_facts WHERE object_index=? AND revision=? AND encryption_id=?`, record.ObjectIndex, marker.FactsRevision, marker.FactsEncryptionID)
	if err != nil {
		return ErrConflict
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return ErrConflict
	}
	result, err = tx.ExecContext(ctx, `DELETE FROM sealed_tree_records WHERE object_index=? AND revision=? AND encryption_id=?`, record.ObjectIndex, marker.NameRevision, marker.NameEncryptionID)
	if err != nil {
		return ErrConflict
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return ErrConflict
	}
	return nil
}
