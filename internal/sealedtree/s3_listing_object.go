package sealedtree

import (
	"context"
	"crypto/hmac"
	"database/sql"
)

// S3ListingObject contains sensitive Master-only metadata and is never an S3
// read grant. In particular its provider key must not be exposed wholesale.
type S3ListingObject struct {
	Path              string
	Entry             Entry
	EntryRevision     int64
	Facts             Facts
	FactsRevision     int64
	Placement         S3Placement
	PlacementRevision int64
}

// ReadS3ListingObjectWithLease verifies one S3 metadata snapshot under the
// same tree fence as its ancestors. It does not authenticate current member
// credentials, provider state, object availability, or a user's access.
// Those checks and admission must hold their own correctly ordered leases.
func (s *SQLStore) ReadS3ListingObjectWithLease(ctx context.Context, lease *TreeLease, objectID string, includeHidden bool) (S3ListingObject, error) {
	var empty S3ListingObject
	if !s.valid() || ctx == nil || lease == nil || !hexID(objectID) || objectID == s.rootID {
		return empty, ErrInvalid
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return empty, ErrFenceRequired
	}
	if err := lease.checkLocked(ctx); err != nil {
		return empty, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err = s.verifyRoot(ctx, tx); err != nil {
		return empty, err
	}
	if err = s.requireListingReady(ctx, tx); err != nil {
		return empty, err
	}
	r, entry, err := s.recordByID(ctx, tx, objectID)
	if err != nil || entry.Kind == "directory" {
		return empty, ErrInvalid
	}
	if _, err = s.listingAncestorAnchor(ctx, tx, entry.ParentID, includeHidden); err != nil {
		return empty, err
	}
	facts, factsRevision, err := s.factsFor(ctx, tx, entry, r.ObjectIndex)
	if err != nil || facts.Revocation != nil || facts.S3Deletion != nil || facts.InternalPlaceholder {
		return empty, ErrInvalid
	}
	var pending int
	if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_revocations WHERE object_index=?`, r.ObjectIndex).Scan(&pending) != nil || pending != 0 {
		return empty, ErrInvalid
	}
	if !includeHidden && !listingVisible(&facts) {
		return empty, ErrHidden
	}
	var slot, id string
	var revision int64
	var sealed []byte
	if err = tx.QueryRowContext(ctx, `SELECT blob_index,revision,encryption_id,sealed FROM sealed_tree_placements WHERE object_index=?`, r.ObjectIndex).Scan(&slot, &revision, &id, &sealed); err != nil {
		return empty, ErrInvalid
	}
	record := S3PlacementRecord{ObjectIndex: r.ObjectIndex, Revision: revision, Sealed: sealed}
	actual, err := S3PlacementEncryptionID(record)
	if err != nil || !hmac.Equal([]byte(id), []byte(actual)) {
		return empty, ErrInvalid
	}
	placement, err := s.openIndexedS3Placement(ctx, tx, objectID, slot, r.ObjectIndex, revision, sealed)
	if err != nil {
		return empty, ErrInvalid
	}
	var reserved, blob, aliases int
	if tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM sealed_tree_encryption_ids WHERE encryption_id=?),(SELECT COUNT(*) FROM sealed_tree_blob_ids WHERE blob_index=?),(SELECT COUNT(*) FROM sealed_tree_aliases WHERE object_index=?)`, id, slot, r.ObjectIndex).Scan(&reserved, &blob, &aliases) != nil || reserved != 1 || blob != 1 || aliases != 0 {
		return empty, ErrInvalid
	}
	path, err := s.pathInTransaction(ctx, tx, entry)
	if err != nil {
		return empty, err
	}
	if err = tx.Commit(); err != nil {
		return empty, err
	}
	if err = lease.checkLocked(ctx); err != nil {
		return empty, err
	}
	return S3ListingObject{Path: path, Entry: entry, EntryRevision: r.Revision, Facts: facts, FactsRevision: factsRevision, Placement: placement, PlacementRevision: revision}, nil
}
