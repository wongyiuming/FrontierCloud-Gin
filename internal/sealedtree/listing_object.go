package sealedtree

import (
	"context"
	"database/sql"
)

// ListingObject is deliberately distinct from a visible object used in the
// media-read pipeline; it conveys metadata only, not a resource grant.
type ListingObject VisibleObject

// ReadListingObjectWithLease is a Master-only metadata comparison primitive
// for catalog display, including the explicit include-hidden scope. It is not
// a capability or authorization to read media or lyrics; its path, facts and
// placement contain sensitive state and must not be passed to a resource node
// or exposed wholesale to a client. The caller owns the shared lease until the
// separate catalog admission commits. Pending revocations always fail closed.
func (s *SQLStore) ReadListingObjectWithLease(ctx context.Context, lease *TreeLease, objectID string, includeHidden bool) (ListingObject, error) {
	if !s.valid() || ctx == nil || lease == nil || !hexID(objectID) || objectID == s.rootID {
		return ListingObject{}, ErrInvalid
	}
	return s.readListingObject(ctx, lease, objectID, "", includeHidden)
}

// ReadListingObjectByAliasWithLease authenticates the same metadata starting
// from the exact keyed read alias. Callers supply their own access admission.
func (s *SQLStore) ReadListingObjectByAliasWithLease(ctx context.Context, lease *TreeLease, alias string, includeHidden bool) (ListingObject, error) {
	if !s.valid() || ctx == nil || lease == nil || !hexID(alias) {
		return ListingObject{}, ErrInvalid
	}
	return s.readListingObject(ctx, lease, "", alias, includeHidden)
}

func (s *SQLStore) readListingObject(ctx context.Context, lease *TreeLease, objectID, alias string, includeHidden bool) (ListingObject, error) {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return ListingObject{}, ErrFenceRequired
	}
	if err := lease.checkLocked(ctx); err != nil {
		return ListingObject{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return ListingObject{}, err
	}
	defer tx.Rollback()
	if err = s.verifyRoot(ctx, tx); err != nil {
		return ListingObject{}, err
	}
	if err = s.requireListingReady(ctx, tx); err != nil {
		return ListingObject{}, err
	}
	var r Record
	var entry Entry
	if alias != "" {
		r, entry, err = s.recordByAlias(ctx, tx, alias)
	} else {
		r, entry, err = s.recordByID(ctx, tx, objectID)
	}
	if err != nil || entry.Kind == "directory" {
		return ListingObject{}, ErrInvalid
	}
	if _, err = s.listingAncestorAnchor(ctx, tx, entry.ParentID, includeHidden); err != nil {
		return ListingObject{}, err
	}
	facts, factsRevision, err := s.factsFor(ctx, tx, entry, r.ObjectIndex)
	if err != nil || facts.Revocation != nil || facts.S3Deletion != nil || facts.InternalPlaceholder || facts.PendingSelectedUpload != nil || facts.PendingPlaceholder != nil {
		return ListingObject{}, ErrInvalid
	}
	var pending int
	if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_revocations WHERE object_index=?`, r.ObjectIndex).Scan(&pending) != nil || pending != 0 {
		return ListingObject{}, ErrInvalid
	}
	if !includeHidden && !listingVisible(&facts) {
		return ListingObject{}, ErrHidden
	}
	placement, err := s.placementFor(ctx, tx, entry, r.ObjectIndex)
	if err != nil || alias != "" && placement.ReadAlias != alias {
		return ListingObject{}, ErrInvalid
	}
	var placementRevision int64
	if tx.QueryRowContext(ctx, `SELECT revision FROM sealed_tree_placements WHERE object_index=?`, r.ObjectIndex).Scan(&placementRevision) != nil || placementRevision < 1 {
		return ListingObject{}, ErrInvalid
	}
	if err = tx.Commit(); err != nil {
		return ListingObject{}, err
	}
	path, err := s.resolvePath(ctx, entry.ObjectID, false)
	if err != nil {
		return ListingObject{}, err
	}
	if err = lease.checkLocked(ctx); err != nil {
		return ListingObject{}, err
	}
	return ListingObject{Path: path, Entry: entry, EntryRevision: r.Revision, Facts: facts, FactsRevision: factsRevision, Placement: placement, PlacementRevision: placementRevision}, nil
}
