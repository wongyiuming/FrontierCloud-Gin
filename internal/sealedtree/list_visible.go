package sealedtree

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"errors"
)

// ListVisibleWithLease queries a keyed visible-only index under a shared tree
// fence. The encrypted cursor is scoped to the visible group revision and the
// authenticated ancestor chain; unrelated directory mutations do not stale it.
// Every returned row and the authenticated group
// count are checked before returning. The caller separately authorizes the
// user and must keep the lease until response/admission commit. Current count
// verification scans that group's index; large-directory one-core performance
// and all mutation/rebuild/recovery paths remain deployment gates.
func (s *SQLStore) ListVisibleWithLease(ctx context.Context, lease *TreeLease, parentID, after string, limit int) ([]Entry, string, error) {
	return s.ListDirectoryWithLease(ctx, lease, parentID, after, limit, false)
}

// ListDirectoryWithLease additionally supports the existing explicit
// include-hidden catalog scope. It is not an object-read authorization. The
// caller must choose the scope from the validated product request and retain
// the lease through admission. Pending revocations remain fail-closed.
func (s *SQLStore) ListDirectoryWithLease(ctx context.Context, lease *TreeLease, parentID, after string, limit int, includeHidden bool) ([]Entry, string, error) {
	items, next, err := s.ListCatalogPageWithLease(ctx, lease, parentID, after, limit, includeHidden)
	if err != nil {
		return nil, "", err
	}
	entries := make([]Entry, 0, len(items))
	for _, item := range items {
		entries = append(entries, item.Entry)
	}
	return entries, next, nil
}

// ListCatalogPageWithLease returns authenticated Master-only tree metadata in
// bounded pages; callers must not serialize placements or treat this as a byte
// grant. Native file placements are required; S3 is not yet implemented.
func (s *SQLStore) ListCatalogPageWithLease(ctx context.Context, lease *TreeLease, parentID, after string, limit int, includeHidden bool) ([]CatalogItem, string, error) {
	if !s.valid() || ctx == nil || lease == nil || !hexID(parentID) || limit < 1 || limit > 256 || len(after) > 512 {
		return nil, "", ErrInvalid
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return nil, "", ErrFenceRequired
	}
	if err := lease.checkLocked(ctx); err != nil {
		return nil, "", err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	decoded, next, err := s.listCatalogPageTx(ctx, tx, parentID, after, limit, includeHidden)
	if err != nil {
		return nil, "", err
	}
	if err = tx.Commit(); err != nil {
		return nil, "", err
	}
	if err = lease.checkLocked(ctx); err != nil {
		return nil, "", err
	}
	return decoded, next, nil
}

func (s *SQLStore) listCatalogPageTx(ctx context.Context, tx treeQuery, parentID, after string, limit int, includeHidden bool) ([]CatalogItem, string, error) {
	if err := s.verifyRoot(ctx, tx); err != nil {
		return nil, "", err
	}
	if err := s.requireListingReady(ctx, tx); err != nil {
		return nil, "", err
	}
	state, err := s.catalogScope(ctx, tx, parentID, includeHidden)
	if err != nil {
		return nil, "", err
	}
	cursor := listingSentinel
	if after != "" {
		cursor, err = s.openListingCursor(after, state.scope, state.revision, state.anchor)
		if err != nil {
			return nil, "", err
		}
	}
	for i, group := range state.groups {
		var all, entries int64
		if tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(CASE WHEN entry_count=-1 THEN 1 ELSE 0 END),0) FROM sealed_tree_listing WHERE group_tag=?`, group).Scan(&all, &entries) != nil || all != state.counts[i]+1 || entries != state.counts[i] {
			return nil, "", ErrInvalid
		}
	}
	var rows *sql.Rows
	if includeHidden {
		rows, err = tx.QueryContext(ctx, `SELECT index_key,group_tag,lookup_tag,object_index,entry_count,group_revision,mac FROM sealed_tree_listing WHERE group_tag IN (?,?) AND lookup_tag>? AND entry_count=-1 ORDER BY lookup_tag LIMIT ?`, state.visibleGroup, state.hiddenGroup, cursor, limit+1)
	} else {
		rows, err = tx.QueryContext(ctx, `SELECT index_key,group_tag,lookup_tag,object_index,entry_count,group_revision,mac FROM sealed_tree_listing WHERE group_tag=? AND lookup_tag>? AND entry_count=-1 ORDER BY lookup_tag LIMIT ?`, state.visibleGroup, cursor, limit+1)
	}
	if err != nil {
		return nil, "", ErrInvalid
	}
	indexed := make([]listingPageRow, 0, limit+1)
	last := cursor
	for rows.Next() {
		var x listingPageRow
		if rows.Scan(&x.key, &x.group, &x.lookup, &x.object, &x.count, &x.revision, &x.mac) != nil || (x.group != state.visibleGroup && (!includeHidden || x.group != state.hiddenGroup)) || !hexID(x.lookup) || x.lookup <= last || !hexID(x.object) || x.count != -1 || x.revision != 0 || x.key != s.listingKey(x.group, x.lookup) || !hmac.Equal([]byte(x.mac), []byte(s.listingRowMAC(x.group, x.lookup, x.object, -1, x.revision))) {
			rows.Close()
			return nil, "", ErrInvalid
		}
		last = x.lookup
		indexed = append(indexed, x)
	}
	err = rows.Err()
	closeErr := rows.Close()
	if err != nil || closeErr != nil {
		return nil, "", ErrInvalid
	}
	decoded, err := s.readCatalogPage(ctx, tx, parentID, indexed, includeHidden)
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(decoded) > limit {
		next, err = s.sealListingCursor(state.scope, indexed[limit-1].lookup, state.revision, state.anchor)
		if err != nil {
			return nil, "", err
		}
		decoded = decoded[:limit]
	}
	return decoded, next, nil
}

func (s *SQLStore) visibleListEntry(ctx context.Context, tx treeQuery, parentID string, r Record) (Entry, bool, error) {
	entry, e := s.tree.Open(parentID, r)
	if e != nil {
		return Entry{}, false, ErrInvalid
	}
	facts, _, e := s.factsFor(ctx, tx, entry, r.ObjectIndex)
	if e != nil {
		return Entry{}, false, ErrInvalid
	}
	if facts.InternalPlaceholder {
		return Entry{}, false, ErrInvalid
	}
	var present int
	e = tx.QueryRowContext(ctx, `SELECT 1 FROM sealed_tree_revocations WHERE object_index=? LIMIT 1`, r.ObjectIndex).Scan(&present)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return Entry{}, false, ErrInvalid
	}
	if (e == nil) != (facts.Revocation != nil || facts.S3Deletion != nil || facts.DirectoryDeletion != nil) {
		return Entry{}, false, ErrInvalid
	}
	if facts.Revocation != nil || facts.S3Deletion != nil || facts.DirectoryDeletion != nil {
		return Entry{}, false, ErrRevocationPending
	}
	return entry, listingVisible(&facts), nil
}
