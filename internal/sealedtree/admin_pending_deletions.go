package sealedtree

import (
	"context"
	"crypto/hmac"
	"database/sql"
)

// ListAdminPendingDeletionsWithLease reads the internal listing group for one
// authenticated directory. Only committed exact deletions are returned.
// Hidden upload placeholders remain internal. This metadata grants no bytes
// or mutation authority and must only be projected by authenticated Admin UI.
func (s *SQLStore) ListAdminPendingDeletionsWithLease(ctx context.Context, lease *TreeLease, parent, after string, limit int) ([]CatalogItem, string, error) {
	if !s.valid() || ctx == nil || lease == nil || !hexID(parent) || limit < 1 || limit > 256 || len(after) > 512 {
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
	if err = s.verifyRoot(ctx, tx); err != nil {
		return nil, "", err
	}
	if err = s.requireListingReady(ctx, tx); err != nil {
		return nil, "", err
	}
	anchor, err := s.listingAncestorAnchor(ctx, tx, parent, true)
	if err != nil {
		return nil, "", err
	}
	group, scope := s.listingClassGroup(parent, listingInternal), s.listingMAC("admin-pending-delete", parent)
	count, revision, err := s.listingSummary(ctx, tx, group)
	if err != nil {
		return nil, "", err
	}
	var total, entries int64
	if tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(CASE WHEN entry_count=-1 THEN 1 ELSE 0 END),0) FROM sealed_tree_listing WHERE group_tag=?`, group).Scan(&total, &entries) != nil || total != count+1 || entries != count {
		return nil, "", ErrInvalid
	}
	cursor := listingSentinel
	if after != "" {
		cursor, err = s.openListingCursor(after, scope, revision, anchor)
		if err != nil {
			return nil, "", err
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT index_key,group_tag,lookup_tag,object_index,entry_count,group_revision,mac FROM sealed_tree_listing WHERE group_tag=? AND lookup_tag>? AND entry_count=-1 ORDER BY lookup_tag LIMIT ?`, group, cursor, limit+1)
	if err != nil {
		return nil, "", err
	}
	page := make([]listingPageRow, 0, limit+1)
	last := cursor
	for rows.Next() {
		var row listingPageRow
		if rows.Scan(&row.key, &row.group, &row.lookup, &row.object, &row.count, &row.revision, &row.mac) != nil || row.group != group || !hexID(row.lookup) || row.lookup <= last || !hexID(row.object) || row.count != -1 || row.revision != 0 || row.key != s.listingKey(group, row.lookup) || !hmac.Equal([]byte(row.mac), []byte(s.listingRowMAC(group, row.lookup, row.object, -1, 0))) {
			rows.Close()
			return nil, "", ErrInvalid
		}
		last = row.lookup
		page = append(page, row)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil || closeErr != nil {
		return nil, "", ErrInvalid
	}
	next := ""
	if len(page) > limit {
		page = page[:limit]
		next, err = s.sealListingCursor(scope, page[len(page)-1].lookup, revision, anchor)
		if err != nil {
			return nil, "", err
		}
	}
	items := make([]CatalogItem, 0, len(page))
	for _, row := range page {
		item, present, err := s.adminPendingDeletion(ctx, tx, parent, row)
		if err != nil {
			return nil, "", err
		}
		if present {
			items = append(items, item)
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, "", err
	}
	if err = lease.checkLocked(ctx); err != nil {
		return nil, "", err
	}
	return items, next, nil
}

func (s *SQLStore) adminPendingDeletion(ctx context.Context, tx treeQuery, parent string, row listingPageRow) (CatalogItem, bool, error) {
	var empty CatalogItem
	record, err := scanRecord(tx.QueryRowContext(ctx, `SELECT object_index,parent_index,lookup_tag,revision,encryption_id,sealed FROM sealed_tree_records WHERE object_index=?`, row.object))
	if err != nil || record.Lookup != row.lookup || verifyNameReservation(ctx, tx, record) != nil {
		return empty, false, ErrInvalid
	}
	entry, err := s.tree.Open(parent, record)
	if err != nil {
		return empty, false, err
	}
	facts, revision, err := s.factsFor(ctx, tx, entry, record.ObjectIndex)
	if err != nil || listingClass(&facts) != listingInternal {
		return empty, false, ErrInvalid
	}
	if facts.InternalPlaceholder {
		return empty, false, nil
	}
	item := CatalogItem{Entry: entry, EntryRevision: record.Revision, Facts: facts, FactsRevision: revision}
	if entry.Kind == "directory" {
		if _, err = s.verifyDirectoryDeleteIntent(ctx, tx, entry, record, facts); err != nil {
			return empty, false, err
		}
		return item, true, nil
	}
	name, err := s.pathInTransaction(ctx, tx, entry)
	if err != nil || selectedMediaDeletionKind(name) != entry.Kind {
		return empty, false, ErrInvalid
	}
	if intent := facts.S3Deletion; intent != nil {
		placement, id, err := s.s3DeletionPlacement(ctx, tx, record, entry)
		if err != nil || s.verifyS3MediaDeletion(ctx, tx, record, intent, placement, id) != nil {
			return empty, false, ErrInvalid
		}
		item.S3Placement = &placement
		return item, true, nil
	}
	intent := facts.Revocation
	if intent == nil || !intent.SelectedDelete || intent.Action != "delete" || entry.Kind == "lyric" && !intent.LocalDelete {
		return empty, false, ErrInvalid
	}
	op := s.followerMediaDeleteOperation(entry.ObjectID, name)
	if intent.LocalDelete {
		op = s.masterLocalMediaDeleteOperation(entry.ObjectID, name)
	}
	placement, err := s.placementFor(ctx, tx, entry, record.ObjectIndex)
	if err != nil || placement.State != "active" || placement.Encryption == nil || intent.OperationID != op || s.verifyRevocation(ctx, tx, intent, placement) != nil {
		return empty, false, ErrInvalid
	}
	item.Placement = &placement
	return item, true, nil
}
