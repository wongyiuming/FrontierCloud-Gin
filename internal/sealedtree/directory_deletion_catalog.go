package sealedtree

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"errors"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type directoryDeleteChild struct {
	entry    Entry
	record   Record
	facts    Facts
	revision int64
	path     string
}

var errDirectoryDeleteLeafPending = errors.New("directory deletion still has a leaf")

func (s *SQLStore) verifyDirectoryDeleteListing(ctx context.Context, tx treeQuery, entry Entry, record Record, facts Facts) error {
	group := s.listingClassGroup(entry.ParentID, listingClass(&facts))
	key := s.listingKey(group, record.Lookup)
	var object, mac string
	var count, revision int64
	if tx.QueryRowContext(ctx, `SELECT object_index,entry_count,group_revision,mac FROM sealed_tree_listing WHERE index_key=? AND group_tag=? AND lookup_tag=?`, key, group, record.Lookup).Scan(&object, &count, &revision, &mac) != nil ||
		object != record.ObjectIndex || count != -1 || revision != 0 || !hmac.Equal([]byte(mac), []byte(s.listingRowMAC(group, record.Lookup, object, -1, 0))) {
		return ErrInvalid
	}
	return nil
}

func (s *SQLStore) directoryDeleteChildCount(ctx context.Context, tx treeQuery, parent string, limit int) (int, error) {
	parentIndex, err := s.tree.ParentIndex(parent)
	if err != nil {
		return 0, err
	}
	var pending int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM sealed_tree_pending_files WHERE parent_index=? LIMIT 1`, parentIndex).Scan(&pending)
	if err == nil {
		return 0, ErrDirectoryDeleteUploadPending
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	count := 0
	for _, class := range []int{listingVisibleGroup, listingHidden, listingInternal} {
		group := s.listingClassGroup(parent, class)
		n, _, err := s.listingSummary(ctx, tx, group)
		if err != nil {
			return 0, err
		}
		if n > int64(limit-count) {
			return 0, ErrDirectoryDeleteLimit
		}
		var actual int64
		if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT 1 FROM sealed_tree_listing WHERE group_tag=? LIMIT ?)`, group, n+2).Scan(&actual) != nil || actual != n+1 {
			return 0, ErrInvalid
		}
		count += int(n)
	}
	var actual int
	if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT 1 FROM sealed_tree_records WHERE parent_index=? LIMIT ?)`, parentIndex, count+1).Scan(&actual) != nil || actual != count {
		return 0, ErrInvalid
	}
	return count, nil
}

func (s *SQLStore) directoryDeleteChildPage(ctx context.Context, tx treeQuery, parent, after string, limit int) ([]Record, error) {
	parentIndex, err := s.tree.ParentIndex(parent)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT object_index,parent_index,lookup_tag,revision,encryption_id,sealed FROM sealed_tree_records WHERE parent_index=? AND lookup_tag>? ORDER BY lookup_tag LIMIT ?`, parentIndex, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	page := make([]Record, 0, limit)
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil || r.ParentIndex != parentIndex || r.Lookup <= after || !hexID(r.Lookup) {
			return nil, ErrInvalid
		}
		page = append(page, r)
		after = r.Lookup
	}
	return page, rows.Err()
}

// walkDirectoryDelete authenticates all three listing classes and raw child
// rows, including hidden folders and import-only placeholders. The public
// catalog deliberately excludes some of those rows and cannot prove empty.
func (s *SQLStore) walkDirectoryDelete(ctx context.Context, tx treeQuery, root directoryDeleteChild, finalizing bool, visit func(directoryDeleteChild) error) ([]directoryDeleteChild, error) {
	remaining := directoryDeleteEntriesLimit - 1
	var directories []directoryDeleteChild
	var walk func(directoryDeleteChild) error
	walk = func(dir directoryDeleteChild) error {
		if !validDirectoryDeleteTarget(store.SelectedMediaDeleteTarget{Path: dir.path, ResourceID: dir.entry.ObjectID, Directory: true}) {
			return ErrConflict
		}
		count, err := s.directoryDeleteChildCount(ctx, tx, dir.entry.ObjectID, remaining)
		if err != nil {
			return err
		}
		remaining -= count
		cursor := ""
		for count > 0 {
			page, err := s.directoryDeleteChildPage(ctx, tx, dir.entry.ObjectID, cursor, min(count, 64))
			if err != nil || len(page) == 0 {
				return ErrInvalid
			}
			for _, record := range page {
				if err = ctx.Err(); err != nil {
					return err
				}
				entry, err := s.tree.Open(dir.entry.ObjectID, record)
				if err != nil || verifyNameReservation(ctx, tx, record) != nil {
					return ErrInvalid
				}
				facts, revision, err := s.factsFor(ctx, tx, entry, record.ObjectIndex)
				if err != nil || facts.DirectoryDeletion != nil || s.verifyDirectoryDeleteListing(ctx, tx, entry, record, facts) != nil {
					return ErrConflict
				}
				child := directoryDeleteChild{entry: entry, record: record, facts: facts, revision: revision, path: dir.path + "/" + entry.Name}
				if entry.Kind == "directory" {
					if err = walk(child); err != nil {
						return err
					}
					continue
				}
				if selectedMediaDeletionKind(child.path) != entry.Kind {
					return ErrConflict
				}
				if finalizing {
					if err = s.verifyDirectoryLeafIntent(ctx, tx, child); err != nil {
						return err
					}
					return errDirectoryDeleteLeafPending
				}
				if facts.Revocation != nil || facts.S3Deletion != nil {
					return ErrRevocationPending
				}
				if err = visit(child); err != nil {
					return err
				}
			}
			count -= len(page)
			cursor = page[len(page)-1].Lookup
		}
		directories = append(directories, dir)
		return nil
	}
	if err := walk(root); err != nil {
		return nil, err
	}
	return directories, nil
}

func (s *SQLStore) verifyQueuedDirectoryLeaf(ctx context.Context, tx treeQuery, target store.SelectedMediaDeleteTarget) error {
	entry, index, err := s.pathEntryTx(ctx, tx, target.Path)
	if err != nil || entry.ObjectID != target.ResourceID || selectedMediaDeletionKind(target.Path) != entry.Kind {
		return ErrConflict
	}
	r, matched, err := s.recordByID(ctx, tx, entry.ObjectID)
	if err != nil || matched != entry || r.ObjectIndex != index {
		return ErrConflict
	}
	facts, revision, err := s.factsFor(ctx, tx, entry, index)
	if err != nil || s.verifyDirectoryDeleteListing(ctx, tx, entry, r, facts) != nil {
		return ErrConflict
	}
	return s.verifyDirectoryLeafIntent(ctx, tx, directoryDeleteChild{entry: entry, record: r, facts: facts, revision: revision, path: target.Path})
}

func (s *SQLStore) verifyDirectoryLeafIntent(ctx context.Context, tx treeQuery, leaf directoryDeleteChild) error {
	if intent := leaf.facts.S3Deletion; intent != nil {
		placement, id, err := s.s3DeletionPlacement(ctx, tx, leaf.record, leaf.entry)
		if err != nil || s.verifyS3MediaDeletion(ctx, tx, leaf.record, intent, placement, id) != nil {
			return ErrConflict
		}
		return nil
	}
	intent := leaf.facts.Revocation
	if intent == nil || !intent.SelectedDelete || intent.Action != "delete" {
		return ErrConflict
	}
	operation := s.followerMediaDeleteOperation(leaf.entry.ObjectID, leaf.path)
	if intent.LocalDelete {
		operation = s.masterLocalMediaDeleteOperation(leaf.entry.ObjectID, leaf.path)
	}
	placement, err := s.placementFor(ctx, tx, leaf.entry, leaf.record.ObjectIndex)
	if err != nil || intent.OperationID != operation || s.verifyRevocation(ctx, tx, intent, placement) != nil {
		return ErrConflict
	}
	return nil
}

// FinalizeDirectoryDeletionTx removes metadata only after all descendant
// leaf workers have settled their physical deletions and refunded quota.
func (m *CoordinatedMutation) FinalizeDirectoryDeletionTx(ctx context.Context, tx treeQuery, item store.SelectedMediaDeleteItem) (done, changed bool, err error) {
	if m == nil || ctx == nil || tx == nil || !validDirectoryDeleteTarget(item.SelectedMediaDeleteTarget) || item.State != store.SelectedMediaDeletePending {
		return false, false, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.store
	if !m.active || !s.valid() || item.OperationID != s.directoryDeleteOperation(item.SelectedMediaDeleteTarget) {
		return false, false, ErrFenceRequired
	}
	if err := s.verifyRoot(ctx, tx); err != nil {
		return false, false, err
	}
	if done, err := s.directoryDeleteCompleted(ctx, tx, item.SelectedMediaDeleteTarget, item.OperationID); err != nil || done {
		return done, false, err
	}
	root, err := s.directoryDeleteRoot(ctx, tx, item.SelectedMediaDeleteTarget)
	if err != nil {
		return false, false, err
	}
	if _, err = s.verifyDirectoryDeleteIntent(ctx, tx, root.entry, root.record, root.facts); err != nil {
		return false, false, err
	}
	dirs, err := s.walkDirectoryDelete(ctx, tx, root, true, nil)
	if errors.Is(err, errDirectoryDeleteLeafPending) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if err = s.lockIndexedWriter(ctx, tx); err != nil {
		return false, false, err
	}
	for _, dir := range dirs {
		if err = s.removeEmptyDirectoryDeleteTx(ctx, tx, dir); err != nil {
			return false, false, err
		}
	}
	marker := s.listingMAC("directory-delete-complete-v1", item.ResourceID, item.OperationID)
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_blob_ids(blob_index) VALUES(?)`, marker); err != nil {
		return false, false, err
	}
	return true, true, nil
}

func (s *SQLStore) removeEmptyDirectoryDeleteTx(ctx context.Context, tx treeQuery, dir directoryDeleteChild) error {
	if count, err := s.directoryDeleteChildCount(ctx, tx, dir.entry.ObjectID, 0); err != nil || count != 0 {
		return ErrConflict
	}
	var physical, pending int
	index := dir.record.ObjectIndex
	if tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM sealed_tree_placements WHERE object_index=?)+(SELECT COUNT(*) FROM sealed_tree_aliases WHERE object_index=?),
		(SELECT COUNT(*) FROM sealed_tree_revocations WHERE object_index=?)`, index, index, index).Scan(&physical, &pending) != nil ||
		physical != 0 || (dir.facts.DirectoryDeletion == nil && pending != 0) || (dir.facts.DirectoryDeletion != nil && pending != 1) {
		return ErrConflict
	}
	if dir.facts.DirectoryDeletion != nil {
		op := dir.facts.DirectoryDeletion.OperationID
		if err := deleteExactlyOne(ctx, tx, `DELETE FROM sealed_tree_revocations WHERE operation_index=? AND object_index=?`, s.directoryDeleteIndex(index, op), index); err != nil {
			return err
		}
	}
	if err := s.listingRemove(ctx, tx, dir.entry, dir.record, listingClass(&dir.facts)); err != nil {
		return err
	}
	for _, class := range []int{listingVisibleGroup, listingHidden, listingInternal} {
		group := s.listingClassGroup(dir.entry.ObjectID, class)
		if err := deleteExactlyOne(ctx, tx, `DELETE FROM sealed_tree_listing WHERE index_key=? AND group_tag=? AND entry_count=0`, s.listingKey(group, listingSentinel), group); err != nil {
			return err
		}
	}
	if err := deleteExactlyOne(ctx, tx, `DELETE FROM sealed_tree_facts WHERE object_index=? AND revision=?`, index, dir.revision); err != nil {
		return err
	}
	return deleteExactlyOne(ctx, tx, `DELETE FROM sealed_tree_records WHERE object_index=? AND revision=?`, index, dir.record.Revision)
}
