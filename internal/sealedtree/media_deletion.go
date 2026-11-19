package sealedtree

import (
	"context"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// deletedFileRecordedTx uses the existing permanent ID reservations for a
// tree-keyed deletion marker. It stores no logical path and never makes the
// object's locators available for reuse.
func (s *SQLStore) deletedFileRecordedTx(ctx context.Context, tx treeQuery, objectID string) (bool, error) {
	index, err := s.tree.ObjectIndex(objectID)
	if err != nil {
		return false, err
	}
	var marker, live int
	err = tx.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM sealed_tree_blob_ids WHERE blob_index=?),
		(SELECT COUNT(*) FROM sealed_tree_records WHERE object_index=?)+
		(SELECT COUNT(*) FROM sealed_tree_facts WHERE object_index=?)+
		(SELECT COUNT(*) FROM sealed_tree_placements WHERE object_index=?)+
		(SELECT COUNT(*) FROM sealed_tree_aliases WHERE object_index=?)+
		(SELECT COUNT(*) FROM sealed_tree_listing WHERE object_index=?)+
		(SELECT COUNT(*) FROM sealed_tree_pending_files WHERE object_index=?)+
		(SELECT COUNT(*) FROM sealed_tree_revocations WHERE object_index=?)`,
		s.listingMAC("file-deleted-v1", index), index, index, index, index, index, index, index).Scan(&marker, &live)
	if err != nil {
		return false, err
	}
	if marker == 1 && live != 0 {
		return false, ErrConflict
	}
	return marker == 1, nil
}

// removeDeletedFileTx is shared by coordinators after they have authenticated
// physical deletion of this exact placement. They own the transaction and
// any quota, journal and audit updates. Directories and lyrics have separate
// reference lifecycles and cannot be removed by this media primitive.
func (s *SQLStore) removeDeletedFileTx(ctx context.Context, tx treeQuery, entry Entry, record Record, facts Facts) error {
	if entry.Kind != "audio" && entry.Kind != "video" {
		return ErrInvalid
	}
	return s.removeDeletedLeafTx(ctx, tx, entry, record, facts)
}

func (s *SQLStore) removeDeletedLeafTx(ctx context.Context, tx treeQuery, entry Entry, record Record, facts Facts) error {
	if entry.Kind == "directory" || facts.ObjectID != entry.ObjectID || facts.InternalPlaceholder || facts.PendingSelectedUpload != nil {
		return ErrInvalid
	}
	if err := s.listingRemove(ctx, tx, entry, record, listingClass(&facts)); err != nil {
		return err
	}
	// The native and S3 placement readers have already validated whether
	// this placement owns exactly one alias or none.
	if _, err := tx.ExecContext(ctx, `DELETE FROM sealed_tree_aliases WHERE object_index=?`, record.ObjectIndex); err != nil {
		return err
	}
	for _, stmt := range []string{
		`DELETE FROM sealed_tree_placements WHERE object_index=?`,
		`DELETE FROM sealed_tree_facts WHERE object_index=?`,
		`DELETE FROM sealed_tree_records WHERE object_index=?`,
	} {
		if err := deleteExactlyOne(ctx, tx, stmt, record.ObjectIndex); err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO sealed_tree_blob_ids(blob_index) VALUES(?)`, s.listingMAC("file-deleted-v1", record.ObjectIndex))
	return err
}

func deleteExactlyOne(ctx context.Context, tx treeQuery, stmt string, args ...any) error {
	result, err := tx.ExecContext(ctx, stmt, args...)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return ErrConflict
	}
	return nil
}

type DeletedNativeMedia struct {
	OwnerID string
	Bytes   int64
	Already bool
}

func (s *SQLStore) nativeDeleteCompleted(ctx context.Context, tx treeQuery, objectID, operationID string) (bool, error) {
	var n int
	marker := s.listingMAC("native-delete-completed-v1", objectID, operationID)
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_blob_ids WHERE blob_index=?`, marker).Scan(&n); err != nil || n == 0 {
		return false, err
	}
	deleted, err := s.deletedFileRecordedTx(ctx, tx, objectID)
	if err != nil || !deleted {
		return false, ErrConflict
	}
	return true, nil
}

// QueueFollowerMediaDeletionTx binds an Admin selection to the exact current
// file, placement and paired Follower under the coordinator's transaction.
// Repeating a selection (including after a lost first reply) returns its
// original operation and never resolves a replacement at the same path.
func (m *CoordinatedMutation) QueueFollowerMediaDeletionTx(ctx context.Context, tx treeQuery, target store.SelectedMediaDeleteTarget) (item store.SelectedMediaDeleteItem, queued bool, err error) {
	if m == nil || ctx == nil || tx == nil || !hexID(target.ResourceID) ||
		(!strings.HasPrefix(target.Path, "music/") && !strings.HasPrefix(target.Path, "vido/")) || strings.Count(target.Path, "/") > 3 {
		return item, false, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.store
	if !m.active || !s.valid() || target.ResourceID == s.rootID {
		return item, false, ErrFenceRequired
	}
	if err := s.verifyRoot(ctx, tx); err != nil {
		return item, false, err
	}
	operation := s.followerMediaDeleteOperation(target.ResourceID, target.Path)
	if target.OperationID != "" && target.OperationID != operation {
		return item, false, ErrConflict
	}
	item = store.SelectedMediaDeleteItem{SelectedMediaDeleteTarget: target, State: store.SelectedMediaDeletePending}
	item.OperationID = operation
	if completed, err := s.nativeDeleteCompleted(ctx, tx, target.ResourceID, operation); err != nil {
		return item, false, err
	} else if completed {
		item.State = store.SelectedMediaDeleteDeleted
		return item, false, nil
	}
	entry, index, err := s.pathEntryTx(ctx, tx, target.Path)
	if err != nil || entry.ObjectID != target.ResourceID ||
		!(entry.Kind == "audio" && strings.HasPrefix(target.Path, "music/") || entry.Kind == "video" && strings.HasPrefix(target.Path, "vido/")) {
		return item, false, ErrConflict
	}
	record, matched, err := s.recordByID(ctx, tx, target.ResourceID)
	if err != nil || matched != entry || record.ObjectIndex != index {
		return item, false, ErrInvalid
	}
	placement, err := s.placementFor(ctx, tx, entry, index)
	if err != nil || placement.State != "active" || placement.Encryption == nil {
		return item, false, ErrInvalid
	}
	var master, relationship string
	if tx.QueryRowContext(ctx, "SELECT node_id FROM node_identity WHERE singleton=1 AND role='Master'").Scan(&master) != nil || placement.OwnerID == master ||
		tx.QueryRowContext(ctx, `SELECT relationship_id FROM cluster_storage_members WHERE member_id=? AND member_kind='Follower' AND used_bytes>=?`, placement.OwnerID, placement.Bytes).Scan(&relationship) != nil {
		return item, false, ErrConflict
	}
	facts, revision, err := s.factsFor(ctx, tx, entry, index)
	if err != nil {
		return item, false, err
	}
	if pending := facts.Revocation; pending != nil {
		if !pending.SelectedDelete || pending.Action != "delete" || pending.OperationID != operation ||
			pending.MasterID != master || pending.RelationshipID != relationship || s.verifyRevocation(ctx, tx, pending, placement) != nil {
			return item, false, ErrConflict
		}
		return item, false, nil
	}
	if target.OperationID != "" {
		return item, false, ErrConflict
	}
	if err := s.lockIndexedWriter(ctx, tx); err != nil {
		return item, false, err
	}
	if _, err := s.beginOpaqueRevocationTx(ctx, tx, entry, record, facts, revision, placement, master, relationship, "delete", operation); err != nil {
		return item, false, err
	}
	return item, true, nil
}

// FinalizeOpaqueMediaDeletionTx removes a native audio/video catalog object
// only after both exact owner signatures are durably recorded. The caller
// must also commit the quota refund and audit in this same SQL transaction.
// It grants no authority to contact an Owner or unlink a blob.
func (m *CoordinatedMutation) FinalizeOpaqueMediaDeletionTx(ctx context.Context, tx treeQuery, objectID, operationID string) (DeletedNativeMedia, error) {
	var out DeletedNativeMedia
	if m == nil || ctx == nil || tx == nil || !hexID(objectID) || !lowerHex(operationID, 32) {
		return out, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.store
	if !m.active || !s.valid() || objectID == s.rootID {
		return out, ErrFenceRequired
	}
	if err := s.verifyRoot(ctx, tx); err != nil {
		return out, err
	}
	if completed, err := s.nativeDeleteCompleted(ctx, tx, objectID, operationID); err != nil {
		return out, err
	} else if completed {
		return DeletedNativeMedia{Already: true}, nil
	}
	if err := s.lockIndexedWriter(ctx, tx); err != nil {
		return out, err
	}
	record, entry, err := s.recordByID(ctx, tx, objectID)
	if err != nil || (entry.Kind != "audio" && entry.Kind != "video") || s.checkDirectory(ctx, tx, entry.ParentID, entry.ObjectID) != nil {
		return out, ErrConflict
	}
	placement, err := s.placementFor(ctx, tx, entry, record.ObjectIndex)
	if err != nil || placement.State != "active" {
		return out, ErrInvalid
	}
	facts, _, err := s.factsFor(ctx, tx, entry, record.ObjectIndex)
	intent := facts.Revocation
	if err != nil || intent == nil || intent.Action != "delete" || intent.OperationID != operationID || intent.OwnerSignature == "" ||
		intent.DeletionSignature == "" || s.verifyRevocation(ctx, tx, intent, placement) != nil {
		return out, ErrConflict
	}
	pending, err := s.revocationReservation(operationID)
	if err != nil {
		return out, err
	}
	if err = s.removeDeletedFileTx(ctx, tx, entry, record, facts); err != nil {
		return out, err
	}
	if err = deleteExactlyOne(ctx, tx, `DELETE FROM sealed_tree_revocations WHERE operation_index=? AND object_index=?`, pending, record.ObjectIndex); err != nil {
		return out, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_blob_ids(blob_index) VALUES(?)`, s.listingMAC("native-delete-completed-v1", objectID, operationID)); err != nil {
		return out, err
	}
	return DeletedNativeMedia{OwnerID: placement.OwnerID, Bytes: placement.Bytes}, nil
}
