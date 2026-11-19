package sealedtree

import (
	"context"
	"math"
	"reflect"
	"strconv"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// S3MediaDeletion is a Master-only intent for one committed S3 placement.
// The provider proof stays in its existing encrypted placement record.
type S3MediaDeletion struct {
	OperationID string `json:"operation_id"`
	UploadID    string `json:"upload_id"`
	PlacementID string `json:"placement_id"`
	QueuedAt    int64  `json:"queued_at"`
}

type S3MediaDeletionTarget struct {
	Path      string
	Placement S3Placement
	Pending   S3MediaDeletion
}

type PendingS3MediaDeletion struct {
	ObjectID string
	Path     string
	Intent   S3MediaDeletion
}

func (s *SQLStore) s3MediaDeletionIndex(objectIndex string, intent S3MediaDeletion) string {
	return s.listingMAC("s3-media-deletion-v1", objectIndex, intent.OperationID, intent.UploadID, intent.PlacementID, strconv.FormatInt(intent.QueuedAt, 10))
}

// s3DeletionPlacement reads only the authenticated S3 envelope and permanent
// locator reservations. It never grants access or falls through to native.
func (s *SQLStore) s3DeletionPlacement(ctx context.Context, tx treeQuery, record Record, entry Entry) (S3Placement, string, error) {
	if entry.Kind != "audio" && entry.Kind != "video" {
		return S3Placement{}, "", ErrInvalid
	}
	handled, err := s.checkIndexedS3(ctx, tx, entry, record.ObjectIndex)
	if err != nil || !handled {
		return S3Placement{}, "", ErrInvalid
	}
	var slot, id string
	var revision int64
	var sealed []byte
	if err = tx.QueryRowContext(ctx, `SELECT blob_index,revision,encryption_id,sealed FROM sealed_tree_placements WHERE object_index=?`,
		record.ObjectIndex).Scan(&slot, &revision, &id, &sealed); err != nil {
		return S3Placement{}, "", err
	}
	placement, err := s.openIndexedS3Placement(ctx, tx, entry.ObjectID, slot, record.ObjectIndex, revision, sealed)
	if err != nil || !hexID(id) || placement.Encryption == nil || placement.Proof.MetadataFormat != store.S3OpaqueMetadata {
		return S3Placement{}, "", ErrInvalid
	}
	return placement, id, nil
}

func (s *SQLStore) verifyS3MediaDeletion(ctx context.Context, tx treeQuery, record Record, intent *S3MediaDeletion, placement S3Placement, placementID string) error {
	if intent == nil || intent.UploadID != placement.Proof.SessionID || intent.PlacementID != placementID || intent.QueuedAt <= 0 {
		return ErrConflict
	}
	index := s.s3MediaDeletionIndex(record.ObjectIndex, *intent)
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_revocations r JOIN sealed_tree_blob_ids b ON b.blob_index=r.operation_index
		WHERE r.operation_index=? AND r.object_index=?`, index, record.ObjectIndex).Scan(&n); err != nil || n != 1 {
		return ErrConflict
	}
	return nil
}

func (s *SQLStore) readS3MediaDeletion(ctx context.Context, tx treeQuery, objectID string) (S3MediaDeletionTarget, Record, Entry, Facts, int64, string, error) {
	var out S3MediaDeletionTarget
	record, entry, err := s.recordByID(ctx, tx, objectID)
	if err != nil || entry.ObjectID != objectID || s.checkDirectory(ctx, tx, entry.ParentID, entry.ObjectID) != nil {
		return out, record, entry, Facts{}, 0, "", ErrInvalid
	}
	placement, id, err := s.s3DeletionPlacement(ctx, tx, record, entry)
	if err != nil {
		return out, record, entry, Facts{}, 0, "", err
	}
	facts, revision, err := s.factsFor(ctx, tx, entry, record.ObjectIndex)
	if err != nil || facts.Revocation != nil || facts.InternalPlaceholder {
		return out, record, entry, facts, 0, "", ErrConflict
	}
	if facts.S3Deletion != nil {
		if err = s.verifyS3MediaDeletion(ctx, tx, record, facts.S3Deletion, placement, id); err != nil {
			return out, record, entry, facts, 0, "", err
		}
		out.Pending = *facts.S3Deletion
	} else {
		var pending int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_revocations WHERE object_index=?`, record.ObjectIndex).Scan(&pending); err != nil || pending != 0 {
			return out, record, entry, facts, 0, "", ErrConflict
		}
	}
	out.Path, err = s.pathInTransaction(ctx, tx, entry)
	out.Placement = placement
	return out, record, entry, facts, revision, id, err
}

func (m *CoordinatedMutation) ReadS3MediaDeletionTx(ctx context.Context, tx treeQuery, objectID string) (S3MediaDeletionTarget, error) {
	if m == nil || ctx == nil || tx == nil || !hexID(objectID) {
		return S3MediaDeletionTarget{}, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.store
	if !m.active || !s.valid() {
		return S3MediaDeletionTarget{}, ErrFenceRequired
	}
	if err := s.verifyRoot(ctx, tx); err != nil {
		return S3MediaDeletionTarget{}, err
	}
	target, _, _, _, _, _, err := s.readS3MediaDeletion(ctx, tx, objectID)
	return target, err
}

// QueueS3MediaDeletionTx fences the path and placement without touching the
// provider or freeing capacity. The caller authenticates the completed S3
// upload and its exact placement in the same transaction.
func (m *CoordinatedMutation) QueueS3MediaDeletionTx(ctx context.Context, tx treeQuery, expected S3MediaDeletionTarget) (S3MediaDeletion, error) {
	var empty S3MediaDeletion
	if m == nil || ctx == nil || tx == nil || !hexID(expected.Placement.ObjectID) {
		return empty, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.store
	if !m.active || !s.valid() {
		return empty, ErrFenceRequired
	}
	if err := s.verifyRoot(ctx, tx); err != nil {
		return empty, err
	}
	target, record, entry, facts, revision, placementID, err := s.readS3MediaDeletion(ctx, tx, expected.Placement.ObjectID)
	if err != nil || !reflect.DeepEqual(target, expected) {
		return empty, ErrConflict
	}
	if facts.S3Deletion != nil {
		return *facts.S3Deletion, nil
	}
	if revision < 1 || revision == math.MaxInt64 {
		return empty, ErrConflict
	}
	if err = s.lockIndexedWriter(ctx, tx); err != nil {
		return empty, err
	}
	oldClass := listingClass(&facts)
	random, err := NewBlobID()
	if err != nil {
		return empty, err
	}
	intent := S3MediaDeletion{OperationID: random[:32], UploadID: target.Placement.Proof.SessionID, PlacementID: placementID, QueuedAt: time.Now().Unix()}
	facts.S3Deletion = &intent
	sealed, err := s.tree.SealFacts(facts, revision+1)
	if err != nil {
		return empty, err
	}
	id, err := FactsEncryptionID(sealed)
	if err != nil {
		return empty, err
	}
	if _, err = reserveID(ctx, tx, id); err != nil {
		return empty, err
	}
	index := s.s3MediaDeletionIndex(record.ObjectIndex, intent)
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_blob_ids(blob_index) VALUES(?)`, index); err != nil {
		return empty, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_revocations(operation_index,object_index) VALUES(?,?)`, index, record.ObjectIndex); err != nil {
		return empty, err
	}
	if err = deleteExactlyOne(ctx, tx, `UPDATE sealed_tree_facts SET revision=?,encryption_id=?,sealed=? WHERE object_index=? AND revision=?`,
		sealed.Revision, id, sealed.Sealed, sealed.ObjectIndex, revision); err != nil {
		return empty, err
	}
	if err = s.listingRemove(ctx, tx, entry, record, oldClass); err != nil {
		return empty, err
	}
	if err = s.listingAdd(ctx, tx, entry, record, listingInternal); err != nil {
		return empty, err
	}
	return intent, nil
}

// FinalizeS3MediaDeletionTx consumes the exact queued placement. The caller
// must hold the provider fence and have independently proven version absence.
// It must commit the quota refund and audit in this same SQL transaction.
func (m *CoordinatedMutation) FinalizeS3MediaDeletionTx(ctx context.Context, tx treeQuery, expected S3MediaDeletionTarget) error {
	if m == nil || ctx == nil || tx == nil || expected.Pending == (S3MediaDeletion{}) {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.store
	if !m.active || !s.valid() {
		return ErrFenceRequired
	}
	if err := s.verifyRoot(ctx, tx); err != nil {
		return err
	}
	target, record, entry, facts, _, _, err := s.readS3MediaDeletion(ctx, tx, expected.Placement.ObjectID)
	if err != nil || !reflect.DeepEqual(target, expected) {
		return ErrConflict
	}
	if err = s.lockIndexedWriter(ctx, tx); err != nil {
		return err
	}
	if err = s.removeDeletedFileTx(ctx, tx, entry, record, facts); err != nil {
		return err
	}
	index := s.s3MediaDeletionIndex(record.ObjectIndex, expected.Pending)
	if err = deleteExactlyOne(ctx, tx, `DELETE FROM sealed_tree_revocations WHERE operation_index=? AND object_index=?`, index, record.ObjectIndex); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_blob_ids(blob_index) VALUES(?),(?)`,
		s.listingMAC("s3-media-deleted-v1", entry.ObjectID, expected.Pending.OperationID, target.Path),
		s.listingMAC("s3-publication-deleted-v1", entry.ObjectID, expected.Pending.UploadID))
	return err
}

func (m *CoordinatedMutation) S3PublicationDeletionRecordedTx(ctx context.Context, tx treeQuery, objectID, uploadID string) (bool, error) {
	if m == nil || ctx == nil || tx == nil || !hexID(objectID) || !lowerHex(uploadID, 32) {
		return false, ErrInvalid
	}
	return m.s3DeletionRecordedTx(ctx, tx, objectID, "s3-publication-deleted-v1", uploadID)
}

func (m *CoordinatedMutation) S3MediaDeletionRecordedTx(ctx context.Context, tx treeQuery, objectID, operationID, path string) (bool, error) {
	if m == nil || ctx == nil || tx == nil || !hexID(objectID) || !lowerHex(operationID, 32) || !factPath(path) {
		return false, ErrInvalid
	}
	return m.s3DeletionRecordedTx(ctx, tx, objectID, "s3-media-deleted-v1", operationID, path)
}

func (m *CoordinatedMutation) s3DeletionRecordedTx(ctx context.Context, tx treeQuery, objectID, domain string, fields ...string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.store
	if !m.active || !s.valid() {
		return false, ErrFenceRequired
	}
	if err := s.verifyRoot(ctx, tx); err != nil {
		return false, err
	}
	return s.s3DeletionRecordedTx(ctx, tx, objectID, domain, fields...)
}

func (s *SQLStore) s3DeletionRecordedTx(ctx context.Context, tx treeQuery, objectID, domain string, fields ...string) (bool, error) {
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_blob_ids WHERE blob_index=?`,
		s.listingMAC(domain, append([]string{objectID}, fields...)...)).Scan(&count); err != nil || count != 1 {
		return false, err
	}
	return s.deletedFileRecordedTx(ctx, tx, objectID)
}
