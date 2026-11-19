package sealedtree

import (
	"context"
	"reflect"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// FinalizeSelectedS3Tx replaces a selected pending native-shaped reservation
// with the authenticated S3 placement in the same fenced SQL transaction.
// check must independently authenticate the selected reservation and the
// Master-verified provider proof and must not perform network I/O or reenter
// this mutation. The caller settles capacity and its durable terminal record
// in this same transaction; any error must roll the entire transaction back.
func (m *CoordinatedMutation) FinalizeSelectedS3Tx(ctx context.Context, tx treeQuery, operation string, placement S3Placement, check func(context.Context, SelectedPending, S3Placement) error) error {
	if m == nil || ctx == nil || tx == nil || check == nil || !hexID(operation) || !validS3Placement(placement) || placement.ObjectRevision != 1 || placement.Encryption == nil {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.store
	if !m.active || !s.valid() || ctx.Err() != nil {
		return ErrInvalid
	}
	if err := s.lockIndexedWriter(ctx, tx); err != nil {
		return err
	}
	if err := s.verifyRoot(ctx, tx); err != nil {
		return err
	}
	before, entry, native, err := s.pending(ctx, tx, operation)
	if err != nil {
		return err
	}
	pending, err := m.readSelectedFileTx(ctx, tx, operation)
	if err != nil || pending.Admission.Policy != "S3" || pending.OperationID != operation || native.Encryption == nil || *native.Encryption != *placement.Encryption || placement.ObjectID != entry.ObjectID || placement.MemberID != native.OwnerID || placement.Proof.MediaID != entry.ObjectID || placement.Proof.ObjectID != entry.ObjectID || placement.Proof.SessionID != pending.Admission.UploadID || placement.Proof.Bytes != native.Bytes {
		return ErrConflict
	}
	providerKey := "objects/" + native.BlobID[:2] + "/" + native.BlobID[2:4] + "/" + native.BlobID + ".blob"
	if placement.Proof.Key != providerKey {
		return ErrConflict
	}
	if err = check(ctx, pending, placement); err != nil {
		return err
	}
	if err = s.finalizePendingTxSelected(ctx, tx, operation, before, entry, native, true); err != nil {
		return err
	}
	sealed, err := s.tree.SealS3Placement(placement, 1)
	if err != nil || sealed.ObjectIndex != before.name.ObjectIndex {
		return ErrInvalid
	}
	encryptionID, err := S3PlacementEncryptionID(sealed)
	if err != nil {
		return err
	}
	if _, err = reserveID(ctx, tx, encryptionID); err != nil {
		return err
	}
	slot, err := s.s3Slot(entry.ObjectID)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_blob_ids(blob_index) VALUES(?)`, slot); err != nil {
		return ErrConflict
	}
	result, err := tx.ExecContext(ctx, `UPDATE sealed_tree_placements SET blob_index=?,revision=?,encryption_id=?,sealed=? WHERE object_index=? AND blob_index=? AND encryption_id=?`, slot, sealed.Revision, encryptionID, sealed.Sealed, sealed.ObjectIndex, before.placement.BlobIndex, before.placementID)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return ErrConflict
	}
	alias, err := s.tree.BlobIndex(native.ReadAlias)
	if err != nil {
		return err
	}
	result, err = tx.ExecContext(ctx, `DELETE FROM sealed_tree_aliases WHERE alias_index=? AND object_index=?`, alias, sealed.ObjectIndex)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return ErrConflict
	}
	return ctx.Err()
}

// VerifySelectedS3CompletedTx verifies a previously committed tree outcome for
// an idempotent completion retry. The caller must authenticate its durable
// selected terminal record and provider proof in the same transaction.
func (m *CoordinatedMutation) VerifySelectedS3CompletedTx(ctx context.Context, tx treeQuery, operation string, expected S3Placement) error {
	if m == nil || ctx == nil || tx == nil || !hexID(operation) || !validS3Placement(expected) {
		return ErrInvalid
	}
	physical, ok := store.S3OpaqueOwner(expected.Proof.Key)
	if !ok {
		return ErrInvalid
	}
	actual, err := m.ReadSelectedS3CompletedTx(ctx, tx, operation, expected.ObjectID, physical)
	if err != nil || !reflect.DeepEqual(actual, expected) {
		return ErrConflict
	}
	return nil
}

// ReadSelectedS3CompletedTx verifies an operation-to-object completion under
// the same tree fence and returns only its authenticated S3 placement.
func (m *CoordinatedMutation) ReadSelectedS3CompletedTx(ctx context.Context, tx treeQuery, operation, objectID, physical string) (S3Placement, error) {
	var zero S3Placement
	if m == nil || ctx == nil || tx == nil || !hexID(operation) || !hexID(objectID) || !hexID(physical) {
		return zero, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.store
	if !m.active || !s.valid() || ctx.Err() != nil {
		return zero, ErrInvalid
	}
	if err := s.lockIndexedWriter(ctx, tx); err != nil {
		return zero, err
	}
	if err := s.verifyRoot(ctx, tx); err != nil {
		return zero, err
	}
	completed, err := s.completed(ctx, tx, operation)
	if err != nil || !completed {
		return zero, ErrConflict
	}
	objectIndex, err := s.tree.ObjectIndex(objectID)
	if err != nil {
		return zero, ErrInvalid
	}
	blobIndex, err := s.tree.BlobIndex(physical)
	if err != nil {
		return zero, ErrInvalid
	}
	var recordedObject, recordedBlob string
	if err = tx.QueryRowContext(ctx, `SELECT object_index,blob_index FROM sealed_tree_operation_ids WHERE operation_id=? AND completed=1`, operation).Scan(&recordedObject, &recordedBlob); err != nil || recordedObject != objectIndex || recordedBlob != blobIndex {
		return zero, ErrConflict
	}
	record, entry, err := s.recordByID(ctx, tx, objectID)
	if err != nil || entry.Kind != "audio" && entry.Kind != "video" {
		return zero, ErrConflict
	}
	handled, err := s.checkIndexedS3(ctx, tx, entry, record.ObjectIndex)
	if err != nil || !handled {
		return zero, ErrInvalid
	}
	var slot, id string
	var revision int64
	var sealed []byte
	if err = tx.QueryRowContext(ctx, `SELECT blob_index,revision,encryption_id,sealed FROM sealed_tree_placements WHERE object_index=?`, record.ObjectIndex).Scan(&slot, &revision, &id, &sealed); err != nil {
		return zero, err
	}
	actual, err := s.openIndexedS3Placement(ctx, tx, objectID, slot, record.ObjectIndex, revision, sealed)
	if err != nil {
		return zero, ErrConflict
	}
	actualPhysical, ok := store.S3OpaqueOwner(actual.Proof.Key)
	if !ok || actualPhysical != physical || ctx.Err() != nil {
		return zero, ErrConflict
	}
	facts, _, err := s.factsFor(ctx, tx, entry, record.ObjectIndex)
	if err != nil || facts.Revocation != nil {
		return zero, ErrConflict
	}
	if intent := facts.S3Deletion; intent != nil && s.verifyS3MediaDeletion(ctx, tx, record, intent, actual, id) != nil {
		return zero, ErrConflict
	}
	return actual, nil
}
