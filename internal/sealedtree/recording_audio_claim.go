package sealedtree

import (
	"context"
	"database/sql"
	"encoding/hex"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/opaqueledger"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// ReserveRecordingAudioPreparationTx permanently reserves a fresh descriptor
// before a key envelope is issued. The trusted coordinator must hold the
// Owner/ingress/tree fences, recheck account authority, and commit the same
// transaction before returning any key. A later failure never releases the ID.
func (m *CoordinatedMutation) ReserveRecordingAudioPreparationTx(ctx context.Context, tx treeQuery, meta mediacrypto.Metadata, binding string) error {
	if m == nil || ctx == nil || tx == nil || !validRecordingAudioBinding(binding) {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active || !m.store.valid() || ctx.Err() != nil {
		return ErrInvalid
	}
	if err := m.store.lockIndexedWriter(ctx, tx); err != nil {
		return err
	}
	if err := m.store.verifyRoot(ctx, tx); err != nil {
		return err
	}
	return m.store.reserveMediaPreparationTx(ctx, tx, meta, binding)
}

// ReserveRecordingAudioBlobTx reserves the server-generated physical blob
// identity in the same permanent namespace as media blobs and aliases. The
// enclosing recording intent and capacity reservation must commit in the same
// transaction; cancellation never frees the identity for reuse.
func (m *CoordinatedMutation) ReserveRecordingAudioBlobTx(ctx context.Context, tx treeQuery, blobID string) error {
	if m == nil || ctx == nil || tx == nil || !hexID(blobID) {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active || !m.store.valid() || ctx.Err() != nil {
		return ErrInvalid
	}
	if err := m.store.lockIndexedWriter(ctx, tx); err != nil {
		return err
	}
	if err := m.store.verifyRoot(ctx, tx); err != nil {
		return err
	}
	index, err := m.store.tree.BlobIndex(blobID)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_blob_ids(blob_index) VALUES(?)`, index); err != nil {
		return ErrConflict
	}
	return nil
}

// CheckRecordingAudioBlobTx rejects a missing or replaced blob reservation;
// it grants neither access to the object nor proof of Owner bytes.
func (m *CoordinatedMutation) CheckRecordingAudioBlobTx(ctx context.Context, tx treeQuery, blobID string) error {
	if m == nil || ctx == nil || tx == nil || !hexID(blobID) {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active || !m.store.valid() || ctx.Err() != nil {
		return ErrInvalid
	}
	if err := m.store.lockIndexedWriter(ctx, tx); err != nil {
		return err
	}
	if err := m.store.verifyRoot(ctx, tx); err != nil {
		return err
	}
	index, err := m.store.tree.BlobIndex(blobID)
	if err != nil {
		return err
	}
	var present int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_blob_ids WHERE blob_index=?`, index).Scan(&present); err != nil || present != 1 {
		return ErrConflict
	}
	return nil
}

// CheckUnstartedRecordingAudioTx proves the original descriptor/operation
// and permanent blob reservations still exist and no tree completion or
// pending tree object exists. The caller must separately prove that no Owner
// scope/capability was issued and atomically record cancellation/refund.
func (m *CoordinatedMutation) CheckUnstartedRecordingAudioTx(ctx context.Context, tx treeQuery, meta mediacrypto.Metadata, binding, operation, blobID string) error {
	if m == nil || ctx == nil || tx == nil || !validRecordingAudioBinding(binding) || !hexID(operation) || !hexID(blobID) {
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
	id, prepared, err := s.mediaPreparationTags(meta, binding)
	if err != nil {
		return err
	}
	claimed, err := s.mediaFileTag("claimed", meta.FileID)
	if err != nil {
		return err
	}
	owner, err := s.mediaFileTag("operation", meta.FileID, binding, operation)
	if err != nil {
		return err
	}
	for _, tag := range []string{id, prepared, claimed, owner} {
		ok, e := mediaTagPresent(ctx, tx, tag)
		if e != nil || !ok {
			return ErrConflict
		}
	}
	index, err := s.tree.BlobIndex(blobID)
	if err != nil {
		return err
	}
	var count int
	if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_blob_ids WHERE blob_index=?`, index).Scan(&count) != nil || count != 1 {
		return ErrConflict
	}
	for _, table := range []string{"sealed_tree_operation_ids", "sealed_tree_pending_files", "sealed_tree_pending_facts"} {
		if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE operation_id=?`, operation).Scan(&count) != nil || count != 0 {
			return ErrConflict
		}
	}
	return ctx.Err()
}

// CompleteRecordingAudioTx records an authenticated completion and settles the
// existing opaque capacity reservation in the caller's fenced transaction.
// The caller must independently authenticate the recording intent and user,
// compare the complete signed receipt, and atomically mark that intent ready.
// A receipt is an Owner claim, not proof of continued object availability.
func (m *CoordinatedMutation) CompleteRecordingAudioTx(ctx context.Context, tx treeQuery, key []byte, nodeVault *vault.Vault, userID, recordingID string, receipt protocol.OpaqueCapacityReceipt, signature string) (bool, error) {
	if m == nil || ctx == nil || tx == nil || !recordingBindingID(userID, 16) || !recordingBindingID(recordingID, 16) || nodeVault == nil {
		return false, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.store
	if !m.active || !s.valid() || ctx.Err() != nil {
		return false, ErrInvalid
	}
	if err := s.lockIndexedWriter(ctx, tx); err != nil {
		return false, err
	}
	if err := s.verifyRoot(ctx, tx); err != nil {
		return false, err
	}
	if err := opaqueledger.VerifyPublished(ctx, tx, key, nodeVault, receipt, signature, ""); err != nil {
		return false, ErrConflict
	}
	objectIndex, err := s.mediaFileTag("recording-audio-object", userID, recordingID)
	if err != nil {
		return false, err
	}
	blobIndex, err := s.tree.BlobIndex(receipt.BlobID)
	if err != nil {
		return false, err
	}
	var blobCount int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_blob_ids WHERE blob_index=?`, blobIndex).Scan(&blobCount); err != nil || blobCount != 1 {
		return false, ErrConflict
	}
	done, err := s.completed(ctx, tx, receipt.OperationID)
	if err != nil {
		return false, err
	}
	if done {
		var actualObject, actualBlob string
		if err = tx.QueryRowContext(ctx, `SELECT object_index,blob_index FROM sealed_tree_operation_ids WHERE operation_id=? AND completed=1`, receipt.OperationID).Scan(&actualObject, &actualBlob); err != nil || actualObject != objectIndex || actualBlob != blobIndex {
			return false, ErrConflict
		}
	} else {
		mac := s.completionMAC(receipt.OperationID, objectIndex, blobIndex)
		if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_operation_ids(operation_id,completed,object_index,blob_index,receipt_mac) VALUES(?,1,?,?,?)`, receipt.OperationID, objectIndex, blobIndex, mac); err != nil {
			return false, ErrConflict
		}
	}
	already, err := opaqueledger.SettlePublished(ctx, tx, key, s.tree.indexKey[:], nodeVault, receipt, signature, "")
	if err != nil || already != done {
		return false, ErrConflict
	}
	return already, nil
}

// CheckRecordingAudioCompletionTx validates the durable tree completion MAC
// and its user, recording and blob binding in the caller's fenced SQL
// transaction. It is not browser authorization and does not prove that the
// Owner still possesses the ciphertext.
func (m *CoordinatedMutation) CheckRecordingAudioCompletionTx(ctx context.Context, tx treeQuery, userID, recordingID, operationID, blobID string) error {
	if m == nil || ctx == nil || tx == nil || !recordingBindingID(userID, 16) || !recordingBindingID(recordingID, 16) || !hexID(operationID) || !hexID(blobID) {
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
	return s.checkRecordingAudioCompletion(ctx, tx, userID, recordingID, operationID, blobID)
}

// WithRecordingRecoverySnapshot verifies recording completions in the same
// read-only transaction as the business inventory. The visitor and its
// completion check must stay inside this call and must not reenter the tree.
func (s *SQLStore) WithRecordingRecoverySnapshot(ctx context.Context, lease *TreeLease, db *sql.DB, visit func(context.Context, *sql.Tx, func(context.Context, string, string, string, string) error) error) error {
	if !s.valid() || ctx == nil || db != s.db || lease == nil || visit == nil {
		return ErrInvalid
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return ErrFenceRequired
	}
	if err := lease.checkLocked(ctx); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.verifyRoot(ctx, tx); err != nil {
		return err
	}
	if err = s.requireListingReady(ctx, tx); err != nil {
		return err
	}
	check := func(ctx context.Context, userID, recordingID, operationID, blobID string) error {
		if ctx == nil || !recordingBindingID(userID, 16) || !recordingBindingID(recordingID, 16) || !hexID(operationID) || !hexID(blobID) {
			return ErrInvalid
		}
		return s.checkRecordingAudioCompletion(ctx, tx, userID, recordingID, operationID, blobID)
	}
	if err = visit(ctx, tx, check); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return lease.checkLocked(ctx)
}

func (s *SQLStore) checkRecordingAudioCompletion(ctx context.Context, tx treeQuery, userID, recordingID, operationID, blobID string) error {
	done, err := s.completed(ctx, tx, operationID)
	if err != nil || !done {
		return ErrConflict
	}
	objectIndex, err := s.mediaFileTag("recording-audio-object", userID, recordingID)
	if err != nil {
		return err
	}
	blobIndex, err := s.tree.BlobIndex(blobID)
	if err != nil {
		return err
	}
	var blobCount int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_blob_ids WHERE blob_index=?`, blobIndex).Scan(&blobCount); err != nil || blobCount != 1 {
		return ErrConflict
	}
	var actualObject, actualBlob string
	if err = tx.QueryRowContext(ctx, `SELECT object_index,blob_index FROM sealed_tree_operation_ids WHERE operation_id=? AND completed=1`, operationID).Scan(&actualObject, &actualBlob); err != nil || actualObject != objectIndex || actualBlob != blobIndex {
		return ErrConflict
	}
	return nil
}

// ClaimRecordingAudioPreparationTx consumes a previously reserved audio file
// ID inside the trusted coordinator's transaction. It does not authenticate a
// user or preparation token. The caller must verify both and durably insert an
// exact user/recording/owner/descriptor intent, reservation and quota in this
// same transaction; any failed check must roll the transaction back. The
// operation is an independent random 256-bit identifier, not a browser input.
func (m *CoordinatedMutation) ClaimRecordingAudioPreparationTx(ctx context.Context, tx treeQuery, meta mediacrypto.Metadata, binding, operation string) error {
	if m == nil || ctx == nil || tx == nil || !validRecordingAudioBinding(binding) || !hexID(operation) {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active || !m.store.valid() || ctx.Err() != nil {
		return ErrInvalid
	}
	if err := m.store.lockIndexedWriter(ctx, tx); err != nil {
		return err
	}
	if err := m.store.verifyRoot(ctx, tx); err != nil {
		return err
	}
	return m.store.claimMediaPreparationTx(ctx, tx, meta, binding, operation)
}

func validRecordingAudioBinding(binding string) bool {
	parts := strings.Split(binding, ":")
	if len(parts) != 5 || parts[0] != "recording-audio" || parts[1] != "v1" || !recordingBindingID(parts[2], 16) || !recordingBindingID(parts[3], 32) || !recordingBindingID(parts[4], 16) {
		return false
	}
	return true
}

func recordingBindingID(value string, size int) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == size && hex.EncodeToString(raw) == value
}
