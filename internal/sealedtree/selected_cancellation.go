package sealedtree

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

func (s *SQLStore) cancellationMAC(op, objectIndex, blobIndex string) string {
	h := hmac.New(sha256.New, s.tree.indexKey[:])
	_, _ = h.Write([]byte("frontiercloud:sealed-tree:selected-cancel:v1\x00" + op + objectIndex + blobIndex))
	return hex.EncodeToString(h.Sum(nil))
}

func hasSelectedCancellationTable(ctx context.Context, tx treeQuery) (bool, error) {
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='selected_upload_cancellations'`).Scan(&count); err != nil || count < 0 || count > 1 {
		return false, ErrInvalid
	}
	return count == 1, nil
}

func (s *SQLStore) verifySelectedCancellationRows(ctx context.Context, tx treeQuery) error {
	after := ""
	for {
		rows, err := tx.QueryContext(ctx, `SELECT c.operation_id,c.object_index,c.blob_index,c.cancellation_mac FROM selected_upload_cancellations c JOIN sealed_tree_operation_ids o ON o.operation_id=c.operation_id WHERE c.operation_id>? AND o.completed=0 AND NOT EXISTS(SELECT 1 FROM sealed_tree_pending_files p WHERE p.operation_id=c.operation_id) AND NOT EXISTS(SELECT 1 FROM sealed_tree_pending_facts f WHERE f.operation_id=c.operation_id) ORDER BY c.operation_id LIMIT 256`, after)
		if err != nil {
			return err
		}
		count := 0
		for rows.Next() {
			var op, object, blob, mac string
			if err = rows.Scan(&op, &object, &blob, &mac); err != nil || op <= after || !hexID(op) || !hexID(object) || !hexID(blob) || !hmac.Equal([]byte(mac), []byte(s.cancellationMAC(op, object, blob))) {
				rows.Close()
				return ErrInvalid
			}
			after = op
			count++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if count < 256 {
			break
		}
	}
	var invalid int
	if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM selected_upload_cancellations c LEFT JOIN sealed_tree_operation_ids o ON o.operation_id=c.operation_id LEFT JOIN sealed_tree_pending_files p ON p.operation_id=c.operation_id LEFT JOIN sealed_tree_pending_facts f ON f.operation_id=c.operation_id WHERE o.operation_id IS NULL OR o.completed<>0 OR p.operation_id IS NOT NULL OR f.operation_id IS NOT NULL`).Scan(&invalid) != nil || invalid != 0 {
		return ErrInvalid
	}
	return nil
}

// CancelSelectedTx is restricted to a held coordinated tree mutation and the
// same authoritative transaction as the caller's cleanup receipt and quota
// checks. check must validate those external facts; this method never commits.
// The operation, blob and encryption identifiers remain permanently reserved.
func (m *CoordinatedMutation) CancelSelectedTx(ctx context.Context, tx treeQuery, op string, check func(SelectedPending) error) error {
	if m == nil || ctx == nil || tx == nil || check == nil || !hexID(op) {
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
	present, err := hasSelectedCancellationTable(ctx, tx)
	if err != nil || !present {
		return ErrInvalid
	}
	selected, err := m.readSelectedFileTx(ctx, tx, op)
	if err != nil {
		return err
	}
	if err = check(selected); err != nil {
		return err
	}
	before, _, _, err := s.pending(ctx, tx, op)
	if err != nil || before.facts == nil {
		return ErrInvalid
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO selected_upload_cancellations(operation_id,object_index,blob_index,cancellation_mac) VALUES(?,?,?,?)`, op, before.name.ObjectIndex, before.placement.BlobIndex, s.cancellationMAC(op, before.name.ObjectIndex, before.placement.BlobIndex)); err != nil {
		return ErrConflict
	}
	for _, table := range []string{"sealed_tree_pending_facts", "sealed_tree_pending_files"} {
		result, e := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE operation_id=?`, op)
		if e != nil {
			return e
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			return ErrInvalid
		}
	}
	return ctx.Err()
}

// IsSelectedCancelledTx authenticates the separate cancellation tombstone. It
// never treats completed=1 (publication) as cancellation, or vice versa.
func (m *CoordinatedMutation) IsSelectedCancelledTx(ctx context.Context, tx treeQuery, op string) (bool, error) {
	if m == nil || ctx == nil || tx == nil || !hexID(op) {
		return false, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.store
	if !m.active || !s.valid() || ctx.Err() != nil {
		return false, ErrInvalid
	}
	var object, blob, mac string
	if err := tx.QueryRowContext(ctx, `SELECT c.object_index,c.blob_index,c.cancellation_mac FROM selected_upload_cancellations c JOIN sealed_tree_operation_ids o ON o.operation_id=c.operation_id WHERE c.operation_id=? AND o.completed=0 AND NOT EXISTS(SELECT 1 FROM sealed_tree_pending_files p WHERE p.operation_id=c.operation_id) AND NOT EXISTS(SELECT 1 FROM sealed_tree_pending_facts f WHERE f.operation_id=c.operation_id)`, op).Scan(&object, &blob, &mac); err != nil {
		return false, ErrInvalid
	}
	if !hexID(object) || !hexID(blob) || !hmac.Equal([]byte(mac), []byte(s.cancellationMAC(op, object, blob))) {
		return false, ErrInvalid
	}
	return true, nil
}
