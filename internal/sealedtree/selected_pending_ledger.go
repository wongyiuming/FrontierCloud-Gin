package sealedtree

import (
	"context"
	"crypto/hmac"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/opaqueledger"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// FinalizeSelectedSignedTx completes a selected pending tree object and settles
// its quota only after validating the already-recorded Owner publication
// signature. It does not publish bytes or authorize an Admin. The trusted
// coordinator must hold Owner -> ingress -> tree fences, provide the same
// SQLite write transaction, check the current policy/session and authenticate
// its durable selected intent and pending binding in check. On a completed
// retry, check receives completed=true and an empty pending value: it must
// authenticate the durable selected intent rather than trusting that value.
// check must not call methods on this mutation handle. Any error MUST roll
// back the whole transaction; this method never commits or opens a transaction.
func (m *CoordinatedMutation) FinalizeSelectedSignedTx(ctx context.Context, tx treeQuery, key []byte, nodeVault *vault.Vault, receipt protocol.OpaqueCapacityReceipt, signature string, check func(context.Context, SelectedPending, bool) error) (bool, error) {
	if m == nil || ctx == nil || tx == nil || nodeVault == nil || check == nil || receipt.OperationID == "" {
		return false, ErrInvalid
	}
	keyCopy := append([]byte(nil), key...)
	defer clear(keyCopy)
	key = keyCopy
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
	before, entry, placement, pendingErr := s.pending(ctx, tx, receipt.OperationID)
	var selected SelectedPending
	if pendingErr == nil {
		var err error
		selected, err = m.readSelectedFileTx(ctx, tx, receipt.OperationID)
		if err != nil || before.facts == nil || placement.BlobID != receipt.BlobID || placement.OwnerID != receipt.OwnerID || placement.Bytes != receipt.Bytes || placement.SHA256 != receipt.Digest {
			return false, ErrConflict
		}
	} else {
		done, err := s.completed(ctx, tx, receipt.OperationID)
		if err != nil || !done {
			return false, ErrConflict
		}
		var blobIndex string
		if tx.QueryRowContext(ctx, `SELECT blob_index FROM sealed_tree_operation_ids WHERE operation_id=? AND completed=1`, receipt.OperationID).Scan(&blobIndex) != nil {
			return false, ErrConflict
		}
		expected, err := s.tree.BlobIndex(receipt.BlobID)
		if err != nil || !hmac.Equal([]byte(blobIndex), []byte(expected)) {
			return false, ErrConflict
		}
	}
	if err := opaqueledger.VerifyPublished(ctx, tx, key, nodeVault, receipt, signature, ""); err != nil {
		return false, err
	}
	if err := check(ctx, selected, pendingErr != nil); err != nil {
		return false, err
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if pendingErr == nil {
		if err := s.finalizePendingTxSelected(ctx, tx, receipt.OperationID, before, entry, placement, true); err != nil {
			return false, err
		}
	}
	already, err := opaqueledger.SettlePublished(ctx, tx, key, s.tree.indexKey[:], nodeVault, receipt, signature, "")
	if err != nil {
		return false, err
	}
	if (pendingErr != nil) != already {
		return false, ErrConflict
	}
	return already, nil
}
