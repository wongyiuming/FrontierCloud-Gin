package sealedtree

import (
	"context"
	"crypto/hmac"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/opaqueledger"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// finalizeSignedPendingTx is an unregistered internal seam. The caller must
// own the actual tree mutation fence and the enclosing owner/ingress fences,
// provide the real business SQL transaction, and roll it back on every error.
// It does not verify the cross-database source evidence or vault key grant and
// must not be used as an import activation decision.
func (s *SQLStore) finalizeSignedPendingTx(ctx context.Context, tx treeQuery, key []byte, nodeVault *vault.Vault, receipt protocol.OpaqueCapacityReceipt, signature, lock string) (bool, error) {
	if !s.valid() || ctx == nil || tx == nil || receipt.OperationID == "" {
		return false, ErrInvalid
	}
	if err := s.verifyRoot(ctx, tx); err != nil {
		return false, err
	}
	before, entry, placement, pendingErr := s.pending(ctx, tx, receipt.OperationID)
	if pendingErr == nil {
		if before.facts == nil || placement.BlobID != receipt.BlobID || placement.OwnerID != receipt.OwnerID || placement.Bytes != receipt.Bytes || placement.SHA256 != receipt.Digest {
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
	if err := opaqueledger.VerifyPublished(ctx, tx, key, nodeVault, receipt, signature, lock); err != nil {
		return false, err
	}
	if pendingErr == nil {
		if err := s.finalizePendingTx(ctx, tx, receipt.OperationID, before, entry, placement); err != nil {
			return false, err
		}
	}
	already, err := opaqueledger.SettlePublished(ctx, tx, key, s.tree.indexKey[:], nodeVault, receipt, signature, lock)
	if err != nil {
		return false, err
	}
	if pendingErr != nil {
		if !already {
			return false, ErrConflict
		}
		return true, nil
	}
	if already {
		return false, ErrConflict
	}
	return false, nil
}
