package business

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/opaqueledger"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

type selectedUploadStatus struct {
	State, OperationID string
	Receipt            *protocol.OpaqueCapacityReceipt
	Signature          string
}

// selectedStatus resolves an uncertain Master commit using authenticated
// durable state rather than assuming an error means rollback. This is not an
// HTTP handler; checkAdmin must authorize the current request without network
// I/O. Unknown/corrupt or unauthorized state never becomes a success result.
func (r *Repository) selectedStatus(ctx context.Context, tree *sealedtree.SQLStore, key []byte, nodeVault *vault.Vault, uploadID string, checkAdmin func(context.Context) error) (selectedUploadStatus, error) {
	var result selectedUploadStatus
	if r == nil || ctx == nil || tree == nil || !validCapacityKey(key) || nodeVault == nil || !nodeIDPattern.MatchString(uploadID) || checkAdmin == nil {
		return result, store.ErrNodeState
	}
	err := r.withSelectedMutation(ctx, tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
		selected, _, found, err := r.selectedIntentAnyTx(c, q, key, uploadID)
		if err != nil || !found {
			return store.ErrNodeState
		}
		if err = checkAdmin(c); err != nil {
			return err
		}
		capacity := selected.Capacity.capacity()
		scope, scopeFound, err := r.selectedScopeTx(c, q, key, selected)
		if err != nil {
			return err
		}
		if selected.State == "pending" {
			pending, e := m.ReadSelectedFileTx(c, q, capacity.OperationID)
			if e != nil || verifySelectedPendingBinding(key, selected, pending) != nil || scopeFound && (scope.Settled || scope.CleanupSignature != "" && !selected.CancelRequested) {
				return store.ErrNodeState
			}
			if scopeFound && scope.PublishedSignature != "" && !selected.CancelRequested {
				receipt := protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-published-v1", MasterID: capacity.MasterID, OwnerID: capacity.MemberID, RelationshipID: scope.RelationshipID, RelationshipBinding: scope.RelationshipBinding, Generation: scope.Generation, OperationID: capacity.OperationID, StageID: scope.StageID, BlobID: capacity.BlobID, Digest: capacity.Digest, Challenge: scope.PublishChallenge, Bytes: capacity.Bytes, State: "published"}
				if opaqueledger.VerifyPublished(c, q, key, nodeVault, receipt, scope.PublishedSignature, r.lock()) != nil {
					return store.ErrNodeState
				}
				result.Receipt, result.Signature = &receipt, scope.PublishedSignature
			}
		} else if selected.State == "completed" {
			if !scopeFound || !scope.Settled || scope.CleanupSignature != "" || scope.PublishedSignature == "" || scope.CompletionBinding != selected.CompletionBinding {
				return store.ErrNodeState
			}
			receipt := protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-published-v1", MasterID: capacity.MasterID, OwnerID: capacity.MemberID, RelationshipID: scope.RelationshipID, RelationshipBinding: scope.RelationshipBinding, Generation: scope.Generation, OperationID: capacity.OperationID, StageID: scope.StageID, BlobID: capacity.BlobID, Digest: capacity.Digest, Challenge: scope.PublishChallenge, Bytes: capacity.Bytes, State: "published"}
			if opaqueledger.VerifyPublished(c, q, key, nodeVault, receipt, scope.PublishedSignature, r.lock()) != nil {
				return store.ErrNodeState
			}
			var completed int
			var objectIndex, blobIndex, receiptMAC string
			if q.QueryRowContext(c, "SELECT completed,object_index,blob_index,receipt_mac FROM sealed_tree_operation_ids WHERE operation_id=?", capacity.OperationID).Scan(&completed, &objectIndex, &blobIndex, &receiptMAC) != nil || completed != 1 || opaqueledger.CompletionBinding(objectIndex, blobIndex, receiptMAC) != selected.CompletionBinding {
				return store.ErrNodeState
			}
		} else if selected.State == "cancelled" {
			if !scopeFound || scope.Settled || scope.CleanupSignature == "" {
				return store.ErrNodeState
			}
			receipt := protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-cleaned-v1", MasterID: capacity.MasterID, OwnerID: capacity.MemberID, RelationshipID: scope.RelationshipID, RelationshipBinding: scope.RelationshipBinding, Generation: scope.Generation, OperationID: capacity.OperationID, StageID: scope.StageID, BlobID: capacity.BlobID, Digest: capacity.Digest, Challenge: scope.CleanupChallenge, Bytes: capacity.Bytes, State: "cleaned"}
			payload, e := receipt.Payload()
			if e != nil {
				return store.ErrNodeState
			}
			var public string
			if selected.Policy == "Local" {
				identity, e := readNode(c, q, r.lock())
				if e != nil || identity.ID != capacity.MasterID {
					return store.ErrNodeState
				}
				private, e := nodeVault.Unseal(identity.PrivateKey)
				if e != nil {
					return store.ErrNodeState
				}
				public, e = protocol.PublicKey(private)
				if e != nil {
					return store.ErrNodeState
				}
			} else {
				relation, e := scanRelation(q.QueryRowContext(c, "SELECT "+relationColumns+" FROM node_relationships WHERE relationship_id=?"+r.lock(), scope.RelationshipID))
				if e != nil {
					return store.ErrNodeState
				}
				public = relation.PublicKey
			}
			if protocol.Verify(public, payload, scope.CleanupSignature) != nil {
				return store.ErrNodeState
			}
			binding, e := selectedCleanupBinding(key, receipt, scope.CleanupSignature)
			if e != nil || binding != selected.CompletionBinding {
				return store.ErrNodeState
			}
			ok, e := m.IsSelectedCancelledTx(c, q, capacity.OperationID)
			if e != nil || !ok {
				return store.ErrNodeState
			}
		} else {
			return store.ErrNodeState
		}
		state := selected.State
		if selected.CancelRequested && selected.State == "pending" {
			state = "cancelling"
		}
		result.State, result.OperationID = state, capacity.OperationID
		return c.Err()
	})
	if err != nil {
		return selectedUploadStatus{}, err
	}
	return result, nil
}
