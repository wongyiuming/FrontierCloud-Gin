package business

import (
	"context"
	"encoding/json"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/opaqueledger"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// selectedFinalizePolicyTx rechecks current Master/Owner authority under the
// final transaction. A previously issued upload ticket is not authority to
// commit after a relationship or applied policy changes.
func (r *Repository) selectedFinalizePolicyTx(ctx context.Context, q queryer, key []byte, selected selectedOpaqueIntent) error {
	capacity := selected.Capacity.capacity()
	identity, err := readNode(ctx, q, r.lock())
	if err != nil || identity.Role != "Master" || identity.ID != capacity.MasterID || capacityMasterBinding(identity) != selected.MasterBinding {
		return store.ErrNodeState
	}
	member, err := scanMember(q.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?"+r.lock(), capacity.MemberID))
	if err != nil || !validSelectedOwnerBinding(selected) {
		return store.ErrNodeState
	}
	if selected.Policy == "Local" {
		if member.ID != identity.ID || member.Kind != "MasterLocal" || member.RelationshipID != nil || selectedOriginBinding(key, "") != selected.OriginBinding {
			return store.ErrNodeState
		}
		return nil
	}
	if selected.Policy == "S3" {
		current, err := r.s3Member(ctx, q, capacity.MemberID, r.lock())
		if err != nil || current.Revision != selected.Revision || selectedOriginBinding(key, "") != selected.OriginBinding {
			return store.ErrNodeState
		}
		binding, err := selectedS3MemberBinding(key, current, time.Now().Unix())
		if err != nil || binding != selected.RelationshipBinding {
			return store.ErrNodeState
		}
		return nil
	}
	if member.Kind != "Follower" || member.RelationshipID == nil || *member.RelationshipID != selected.RelationshipID {
		return store.ErrNodeState
	}
	relation, err := scanRelation(q.QueryRowContext(ctx, "SELECT "+relationColumns+" FROM node_relationships WHERE relationship_id=?"+r.lock(), selected.RelationshipID))
	if err != nil || relation.PeerID != capacity.MemberID || relation.Direction != "downstream" || relation.State != "active" || relation.Protocol != protocol.Version || relation.Endpoint == "" || relation.Credential == "" || relation.CreatedAt <= 0 {
		return store.ErrNodeState
	}
	binding := store.PeerIngressBinding(store.PeerIngressEvidence{MemberID: relation.PeerID, RelationshipID: relation.ID, PublicKey: relation.PublicKey, ControlEndpoint: relation.Endpoint, CredentialDigest: store.PeerCredentialDigest(relation.Credential), CreatedAt: relation.CreatedAt})
	var configured string
	var revision int64
	if binding != selected.RelationshipBinding || q.QueryRowContext(ctx, "SELECT configured_transport,revision FROM native_transport_policy WHERE member_id=?"+r.lock(), member.ID).Scan(&configured, &revision) != nil || configured != selected.Policy || revision != selected.Revision {
		return store.ErrNodeState
	}
	raw, err := json.Marshal(relation.Summary[nativeTransportReceiptKey])
	var applied nativeTransportReceipt
	if err != nil || json.Unmarshal(raw, &applied) != nil || applied.Transport != selected.Policy || applied.Revision != selected.Revision || !validSelectedTransport(selected.Policy, applied.Origin) || selected.Policy == "Direct" && relation.Summary["native_resource_origin"] != applied.Origin || selectedOriginBinding(key, applied.Origin) != selected.OriginBinding {
		return store.ErrNodeState
	}
	return nil
}

// finalizeSelectedSigned is a private transaction composition, not an HTTP
// endpoint. checkAdmin must authenticate the current request without network
// I/O while the transaction is held. The exact signed Owner publication must
// already have been durably recorded; a lost COMMIT response must be resolved
// by upload ID, never by assuming rollback or deleting Owner data.
func (r *Repository) finalizeSelectedSigned(ctx context.Context, tree *sealedtree.SQLStore, key []byte, nodeVault *vault.Vault, uploadID string, receipt protocol.OpaqueCapacityReceipt, signature string, checkAdmin func(context.Context) error) (bool, error) {
	if r == nil || ctx == nil || tree == nil || !validCapacityKey(key) || nodeVault == nil || !nodeIDPattern.MatchString(uploadID) || signature == "" || checkAdmin == nil {
		return false, store.ErrNodeState
	}
	var already bool
	err := r.withSelectedMutation(ctx, tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
		selected, oldID, found, err := r.selectedIntentAnyTx(c, q, key, uploadID)
		if err != nil || !found || selected.CancelRequested {
			return store.ErrNodeState
		}
		capacity := selected.Capacity.capacity()
		if receipt.OperationID != capacity.OperationID || receipt.MasterID != capacity.MasterID || receipt.OwnerID != capacity.MemberID || receipt.BlobID != capacity.BlobID || receipt.Digest != capacity.Digest || receipt.Bytes != capacity.Bytes {
			return store.ErrNodeState
		}
		if err = checkAdmin(c); err != nil {
			return err
		}
		if err = r.selectedFinalizePolicyTx(c, q, key, selected); err != nil {
			return err
		}
		scope, found, err := r.selectedScopeTx(c, q, key, selected)
		if err != nil || !found || scope.PublishedSignature != signature || scope.CleanupSignature != "" {
			return store.ErrNodeState
		}
		var parent selectedParentScope
		var parentID string
		if selected.State == "pending" {
			if scope.Settled || scope.CompletionBinding != "" {
				return store.ErrNodeState
			}
			parent, found, err = r.readSelectedParentScope(c, q, key, selected.ParentID, capacity.MemberID)
			if err != nil || !found || q.QueryRowContext(c, "SELECT encryption_id FROM selected_upload_parent_scopes WHERE parent_index=?"+r.lock(), selectedParentIndex(key, selected.ParentID)).Scan(&parentID) != nil {
				return store.ErrNodeState
			}
		} else if selected.State != "completed" || !scope.Settled || scope.CompletionBinding != selected.CompletionBinding {
			return store.ErrNodeState
		}
		already, err = m.FinalizeSelectedSignedTx(c, q, key, nodeVault, receipt, signature, func(_ context.Context, pending sealedtree.SelectedPending, completed bool) error {
			if completed != (selected.State == "completed") || !completed && verifySelectedPendingBinding(key, selected, pending) != nil {
				return store.ErrNodeState
			}
			return nil
		})
		if err != nil {
			return err
		}
		if already {
			return c.Err()
		}
		settled, found, err := r.selectedScopeTx(c, q, key, selected)
		if err != nil || !found || !settled.Settled || !nodeHashPattern.MatchString(settled.CompletionBinding) {
			return store.ErrNodeState
		}
		var completed int
		var objectIndex, blobIndex, receiptMAC string
		if q.QueryRowContext(c, "SELECT completed,object_index,blob_index,receipt_mac FROM sealed_tree_operation_ids WHERE operation_id=?", capacity.OperationID).Scan(&completed, &objectIndex, &blobIndex, &receiptMAC) != nil || completed != 1 || opaqueledger.CompletionBinding(objectIndex, blobIndex, receiptMAC) != settled.CompletionBinding {
			return store.ErrNodeState
		}
		if parent.Count == 1 {
			if parent.Bytes != capacity.Bytes {
				return store.ErrNodeState
			}
			res, e := q.ExecContext(c, "DELETE FROM selected_upload_parent_scopes WHERE parent_index=? AND encryption_id=?", selectedParentIndex(key, selected.ParentID), parentID)
			if e != nil {
				return e
			}
			if n, e := res.RowsAffected(); e != nil || n != 1 {
				return store.ErrNodeState
			}
		} else {
			if parent.Count < 2 || parent.Bytes-capacity.Bytes < parent.Count-1 {
				return store.ErrNodeState
			}
			parent.Count--
			parent.Bytes -= capacity.Bytes
			if err = r.writeSelectedParentScope(c, q, key, parent, true); err != nil {
				return err
			}
		}
		selected.State, selected.CompletionBinding = "completed", settled.CompletionBinding
		raw, err := json.Marshal(selected)
		if err != nil {
			return store.ErrNodeState
		}
		defer clear(raw)
		index := opaqueCapacityIndex(key, capacity.OperationID)
		id, sealed, err := sealCapacityRecord(key, index, raw)
		if err != nil {
			return err
		}
		if _, err = q.ExecContext(c, "INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)", id); err != nil {
			return store.ErrNodeState
		}
		res, err := q.ExecContext(c, "UPDATE selected_upload_intents SET encryption_id=?,sealed=?,state='completed' WHERE operation_index=? AND encryption_id=? AND state='pending'", id, sealed, index, oldID)
		if err != nil {
			return err
		}
		if n, e := res.RowsAffected(); e != nil || n != 1 {
			return store.ErrNodeState
		}
		return c.Err()
	})
	return already, err
}
