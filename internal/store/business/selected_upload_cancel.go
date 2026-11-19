package business

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// beginSelectedCancel records cancellation before releasing the fenced Master
// transaction and returning a distinct short-lived cleanup capability. It
// deliberately retains tree pending state and quota until a verified Owner
// cleanup and a separate atomic completion. It is not a product endpoint.
func (r *Repository) beginSelectedCancel(ctx context.Context, tree *sealedtree.SQLStore, key []byte, v *vault.Vault, uploadID, sessionHash, adminOrigin string, check func(context.Context, queryer, *sealedtree.CoordinatedMutation, sealedtree.SelectedPending, string) error) (string, error) {
	if r == nil || ctx == nil || tree == nil || !validCapacityKey(key) || v == nil || !nodeIDPattern.MatchString(uploadID) || !nodeHashPattern.MatchString(sessionHash) || check == nil {
		return "", store.ErrNodeState
	}
	var token string
	err := r.withSelectedMutation(ctx, tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
		selected, oldID, found, err := r.selectedIntentAnyTx(c, q, key, uploadID)
		if err != nil || !found || selected.State != "pending" {
			return store.ErrNodeState
		}
		capacity := selected.Capacity.capacity()
		pending, err := m.ReadSelectedFileTx(c, q, capacity.OperationID)
		if err != nil || verifySelectedPendingBinding(key, selected, pending) != nil {
			return store.ErrNodeState
		}
		if err = check(c, q, m, pending, sessionHash); err != nil {
			return err
		}
		if err = r.selectedFinalizePolicyTx(c, q, key, selected); err != nil {
			return err
		}
		scope, found, err := r.selectedScopeTx(c, q, key, selected)
		if err != nil || !found || scope.Settled || scope.CleanupSignature != "" {
			return store.ErrNodeState
		}
		if !selected.CancelRequested {
			selected.CancelRequested = true
			raw, e := json.Marshal(selected)
			if e != nil {
				return store.ErrNodeState
			}
			defer clear(raw)
			index := opaqueCapacityIndex(key, capacity.OperationID)
			id, sealed, e := sealCapacityRecord(key, index, raw)
			if e != nil {
				return e
			}
			if _, e = q.ExecContext(c, "INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)", id); e != nil {
				return store.ErrNodeState
			}
			result, e := q.ExecContext(c, "UPDATE selected_upload_intents SET encryption_id=?,sealed=? WHERE operation_index=? AND encryption_id=? AND state='pending'", id, sealed, index, oldID)
			if e != nil {
				return e
			}
			if n, e := result.RowsAffected(); e != nil || n != 1 {
				return store.ErrNodeState
			}
		}
		relation, err := scanRelation(q.QueryRowContext(c, "SELECT "+relationColumns+" FROM node_relationships WHERE relationship_id=?"+r.lock(), scope.RelationshipID))
		if err != nil {
			return store.ErrNodeState
		}
		credential, err := v.Unseal(relation.Credential)
		if err != nil {
			return store.ErrNodeState
		}
		admin, err := protocol.SelectedStorageAdminBinding(credential, relation.ID, sessionHash)
		if err != nil {
			return store.ErrNodeState
		}
		now := time.Now().Unix()
		claim := protocol.SelectedStorageUpload{Relationship: relation.ID, Master: capacity.MasterID, Owner: capacity.MemberID, MediaID: pending.Placement.ReadAlias, ObjectID: capacity.BlobID, UploadID: selected.UploadID, OperationID: capacity.OperationID, ContentSHA256: capacity.Digest, Size: capacity.Bytes, Policy: selected.Policy, Revision: selected.Revision, ResourceOrigin: pending.Admission.Origin, AdminOrigin: adminOrigin, AdminBinding: admin, RelationshipBinding: scope.RelationshipBinding, Generation: scope.Generation, StageID: scope.StageID, PublishChallenge: scope.PublishChallenge, CleanupChallenge: scope.CleanupChallenge, ExpiresAt: now + protocol.TokenSeconds, Encryption: pending.Placement.Encryption}
		token, err = protocol.SignSelectedStorageCleanup(credential, claim, now)
		return err
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

func selectedCleanupBinding(key []byte, receipt protocol.OpaqueCapacityReceipt, signature string) (string, error) {
	payload, err := receipt.Payload()
	if err != nil || receipt.Kind != "opaque-capacity-cleaned-v1" || receipt.State != "cleaned" || signature == "" {
		return "", store.ErrNodeState
	}
	raw, err := json.Marshal(struct {
		Payload   map[string]any `json:"payload"`
		Signature string         `json:"signature"`
	}{payload, signature})
	if err != nil {
		return "", store.ErrNodeState
	}
	defer clear(raw)
	return hex.EncodeToString(capacityMAC(key, "selected-cancel-completion-v1", raw)), nil
}

// finishSelectedCancel consumes a previously recorded exact Owner cleanup
// receipt. Tree tombstone, pending removal, quota/account, parent scope and
// terminal intent commit together; all failures require transaction rollback.
func (r *Repository) finishSelectedCancel(ctx context.Context, tree *sealedtree.SQLStore, key []byte, uploadID string, receipt protocol.OpaqueCapacityReceipt, signature string, checkAdmin func(context.Context) error, nodeVault *vault.Vault) (bool, error) {
	if r == nil || ctx == nil || tree == nil || !validCapacityKey(key) || !nodeIDPattern.MatchString(uploadID) || signature == "" || checkAdmin == nil {
		return false, store.ErrNodeState
	}
	var already bool
	err := r.withSelectedMutation(ctx, tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
		selected, oldID, found, err := r.selectedIntentAnyTx(c, q, key, uploadID)
		if err != nil || !found || !selected.CancelRequested {
			return store.ErrNodeState
		}
		if err = checkAdmin(c); err != nil {
			return err
		}
		capacity := selected.Capacity.capacity()
		scope, found, err := r.selectedScopeTx(c, q, key, selected)
		if err != nil || !found || scope.Settled || scope.CompletionBinding != "" || scope.CleanupSignature != signature {
			return store.ErrNodeState
		}
		expected := protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-cleaned-v1", MasterID: capacity.MasterID, OwnerID: capacity.MemberID, RelationshipID: scope.RelationshipID, RelationshipBinding: scope.RelationshipBinding, Generation: scope.Generation, OperationID: capacity.OperationID, StageID: scope.StageID, BlobID: capacity.BlobID, Digest: capacity.Digest, Challenge: scope.CleanupChallenge, Bytes: capacity.Bytes, State: "cleaned"}
		if receipt != expected {
			return store.ErrNodeState
		}
		payload, err := receipt.Payload()
		if err != nil {
			return store.ErrNodeState
		}
		var public string
		if selected.Policy == "Local" {
			if nodeVault == nil {
				return store.ErrNodeState
			}
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
		if protocol.Verify(public, payload, signature) != nil {
			return store.ErrNodeState
		}
		binding, err := selectedCleanupBinding(key, receipt, signature)
		if err != nil {
			return err
		}
		if selected.State == "cancelled" {
			if selected.CompletionBinding != binding {
				return store.ErrNodeState
			}
			ok, e := m.IsSelectedCancelledTx(c, q, capacity.OperationID)
			if e != nil || !ok {
				return store.ErrNodeState
			}
			already = true
			return c.Err()
		}
		if selected.State != "pending" || selected.CompletionBinding != "" {
			return store.ErrNodeState
		}
		parent, found, err := r.readSelectedParentScope(c, q, key, selected.ParentID, capacity.MemberID)
		var parentID string
		if err != nil || !found || q.QueryRowContext(c, "SELECT encryption_id FROM selected_upload_parent_scopes WHERE parent_index=?"+r.lock(), selectedParentIndex(key, selected.ParentID)).Scan(&parentID) != nil {
			return store.ErrNodeState
		}
		account, accountID, found, err := r.readOpaqueCapacityAccount(c, q, key, capacity.MemberID, r.lock())
		member, memberErr := scanMember(q.QueryRowContext(c, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?"+r.lock(), capacity.MemberID))
		if err != nil || !found || memberErr != nil || account.Total < capacity.Bytes || account.Revision == math.MaxInt64 || member.Reserved < account.Total {
			return store.ErrNodeState
		}
		if err = m.CancelSelectedTx(c, q, capacity.OperationID, func(p sealedtree.SelectedPending) error { return verifySelectedPendingBinding(key, selected, p) }); err != nil {
			return err
		}
		if parent.Count == 1 {
			if parent.Bytes != capacity.Bytes {
				return store.ErrNodeState
			}
			result, e := q.ExecContext(c, "DELETE FROM selected_upload_parent_scopes WHERE parent_index=? AND encryption_id=?", selectedParentIndex(key, selected.ParentID), parentID)
			if e != nil {
				return e
			}
			if n, e := result.RowsAffected(); e != nil || n != 1 {
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
		account.Total -= capacity.Bytes
		account.Revision++
		accountRaw, err := json.Marshal(account)
		if err != nil {
			return store.ErrNodeState
		}
		defer clear(accountRaw)
		accountIndex := opaqueCapacityMemberIndex(key, capacity.MemberID)
		newAccountID, accountSealed, err := sealCapacityRecord(key, accountIndex, accountRaw)
		if err != nil {
			return err
		}
		if _, err = q.ExecContext(c, "INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)", newAccountID); err != nil {
			return store.ErrNodeState
		}
		result, err := q.ExecContext(c, "UPDATE sealed_tree_capacity_accounts SET encryption_id=?,sealed=? WHERE member_index=? AND encryption_id=?", newAccountID, accountSealed, accountIndex, accountID)
		if err != nil {
			return err
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			return store.ErrNodeState
		}
		result, err = q.ExecContext(c, "UPDATE cluster_storage_members SET reserved_bytes=reserved_bytes-? WHERE member_id=? AND reserved_bytes=?", capacity.Bytes, capacity.MemberID, member.Reserved)
		if err != nil {
			return err
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			return store.ErrNodeState
		}
		selected.State, selected.CompletionBinding = "cancelled", binding
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
		result, err = q.ExecContext(c, "UPDATE selected_upload_intents SET encryption_id=?,sealed=?,state='cancelled' WHERE operation_index=? AND encryption_id=? AND state='pending'", id, sealed, index, oldID)
		if err != nil {
			return err
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			return store.ErrNodeState
		}
		return c.Err()
	})
	if err != nil {
		return false, err
	}
	return already, nil
}
