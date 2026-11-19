package business

import (
	"context"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// issueSelectedDirectCapability is an unregistered building block. The caller
// must authenticate the current Admin and ensure check verifies that session
// in this transaction. Reauthentication after a restart may use a new session;
// the durable pending record and original operation are still checked here.
// The returned token is not exposed unless the read transaction commits.
func (r *Repository) issueSelectedDirectCapability(ctx context.Context, tree *sealedtree.SQLStore, key []byte, v *vault.Vault, uploadID, sessionHash, adminOrigin string, check func(context.Context, queryer, *sealedtree.CoordinatedMutation, sealedtree.SelectedPending, string) error) (string, error) {
	if r == nil || ctx == nil || tree == nil || v == nil || !validCapacityKey(key) || !nodeIDPattern.MatchString(uploadID) || !nodeHashPattern.MatchString(sessionHash) || check == nil {
		return "", store.ErrNodeState
	}
	var token string
	err := r.withSelectedMutation(ctx, tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
		selected, found, err := r.recoverSelectedOpaqueCapacityTx(c, q, key, uploadID)
		if err != nil || !found {
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
		identity, err := readNode(c, q, r.lock())
		if err != nil {
			return err
		}
		if err = r.selectedCapacityPreparation(c, key, capacity, selected.UploadID, selected.ParentID, selected.AdminBinding, selected.Policy, selected.Revision, pending.Admission.Origin, selected.PendingBinding)(q, identity); err != nil {
			return err
		}
		scope, found, err := r.selectedScopeTx(c, q, key, selected)
		if err != nil || !found || scope.Settled || scope.PublishedSignature != "" || scope.CleanupSignature != "" || scope.CompletionBinding != "" {
			return store.ErrNodeState
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
		token, err = protocol.SignSelectedStorageUpload(credential, claim, now)
		return err
	})
	if err != nil {
		return "", err
	}
	return token, nil
}
