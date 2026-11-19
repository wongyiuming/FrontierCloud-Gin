package business

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// selectedScopeTx only authenticates an existing selected scope against the
// Master intent. It does not turn an Owner claim into proof of stored bytes.
func (r *Repository) selectedScopeTx(ctx context.Context, q queryer, key []byte, selected selectedOpaqueIntent) (OpaqueCapacityScope, bool, error) {
	var zero OpaqueCapacityScope
	capacity := selected.Capacity.capacity()
	if ctx == nil || q == nil || !validCapacityKey(key) || !validOpaqueCapacity(capacity) {
		return zero, false, store.ErrNodeState
	}
	index := opaqueCapacityIndex(key, capacity.OperationID)
	var id string
	var sealed []byte
	err := q.QueryRowContext(ctx, "SELECT encryption_id,sealed FROM sealed_tree_capacity_scopes WHERE operation_index=?"+r.lock(), index).Scan(&id, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return zero, false, nil
	}
	if err != nil || !capacityIDExists(ctx, q, id, r.lock()) {
		return zero, false, store.ErrNodeState
	}
	raw, err := openCapacityRecord(key, index, id, sealed)
	if err != nil {
		return zero, false, store.ErrNodeState
	}
	defer clear(raw)
	var scope OpaqueCapacityScope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&scope) != nil || dec.Decode(new(any)) != io.EOF || scope.OperationID != capacity.OperationID || scope.MasterBinding != selected.MasterBinding || scope.RelationshipID != selected.RelationshipID || scope.RelationshipBinding != selected.RelationshipBinding || !nodeHashPattern.MatchString(scope.Generation) || !nodeHashPattern.MatchString(scope.StageID) || !nodeHashPattern.MatchString(scope.PublishChallenge) || !nodeHashPattern.MatchString(scope.CleanupChallenge) || scope.StageID == capacity.OperationID || scope.StageID == capacity.BlobID || scope.PublishChallenge == scope.CleanupChallenge || scope.PublishChallenge == scope.StageID || scope.CleanupChallenge == scope.StageID || scope.PublishChallenge == capacity.OperationID || scope.CleanupChallenge == capacity.OperationID || scope.PublishChallenge == capacity.BlobID || scope.CleanupChallenge == capacity.BlobID || !capacityIDExists(ctx, q, capacityChallengeIndex(key, scope.PublishChallenge), r.lock()) || !capacityIDExists(ctx, q, capacityChallengeIndex(key, scope.CleanupChallenge), r.lock()) {
		return zero, false, store.ErrNodeState
	}
	identity, err := readNode(ctx, q, r.lock())
	if err != nil || identity.Role != "Master" || identity.ID != capacity.MasterID || capacityMasterBinding(identity) != scope.MasterBinding {
		return zero, false, store.ErrNodeState
	}
	if selected.Policy == "Local" {
		if !validSelectedOwnerBinding(selected) || capacity.MemberID != identity.ID || scope.RelationshipID != "" || scope.RelationshipBinding != "" {
			return zero, false, store.ErrNodeState
		}
		return scope, true, nil
	}
	relation, err := scanRelation(q.QueryRowContext(ctx, "SELECT "+relationColumns+" FROM node_relationships WHERE relationship_id=?"+r.lock(), scope.RelationshipID))
	if err != nil || relation.ID != scope.RelationshipID || relation.PeerID != capacity.MemberID || relation.Direction != "downstream" || relation.State != "active" || relation.Protocol != protocol.Version || relation.Endpoint == "" || relation.Credential == "" || relation.CreatedAt <= 0 || store.PeerIngressBinding(store.PeerIngressEvidence{MemberID: relation.PeerID, RelationshipID: relation.ID, PublicKey: relation.PublicKey, ControlEndpoint: relation.Endpoint, CredentialDigest: store.PeerCredentialDigest(relation.Credential), CreatedAt: relation.CreatedAt}) != scope.RelationshipBinding {
		return zero, false, store.ErrNodeState
	}
	return scope, true, nil
}

// bindSelectedCapacityScope allocates stable random Owner publication and
// cleanup challenges for a previously committed selected reservation. The
// actual Admin admission and pending/Owner recovery checks remain mandatory;
// no route or byte transfer is registered by this private method.
func (r *Repository) bindSelectedCapacityScope(ctx context.Context, tree *sealedtree.SQLStore, key []byte, uploadID string, check func(context.Context, queryer, *sealedtree.CoordinatedMutation, sealedtree.SelectedPending) error) (OpaqueCapacityScope, bool, error) {
	var result OpaqueCapacityScope
	var already bool
	if r == nil || ctx == nil || tree == nil || !validCapacityKey(key) || !nodeIDPattern.MatchString(uploadID) || check == nil {
		return result, false, store.ErrNodeState
	}
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
		if err = check(c, q, m, pending); err != nil {
			return err
		}
		identity, err := readNode(c, q, r.lock())
		if err != nil {
			return err
		}
		if err = r.selectedCapacityPreparation(c, key, capacity, selected.UploadID, selected.ParentID, selected.AdminBinding, selected.Policy, selected.Revision, pending.Admission.Origin, selected.PendingBinding)(q, identity); err != nil {
			return err
		}
		result, already, err = r.selectedScopeTx(c, q, key, selected)
		if err != nil {
			return err
		}
		if already {
			if result.CleanupSignature != "" || result.PublishedSignature != "" || result.Settled || result.CompletionBinding != "" {
				return store.ErrNodeState
			}
			return nil
		}
		result = OpaqueCapacityScope{OperationID: capacity.OperationID, MasterBinding: selected.MasterBinding, RelationshipID: selected.RelationshipID, RelationshipBinding: selected.RelationshipBinding}
		result.Generation, err = randomID()
		if err != nil {
			return err
		}
		result.StageID, err = randomID()
		if err != nil {
			return err
		}
		result.PublishChallenge, err = randomID()
		if err != nil {
			return err
		}
		result.CleanupChallenge, err = randomID()
		if err != nil {
			return err
		}
		if result.StageID == capacity.OperationID || result.StageID == capacity.BlobID || result.PublishChallenge == result.CleanupChallenge || result.PublishChallenge == result.StageID || result.CleanupChallenge == result.StageID || result.PublishChallenge == capacity.OperationID || result.CleanupChallenge == capacity.OperationID || result.PublishChallenge == capacity.BlobID || result.CleanupChallenge == capacity.BlobID {
			return store.ErrNodeState
		}
		raw, err := json.Marshal(result)
		if err != nil {
			return store.ErrNodeState
		}
		defer clear(raw)
		index := opaqueCapacityIndex(key, capacity.OperationID)
		id, sealed, err := sealCapacityRecord(key, index, raw)
		if err != nil {
			return err
		}
		for _, v := range []string{id, capacityChallengeIndex(key, result.PublishChallenge), capacityChallengeIndex(key, result.CleanupChallenge)} {
			if _, err = q.ExecContext(c, "INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)", v); err != nil {
				return store.ErrNodeState
			}
		}
		if _, err = q.ExecContext(c, "INSERT INTO sealed_tree_capacity_scopes(operation_index,encryption_id,sealed) VALUES(?,?,?)", index, id, sealed); err != nil {
			return store.ErrNodeState
		}
		return nil
	})
	if err != nil {
		return OpaqueCapacityScope{}, false, err
	}
	return result, already, nil
}
