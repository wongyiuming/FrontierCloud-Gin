package business

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/opaqueledger"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// RecordOpaquePublishedReceipt verifies an owner's exact signed publication
// claim against the durable reserved intent, source-generation scope and the
// current pinned Master/relationship instance in one repository transaction.
// It stores only the signature inside the encrypted scope: every signed field
// is deterministically reconstructed from that scope and intent on recovery.
// This is not source authorization, quota settlement, tree publication or a
// registered endpoint. The caller must hold all external source/identity
// fences in the agreed order and independently authenticate the source plan.
func (r *Repository) RecordOpaquePublishedReceipt(ctx context.Context, key []byte, nodeVault *vault.Vault, receipt protocol.OpaqueCapacityReceipt, signature string) (bool, error) {
	return r.recordOpaqueCapacityReceipt(ctx, key, nodeVault, receipt, signature, false)
}

// RecordOpaqueCleanedReceipt records an exact owner-signed terminal cleanup
// claim. The owner must first durably stop publication and drain in-flight
// work before signing; this call does not itself release reserved capacity.
func (r *Repository) RecordOpaqueCleanedReceipt(ctx context.Context, key []byte, nodeVault *vault.Vault, receipt protocol.OpaqueCapacityReceipt, signature string) (bool, error) {
	return r.recordOpaqueCapacityReceipt(ctx, key, nodeVault, receipt, signature, true)
}

func (r *Repository) recordOpaqueCapacityReceipt(ctx context.Context, key []byte, nodeVault *vault.Vault, receipt protocol.OpaqueCapacityReceipt, signature string, cleaned bool) (bool, error) {
	if ctx == nil || !validCapacityKey(key) || nodeVault == nil || signature == "" {
		return false, store.ErrNodeState
	}
	if _, err := receipt.Payload(); err != nil || !cleaned && (receipt.Kind != "opaque-capacity-published-v1" || receipt.State != "published") || cleaned && (receipt.Kind != "opaque-capacity-cleaned-v1" || receipt.State != "cleaned") {
		return false, store.ErrNodeState
	}
	var already bool
	err := r.ingressWrite(ctx, func(q queryer) error {
		already = false
		if !cleaned && opaqueledger.VerifyCandidate(ctx, q, key, nodeVault, receipt, signature, r.lock()) != nil {
			return store.ErrNodeState
		}
		if checkCapacityVerifier(ctx, q, key) != nil {
			return store.ErrNodeState
		}
		identity, err := readNode(ctx, q, r.lock())
		if err != nil || identity.Role != "Master" || identity.PrivateKey == "" || identity.CreatedAt <= 0 {
			return store.ErrNodeState
		}
		encoded, err := nodeVault.Unseal(identity.PrivateKey)
		if err != nil {
			return store.ErrNodeState
		}
		seed, err := protocol.Decode(encoded)
		if err != nil || len(seed) != ed25519.SeedSize {
			return store.ErrNodeState
		}
		defer clear(seed)
		private := ed25519.NewKeyFromSeed(seed)
		defer clear(private)
		masterPublic := protocol.Encode(private.Public().(ed25519.PublicKey))
		index := opaqueCapacityIndex(key, receipt.OperationID)
		var memberIndex, blobIndex, intentID string
		var intentSealed []byte
		if q.QueryRowContext(ctx, `SELECT member_index,blob_index,encryption_id,sealed FROM sealed_tree_capacity_intents WHERE operation_index=?`+r.lock(), index).Scan(&memberIndex, &blobIndex, &intentID, &intentSealed) != nil {
			return store.ErrNodeState
		}
		intent, err := openOpaqueCapacity(key, index, intentID, intentSealed)
		if err != nil || intent.MasterID != identity.ID || memberIndex != opaqueCapacityMemberIndex(key, intent.MemberID) || blobIndex != opaqueCapacityBlobIndex(key, intent.BlobID) || !capacityIDExists(ctx, q, intentID, r.lock()) {
			return store.ErrNodeState
		}
		var scopeID string
		var sealed []byte
		if q.QueryRowContext(ctx, `SELECT encryption_id,sealed FROM sealed_tree_capacity_scopes WHERE operation_index=?`+r.lock(), index).Scan(&scopeID, &sealed) != nil || !capacityIDExists(ctx, q, scopeID, r.lock()) {
			return store.ErrNodeState
		}
		raw, err := openCapacityRecord(key, index, scopeID, sealed)
		if err != nil {
			return store.ErrNodeState
		}
		defer clear(raw)
		var scope OpaqueCapacityScope
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&scope) != nil || decoder.Decode(new(any)) != io.EOF || scope.OperationID != intent.OperationID || scope.MasterBinding != capacityMasterBinding(identity) || !nodeHashPattern.MatchString(scope.Generation) || !nodeHashPattern.MatchString(scope.StageID) || !nodeHashPattern.MatchString(scope.PublishChallenge) || !nodeHashPattern.MatchString(scope.CleanupChallenge) || !capacityIDExists(ctx, q, capacityChallengeIndex(key, scope.PublishChallenge), r.lock()) || !capacityIDExists(ctx, q, capacityChallengeIndex(key, scope.CleanupChallenge), r.lock()) {
			return store.ErrNodeState
		}
		member, err := scanMember(q.QueryRowContext(ctx, `SELECT `+memberColumns+` FROM cluster_storage_members WHERE member_id=?`+r.lock(), intent.MemberID))
		if err != nil {
			return store.ErrNodeState
		}
		account, _, exists, err := r.readOpaqueCapacityAccount(ctx, q, key, intent.MemberID, r.lock())
		if err != nil || !exists || !scope.Settled && account.Total < intent.Bytes || member.Reserved < account.Total {
			return store.ErrNodeState
		}
		ownerPublic := masterPublic
		if intent.MemberID == identity.ID {
			if member.Kind != "MasterLocal" || member.RelationshipID != nil || scope.RelationshipID != "" || scope.RelationshipBinding != "" {
				return store.ErrNodeState
			}
		} else {
			if member.Kind != "Follower" || member.RelationshipID == nil || *member.RelationshipID != scope.RelationshipID {
				return store.ErrNodeState
			}
			var peer, pub, endpoint, credential, direction, state string
			var version int
			var created int64
			if q.QueryRowContext(ctx, `SELECT peer_id,peer_key,peer_endpoint,credential,direction,state,protocol,created_at FROM node_relationships WHERE relationship_id=?`+r.lock(), scope.RelationshipID).Scan(&peer, &pub, &endpoint, &credential, &direction, &state, &version, &created) != nil || peer != intent.MemberID || direction != "downstream" || state != "active" || version != protocol.Version || endpoint == "" || credential == "" || created <= 0 {
				return store.ErrNodeState
			}
			binding := store.PeerIngressBinding(store.PeerIngressEvidence{MemberID: peer, RelationshipID: scope.RelationshipID, PublicKey: pub, ControlEndpoint: endpoint, CredentialDigest: store.PeerCredentialDigest(credential), CreatedAt: created})
			if binding != scope.RelationshipBinding {
				return store.ErrNodeState
			}
			ownerPublic = pub
		}
		expected := protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-published-v1", MasterID: intent.MasterID, OwnerID: intent.MemberID, RelationshipID: scope.RelationshipID, RelationshipBinding: scope.RelationshipBinding, Generation: scope.Generation, OperationID: intent.OperationID, StageID: scope.StageID, BlobID: intent.BlobID, Digest: intent.Digest, Challenge: scope.PublishChallenge, Bytes: intent.Bytes, State: "published"}
		if cleaned {
			expected.Kind = "opaque-capacity-cleaned-v1"
			expected.State = "cleaned"
			expected.Challenge = scope.CleanupChallenge
		}
		if receipt != expected {
			return store.ErrNodeState
		}
		payload, err := expected.Payload()
		if err != nil || protocol.Verify(ownerPublic, payload, signature) != nil {
			return store.ErrNodeState
		}
		previous := scope.PublishedSignature
		if cleaned {
			if scope.Settled {
				return store.ErrNodeState
			}
			previous = scope.CleanupSignature
		} else if scope.CleanupSignature != "" {
			return store.ErrNodeState
		}
		if previous != "" {
			if previous != signature {
				return store.ErrNodeState
			}
			already = true
			return nil
		}
		if cleaned {
			scope.CleanupSignature = signature
		} else {
			scope.PublishedSignature = signature
		}
		updatedRaw, err := json.Marshal(scope)
		if err != nil {
			return store.ErrNodeState
		}
		defer clear(updatedRaw)
		newID, newSealed, err := sealCapacityRecord(key, index, updatedRaw)
		if err != nil {
			return err
		}
		if _, err = q.ExecContext(ctx, `INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)`, newID); err != nil {
			return store.ErrNodeState
		}
		result, err := q.ExecContext(ctx, `UPDATE sealed_tree_capacity_scopes SET encryption_id=?,sealed=? WHERE operation_index=? AND encryption_id=?`, newID, newSealed, index, scopeID)
		if err != nil {
			return err
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return store.ErrNodeState
		}
		return nil
	})
	return already, err
}
