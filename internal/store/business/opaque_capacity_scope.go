package business

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/opaqueledger"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// OpaqueCapacityScope remains Master-only memory. Neither its existence nor
// a bound challenge proves that a source plan or physical object is valid.
type OpaqueCapacityScope struct {
	OperationID         string `json:"operation_id"`
	Generation          string `json:"generation"`
	StageID             string `json:"stage_id"`
	MasterBinding       string `json:"master_binding"`
	RelationshipID      string `json:"relationship_id"`
	RelationshipBinding string `json:"relationship_binding"`
	PublishChallenge    string `json:"publish_challenge"`
	CleanupChallenge    string `json:"cleanup_challenge"`
	// PublishedSignature is a persisted owner claim only; it does not settle
	// quota, prove source authorization, or make the pending tree visible.
	PublishedSignature string `json:"published_signature,omitempty"`
	// CleanupSignature is terminal: no published claim may be reactivated by
	// this scope after the owner has signed an exact stopped-and-cleaned claim.
	CleanupSignature string `json:"cleanup_signature,omitempty"`
	// Settled is written only in the same transaction as tree publication.
	Settled           bool   `json:"settled,omitempty"`
	CompletionBinding string `json:"completion_binding,omitempty"`
}

func capacityMasterBinding(identity store.NodeIdentity) string {
	raw, _ := json.Marshal(struct {
		ID      string `json:"id"`
		Sealed  string `json:"sealed_private"`
		Created int64  `json:"created_at"`
	}{identity.ID, identity.PrivateKey, identity.CreatedAt})
	defer clear(raw)
	h := sha256.New()
	h.Write([]byte("frontiercloud:sealed-tree:master-instance:v1\x00"))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}
func capacityChallengeIndex(key []byte, challenge string) string {
	return hex.EncodeToString(capacityMAC(key, "challenge", []byte(challenge)))
}
func capacityIDExists(ctx context.Context, q queryer, id, lock string) bool {
	var found string
	return q.QueryRowContext(ctx, "SELECT encryption_id FROM sealed_tree_capacity_ids WHERE encryption_id=?"+lock, id).Scan(&found) == nil && found == id
}

// capacityScopeSettled checks only the durable, authenticated ledger history.
// It does not revalidate the tree's keyed completion MAC or current owner
// signature; the combined tree recovery path must do that before activation.
func capacityScopeSettled(ctx context.Context, q queryer, key []byte, intent OpaqueCapacityIntent, identity store.NodeIdentity, lock string) (bool, error) {
	index := opaqueCapacityIndex(key, intent.OperationID)
	var id string
	var sealed []byte
	err := q.QueryRowContext(ctx, `SELECT encryption_id,sealed FROM sealed_tree_capacity_scopes WHERE operation_index=?`+lock, index).Scan(&id, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil || !capacityIDExists(ctx, q, id, lock) {
		return false, store.ErrNodeState
	}
	raw, err := openCapacityRecord(key, index, id, sealed)
	if err != nil {
		return false, store.ErrNodeState
	}
	defer clear(raw)
	var scope OpaqueCapacityScope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&scope) != nil || dec.Decode(new(any)) != io.EOF || scope.OperationID != intent.OperationID || scope.MasterBinding != capacityMasterBinding(identity) || !nodeHashPattern.MatchString(scope.Generation) || !nodeHashPattern.MatchString(scope.StageID) || !nodeHashPattern.MatchString(scope.PublishChallenge) || !nodeHashPattern.MatchString(scope.CleanupChallenge) || !capacityIDExists(ctx, q, capacityChallengeIndex(key, scope.PublishChallenge), lock) || !capacityIDExists(ctx, q, capacityChallengeIndex(key, scope.CleanupChallenge), lock) {
		return false, store.ErrNodeState
	}
	if !scope.Settled {
		if scope.CompletionBinding != "" {
			return false, store.ErrNodeState
		}
		return false, nil
	}
	if scope.PublishedSignature == "" || scope.CleanupSignature != "" || !nodeHashPattern.MatchString(scope.CompletionBinding) {
		return false, store.ErrNodeState
	}
	var completed int
	var object, blob, mac string
	if q.QueryRowContext(ctx, `SELECT completed,object_index,blob_index,receipt_mac FROM sealed_tree_operation_ids WHERE operation_id=?`+lock, intent.OperationID).Scan(&completed, &object, &blob, &mac) != nil || completed != 1 || opaqueledger.CompletionBinding(object, blob, mac) != scope.CompletionBinding {
		return false, store.ErrNodeState
	}
	for _, table := range []string{"sealed_tree_pending_files", "sealed_tree_pending_facts"} {
		var count int
		if q.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE operation_id=?`, intent.OperationID).Scan(&count) != nil || count != 0 {
			return false, store.ErrNodeState
		}
	}
	return true, nil
}

// BindOpaqueCapacityScope binds a verified stored reservation to a plan
// generation/stage and the currently paired owner. Call before acquiring an
// ingress shared lease. The caller must independently verify the plan and
// source identity. No owner request is signed or sent here.
func (r *Repository) BindOpaqueCapacityScope(ctx context.Context, key []byte, operation, generation, stage string) (OpaqueCapacityScope, bool, error) {
	var result OpaqueCapacityScope
	if ctx == nil || !validCapacityKey(key) || !nodeHashPattern.MatchString(operation) || !nodeHashPattern.MatchString(generation) || !nodeHashPattern.MatchString(stage) || operation == stage {
		return result, false, store.ErrNodeState
	}
	var existed bool
	err := r.ingressWrite(ctx, func(q queryer) error {
		existed = false
		if err := checkCapacityVerifier(ctx, q, key); err != nil {
			return err
		}
		identity, err := readNode(ctx, q, r.lock())
		if err != nil || identity.Role != "Master" || identity.PrivateKey == "" || identity.CreatedAt <= 0 {
			return store.ErrNodeState
		}
		index := opaqueCapacityIndex(key, operation)
		var selected int
		if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM selected_upload_intents WHERE operation_index=?", index).Scan(&selected); err != nil || selected != 0 {
			return store.ErrNodeState
		}
		var memberIndex, blobIndex, encID string
		var sealed []byte
		if err = q.QueryRowContext(ctx, "SELECT member_index,blob_index,encryption_id,sealed FROM sealed_tree_capacity_intents WHERE operation_index=?"+r.lock(), index).Scan(&memberIndex, &blobIndex, &encID, &sealed); err != nil {
			return store.ErrNodeState
		}
		intent, err := openOpaqueCapacity(key, index, encID, sealed)
		if err != nil || intent.MasterID != identity.ID || memberIndex != opaqueCapacityMemberIndex(key, intent.MemberID) || blobIndex != opaqueCapacityBlobIndex(key, intent.BlobID) || !capacityIDExists(ctx, q, encID, r.lock()) || stage == intent.BlobID {
			return store.ErrNodeState
		}
		member, err := scanMember(q.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?"+r.lock(), intent.MemberID))
		if err != nil {
			return store.ErrNodeState
		}
		account, _, ok, err := r.readOpaqueCapacityAccount(ctx, q, key, intent.MemberID, r.lock())
		if err != nil || !ok || account.Total < intent.Bytes || member.Reserved < account.Total {
			return store.ErrNodeState
		}
		result = OpaqueCapacityScope{OperationID: operation, Generation: generation, StageID: stage, MasterBinding: capacityMasterBinding(identity)}
		if member.ID == identity.ID {
			if member.Kind != "MasterLocal" || member.RelationshipID != nil {
				return store.ErrNodeState
			}
		} else {
			if member.Kind != "Follower" || member.RelationshipID == nil {
				return store.ErrNodeState
			}
			var peer, pub, endpoint, credential, direction, state string
			var version int
			var created int64
			if err = q.QueryRowContext(ctx, "SELECT peer_id,peer_key,peer_endpoint,credential,direction,state,protocol,created_at FROM node_relationships WHERE relationship_id=?"+r.lock(), *member.RelationshipID).Scan(&peer, &pub, &endpoint, &credential, &direction, &state, &version, &created); err != nil || peer != member.ID || direction != "downstream" || state != "active" || version != protocol.Version || endpoint == "" || credential == "" || created <= 0 {
				return store.ErrNodeState
			}
			if public, e := protocol.Decode(pub); e != nil || len(public) != 32 {
				return store.ErrNodeState
			}
			result.RelationshipID = *member.RelationshipID
			result.RelationshipBinding = store.PeerIngressBinding(store.PeerIngressEvidence{MemberID: peer, RelationshipID: *member.RelationshipID, PublicKey: pub, ControlEndpoint: endpoint, CredentialDigest: store.PeerCredentialDigest(credential), CreatedAt: created})
		}
		var scopeID string
		var scopeSealed []byte
		err = q.QueryRowContext(ctx, "SELECT encryption_id,sealed FROM sealed_tree_capacity_scopes WHERE operation_index=?"+r.lock(), index).Scan(&scopeID, &scopeSealed)
		if err == nil {
			raw, e := openCapacityRecord(key, index, scopeID, scopeSealed)
			if e != nil {
				return store.ErrNodeState
			}
			defer clear(raw)
			var old OpaqueCapacityScope
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if dec.Decode(&old) != nil || dec.Decode(new(any)) != io.EOF || old.OperationID != operation || old.Generation != generation || old.StageID != stage || old.MasterBinding != result.MasterBinding || old.RelationshipID != result.RelationshipID || old.RelationshipBinding != result.RelationshipBinding || !nodeHashPattern.MatchString(old.PublishChallenge) || !nodeHashPattern.MatchString(old.CleanupChallenge) || old.PublishChallenge == old.CleanupChallenge || old.PublishChallenge == operation || old.CleanupChallenge == operation || old.PublishChallenge == stage || old.CleanupChallenge == stage || old.PublishChallenge == intent.BlobID || old.CleanupChallenge == intent.BlobID || !capacityIDExists(ctx, q, scopeID, r.lock()) || !capacityIDExists(ctx, q, capacityChallengeIndex(key, old.PublishChallenge), r.lock()) || !capacityIDExists(ctx, q, capacityChallengeIndex(key, old.CleanupChallenge), r.lock()) {
				return store.ErrNodeState
			}
			result = old
			existed = true
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
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
		if result.PublishChallenge == result.CleanupChallenge || result.PublishChallenge == operation || result.CleanupChallenge == operation || result.PublishChallenge == stage || result.CleanupChallenge == stage || result.PublishChallenge == intent.BlobID || result.CleanupChallenge == intent.BlobID {
			return store.ErrNodeState
		}
		raw, err := json.Marshal(result)
		if err != nil {
			return err
		}
		defer clear(raw)
		scopeID, scopeSealed, err = sealCapacityRecord(key, index, raw)
		if err != nil {
			return err
		}
		for _, id := range []string{scopeID, capacityChallengeIndex(key, result.PublishChallenge), capacityChallengeIndex(key, result.CleanupChallenge)} {
			if _, err = q.ExecContext(ctx, "INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)", id); err != nil {
				return store.ErrNodeState
			}
		}
		if _, err = q.ExecContext(ctx, "INSERT INTO sealed_tree_capacity_scopes(operation_index,encryption_id,sealed) VALUES(?,?,?)", index, scopeID, scopeSealed); err != nil {
			return store.ErrNodeState
		}
		return nil
	})
	if err != nil {
		return OpaqueCapacityScope{}, false, err
	}
	return result, existed, nil
}
