package business

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// bindRecordingAudioScope ties the previously committed recording intent to a
// durable Owner stage and distinct publication/cleanup challenges. It holds
// the same fences as reservation and requires fresh account authorization.
// This is not an Owner capability or proof that bytes exist.
func (r *Repository) bindRecordingAudioScope(ctx context.Context, tree *sealedtree.SQLStore, key []byte, userID, recordingID string, check func(context.Context, queryer, recordingAudioIntent) error) (OpaqueCapacityScope, bool, error) {
	return r.bindRecordingAudioScopeChecked(ctx, tree, key, userID, recordingID, false, check, nil)
}

func (r *Repository) bindRecordingAudioScopeChecked(ctx context.Context, tree *sealedtree.SQLStore, key []byte, userID, recordingID string, cancel bool, check func(context.Context, queryer, recordingAudioIntent) error, issue func(context.Context, queryer, recordingAudioIntent, OpaqueCapacityScope) error) (OpaqueCapacityScope, bool, error) {
	var result OpaqueCapacityScope
	var already bool
	if r == nil || ctx == nil || tree == nil || !validCapacityKey(key) || !nodeIDPattern.MatchString(userID) || !nodeIDPattern.MatchString(recordingID) || check == nil {
		return result, false, store.ErrRecordingState
	}
	err := r.withSelectedMutation(ctx, tree, func(c context.Context, q queryer, mutation *sealedtree.CoordinatedMutation) error {
		intent, _, _, found, err := r.readRecordingAudioIntentTx(c, q, key, recordingID)
		if err != nil || !found || (intent.State != "pending" && !(cancel && intent.State == "cancel_pending")) || intent.UserID != userID || check(c, q, intent) != nil {
			return store.ErrRecordingState
		}
		if err = mutation.CheckRecordingAudioBlobTx(c, q, intent.BlobID); err != nil {
			return err
		}
		identity, err := readNode(c, q, r.lock())
		if err != nil || identity.ID != intent.MasterID {
			return store.ErrNodeState
		}
		binding, err := r.recordingAudioOwnerBinding(c, q, key, identity, intent.MemberID)
		if err != nil || binding != intent.OwnerBinding {
			return store.ErrNodeState
		}
		user, err := scanUser(q.QueryRowContext(c, "SELECT "+userColumns+" FROM karaoke_users WHERE user_id=?"+r.lock(), userID))
		if err != nil || user.Status != "active" || user.Used < intent.Bytes || user.Quota < user.Used {
			return store.ErrRecordingState
		}
		row, err := recordingLookup(q.QueryRowContext(c, "SELECT "+recordingColumns+" FROM karaoke_recordings WHERE recording_id=?"+r.lock(), recordingID))
		if err != nil || row == nil || row.UserID != userID || row.MemberID != intent.MemberID || row.State != "pending" || row.Bytes != intent.Bytes {
			return store.ErrRecordingState
		}
		capacity := OpaqueCapacityIntent{OperationID: intent.OperationID, MasterID: intent.MasterID, MemberID: intent.MemberID, BlobID: intent.BlobID, Digest: intent.Digest, Bytes: intent.Bytes}
		index := opaqueCapacityIndex(key, capacity.OperationID)
		encID, sealed, err := sealOpaqueCapacity(key, index, capacity)
		if err != nil {
			return err
		}
		prior, err := r.reserveOpaqueCapacityTx(c, q, key, capacity, 0, func(queryer, store.NodeIdentity) error { return nil }, index, encID, sealed, false)
		if err != nil || !prior {
			return store.ErrRecordingState
		}
		result = OpaqueCapacityScope{OperationID: capacity.OperationID, MasterBinding: capacityMasterBinding(identity)}
		if intent.MemberID != identity.ID {
			member, e := scanMember(q.QueryRowContext(c, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?"+r.lock(), intent.MemberID))
			if e != nil || member.Kind != "Follower" || member.RelationshipID == nil {
				return store.ErrNodeState
			}
			relation, e := scanRelation(q.QueryRowContext(c, "SELECT "+relationColumns+" FROM node_relationships WHERE relationship_id=?"+r.lock(), *member.RelationshipID))
			if e != nil {
				return store.ErrNodeState
			}
			result.RelationshipID = relation.ID
			result.RelationshipBinding = store.PeerIngressBinding(store.PeerIngressEvidence{MemberID: relation.PeerID, RelationshipID: relation.ID, PublicKey: relation.PublicKey, ControlEndpoint: relation.Endpoint, CredentialDigest: store.PeerCredentialDigest(relation.Credential), CreatedAt: relation.CreatedAt})
		}
		var scopeID string
		var scopeSealed []byte
		err = q.QueryRowContext(c, `SELECT encryption_id,sealed FROM sealed_tree_capacity_scopes WHERE operation_index=?`+r.lock(), index).Scan(&scopeID, &scopeSealed)
		if err == nil {
			if !capacityIDExists(c, q, scopeID, r.lock()) {
				return store.ErrNodeState
			}
			raw, e := openCapacityRecord(key, index, scopeID, scopeSealed)
			if e != nil {
				return e
			}
			defer clear(raw)
			var old OpaqueCapacityScope
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if dec.Decode(&old) != nil || dec.Decode(new(any)) != io.EOF || old.OperationID != result.OperationID || old.MasterBinding != result.MasterBinding || old.RelationshipID != result.RelationshipID || old.RelationshipBinding != result.RelationshipBinding || !recordingAudioScopeIDsValid(old, intent.BlobID) || old.Settled || old.CompletionBinding != "" || old.PublishedSignature != "" || old.CleanupSignature != "" || !capacityIDExists(c, q, capacityChallengeIndex(key, old.PublishChallenge), r.lock()) || !capacityIDExists(c, q, capacityChallengeIndex(key, old.CleanupChallenge), r.lock()) {
				return store.ErrNodeState
			}
			result, already = old, true
		} else {
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if intent.State != "pending" {
				return store.ErrRecordingState
			}
			for _, dst := range []*string{&result.Generation, &result.StageID, &result.PublishChallenge, &result.CleanupChallenge} {
				if *dst, err = randomID(); err != nil {
					return err
				}
			}
			if !recordingAudioScopeIDsValid(result, intent.BlobID) {
				return store.ErrNodeState
			}
			raw, e := json.Marshal(result)
			if e != nil {
				return e
			}
			defer clear(raw)
			scopeID, scopeSealed, e = sealCapacityRecord(key, index, raw)
			if e != nil {
				return e
			}
			for _, id := range []string{scopeID, capacityChallengeIndex(key, result.PublishChallenge), capacityChallengeIndex(key, result.CleanupChallenge)} {
				if _, e = q.ExecContext(c, `INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)`, id); e != nil {
					return store.ErrNodeState
				}
			}
			if _, e = q.ExecContext(c, `INSERT INTO sealed_tree_capacity_scopes(operation_index,encryption_id,sealed) VALUES(?,?,?)`, index, scopeID, scopeSealed); e != nil {
				return store.ErrNodeState
			}
		}
		if err = check(c, q, intent); err != nil {
			return err
		}
		if issue != nil {
			return issue(c, q, intent, result)
		}
		return c.Err()
	})
	if err != nil {
		return OpaqueCapacityScope{}, false, err
	}
	return result, already, nil
}

func recordingAudioScopeIDsValid(scope OpaqueCapacityScope, blob string) bool {
	ids := []string{scope.OperationID, blob, scope.Generation, scope.StageID, scope.PublishChallenge, scope.CleanupChallenge}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !nodeHashPattern.MatchString(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}
