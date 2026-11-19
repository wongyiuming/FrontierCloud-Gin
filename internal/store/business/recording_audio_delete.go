package business

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// recordingAudioCleanupClaimTx reconstructs the exact originally published
// Owner operation from already authenticated deleting state. The caller
// must first verify the Owner signature/tree completion and must not accept a
// claim or blob path from the browser.
func (r *Repository) recordingAudioCleanupClaimTx(ctx context.Context, q queryer, key []byte, intent recordingAudioIntent) (protocol.SelectedStorageUpload, error) {
	var zero protocol.SelectedStorageUpload
	if (intent.State != "deleting" && intent.State != "deleted") || !validRecordingAudioIntent(intent) {
		return zero, store.ErrRecordingState
	}
	scope, _, err := r.readRecordingAudioCleanupScopeTx(ctx, q, key, intent)
	if err != nil || !scope.Settled || scope.PublishedSignature == "" || scope.CleanupSignature != "" {
		return zero, store.ErrRecordingState
	}
	return recordingAudioCleanupClaim(key, intent, scope)
}

func (r *Repository) readRecordingAudioCleanupScopeTx(ctx context.Context, q queryer, key []byte, intent recordingAudioIntent) (OpaqueCapacityScope, string, error) {
	index := opaqueCapacityIndex(key, intent.OperationID)
	var id string
	var sealed []byte
	if q.QueryRowContext(ctx, `SELECT encryption_id,sealed FROM sealed_tree_capacity_scopes WHERE operation_index=?`+r.lock(), index).Scan(&id, &sealed) != nil || !capacityIDExists(ctx, q, id, r.lock()) {
		return OpaqueCapacityScope{}, "", store.ErrRecordingState
	}
	raw, err := openCapacityRecord(key, index, id, sealed)
	if err != nil {
		return OpaqueCapacityScope{}, "", store.ErrRecordingState
	}
	defer clear(raw)
	var scope OpaqueCapacityScope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&scope) != nil || dec.Decode(new(any)) != io.EOF || !recordingAudioScopeIDsValid(scope, intent.BlobID) || scope.OperationID != intent.OperationID ||
		!capacityIDExists(ctx, q, capacityChallengeIndex(key, scope.PublishChallenge), r.lock()) ||
		!capacityIDExists(ctx, q, capacityChallengeIndex(key, scope.CleanupChallenge), r.lock()) {
		return OpaqueCapacityScope{}, "", store.ErrRecordingState
	}
	master, err := readNode(ctx, q, r.lock())
	if err != nil || master.Role != "Master" || master.ID != intent.MasterID || scope.MasterBinding != capacityMasterBinding(master) {
		return OpaqueCapacityScope{}, "", store.ErrNodeState
	}
	return scope, id, nil
}

func recordingAudioCleanupClaim(key []byte, intent recordingAudioIntent, scope OpaqueCapacityScope) (protocol.SelectedStorageUpload, error) {
	var zero protocol.SelectedStorageUpload
	var alias, transport string
	var revision int64
	if intent.MemberID == intent.MasterID {
		if scope.RelationshipID != "" || scope.RelationshipBinding != "" {
			return zero, store.ErrRecordingState
		}
		alias = hex.EncodeToString(capacityMAC(key, "recording-audio-local-alias-v1", []byte(intent.OperationID)))
		transport, revision = "Local", 1
	} else {
		if !nodeIDPattern.MatchString(scope.RelationshipID) || !nodeHashPattern.MatchString(scope.RelationshipBinding) {
			return zero, store.ErrRecordingState
		}
		alias = recordingAudioDirectAlias(key, intent.OperationID)
		transport = "Direct"
	}
	if alias == intent.BlobID || alias == intent.OperationID {
		return zero, store.ErrRecordingState
	}
	meta := intent.Encryption
	return protocol.SelectedStorageUpload{Master: intent.MasterID, Owner: intent.MemberID, MediaID: alias,
		ObjectID: intent.BlobID, UploadID: intent.RecordingID, OperationID: intent.OperationID, Generation: scope.Generation,
		StageID: scope.StageID, PublishChallenge: scope.PublishChallenge, CleanupChallenge: scope.CleanupChallenge,
		ContentSHA256: intent.Digest, Size: intent.Bytes, Policy: transport, Revision: revision, Encryption: &meta,
		Relationship: scope.RelationshipID, RelationshipBinding: scope.RelationshipBinding}, nil
}

// stageRecordingAudioDeletion is deliberately private and not registered. It
// durably blocks new reads, but it does not remove Owner bytes, refund quota,
// or constitute a completed deletion. Those steps need a separate guarded
// Owner cleanup and restart reconciliation before a product route can use it.
func (s *SelectedUploadRuntime) stageRecordingAudioDeletion(ctx context.Context, tree *sealedtree.SQLStore, expected store.PublicIngress, user store.KaraokeUser, browser, recordingID string, audit store.KaraokeAudit, checkAccount func(context.Context) error) (bool, error) {
	if s == nil || s.repo == nil || ctx == nil || tree == nil || tree != s.tree || s.crypto == nil || s.vault == nil || selectedNil(s.gate) || checkAccount == nil || checkAccount(ctx) != nil {
		return false, store.ErrRecordingState
	}
	actualBrowser, sessionID, _, valid := mediacrypto.DirectSessionFromContext(ctx).Values()
	if !valid || actualBrowser != browser {
		return false, store.ErrRecordingState
	}
	lease, err := s.gate.AcquireSelectedUpload(ctx, tree)
	if err != nil || selectedNil(lease) {
		return false, store.ErrNodeState
	}
	defer lease.Release()
	if lease.Check(ctx) != nil {
		return false, store.ErrNodeState
	}
	if _, err := store.RecordingAudioPreparationBinding(user.ID, browser, recordingID); err != nil {
		return false, err
	}
	return s.stageRecordingAudioDeletionChecked(ctx, tree, user.ID, recordingID, audit, func(c context.Context, q queryer, intent recordingAudioIntent) error {
		if lease.Check(c) != nil {
			return store.ErrRecordingState
		}
		return s.checkRecordingAudioAuthorityTx(c, q, expected, user, browser, sessionID, intent.MemberID)
	})
}

func (s *SelectedUploadRuntime) stageRecordingAudioDeletionChecked(ctx context.Context, tree *sealedtree.SQLStore, userID, recordingID string, audit store.KaraokeAudit, check func(context.Context, queryer, recordingAudioIntent) error) (bool, error) {
	already := false
	err := s.repo.WithOwnerControlExclusive(ctx, func(held context.Context) error {
		var intent recordingAudioIntent
		ready, e := s.recordingAudioReadyChecked(held, userID, recordingID, &intent, nil, true, check, nil)
		if e != nil || !ready {
			return store.ErrRecordingState
		}
		if intent.State == "deleting" {
			already = true
			return nil
		}
		return s.repo.withSelectedMutation(held, tree, func(c context.Context, q queryer, mutation *sealedtree.CoordinatedMutation) error {
			current, _, _, found, e := s.repo.readRecordingAudioIntentTx(c, q, s.key, recordingID)
			if e != nil || !found || current != intent || current.State != "ready" || check(c, q, current) != nil || mutation.CheckRecordingAudioCompletionTx(c, q, intent.UserID, intent.RecordingID, intent.OperationID, intent.BlobID) != nil {
				return store.ErrRecordingState
			}
			if e = s.repo.transitionRecordingAudioTx(c, q, s.key, intent, "ready", "deleting"); e != nil {
				return e
			}
			changed, e := q.ExecContext(c, `UPDATE karaoke_recordings SET state='deleting',updated_at=? WHERE recording_id=? AND user_id=? AND storage_member_id=? AND state='ready' AND sha256=?`, time.Now().Unix(), recordingID, userID, intent.MemberID, intent.Digest)
			if e != nil {
				return e
			}
			if n, e := changed.RowsAffected(); e != nil || n != 1 {
				return store.ErrRecordingState
			}
			audit.UserID, audit.Action, audit.Result = userID, "recording-delete", "pending"
			audit.Detail = map[string]any{"recording_id": recordingID}
			if e = s.repo.karaokeAudit(c, q, audit); e != nil {
				return e
			}
			if check(c, q, intent) != nil {
				return store.ErrRecordingState
			}
			return c.Err()
		})
	})
	return already, err
}
