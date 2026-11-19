package business

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/opaqueledger"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// recordRecordingAudioReceiptTx persists only a previously verified Owner
// signature, in the caller's tree/Owner/ingress fenced transaction. Its
// encrypted scope can be replayed after an interrupted finalization.
func (r *Repository) recordRecordingAudioReceiptTx(ctx context.Context, q queryer, key []byte, nodeVault *vault.Vault, intent recordingAudioIntent, receipt protocol.OpaqueCapacityReceipt, signature string) error {
	if opaqueledger.VerifyCandidate(ctx, q, key, nodeVault, receipt, signature, r.lock()) != nil || receipt.OperationID != intent.OperationID || receipt.MasterID != intent.MasterID || receipt.OwnerID != intent.MemberID || receipt.BlobID != intent.BlobID || receipt.Bytes != intent.Bytes || receipt.Digest != intent.Digest {
		return store.ErrRecordingState
	}
	index := opaqueCapacityIndex(key, intent.OperationID)
	var priorID string
	var sealed []byte
	if q.QueryRowContext(ctx, `SELECT encryption_id,sealed FROM sealed_tree_capacity_scopes WHERE operation_index=?`+r.lock(), index).Scan(&priorID, &sealed) != nil || !capacityIDExists(ctx, q, priorID, r.lock()) {
		return store.ErrRecordingState
	}
	raw, err := openCapacityRecord(key, index, priorID, sealed)
	if err != nil {
		return err
	}
	defer clear(raw)
	var scope OpaqueCapacityScope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&scope) != nil || dec.Decode(new(any)) != io.EOF || !recordingAudioScopeIDsValid(scope, intent.BlobID) || scope.OperationID != intent.OperationID || scope.CleanupSignature != "" {
		return store.ErrRecordingState
	}
	if scope.PublishedSignature != "" {
		if scope.PublishedSignature != signature {
			return store.ErrRecordingState
		}
		return nil
	}
	if scope.Settled || scope.CompletionBinding != "" {
		return store.ErrRecordingState
	}
	scope.PublishedSignature = signature
	updated, err := json.Marshal(scope)
	if err != nil {
		return err
	}
	defer clear(updated)
	id, next, err := sealCapacityRecord(key, index, updated)
	if err != nil {
		return err
	}
	if _, err = q.ExecContext(ctx, `INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)`, id); err != nil {
		return store.ErrRecordingState
	}
	result, err := q.ExecContext(ctx, `UPDATE sealed_tree_capacity_scopes SET encryption_id=?,sealed=? WHERE operation_index=? AND encryption_id=?`, id, next, index, priorID)
	if err != nil {
		return err
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return store.ErrRecordingState
	}
	return nil
}

// finalizeRecordingAudio is an unregistered coordinator. The trusted caller
// rechecks the account/session authorization under the same SQL transaction;
// a signed Owner receipt alone is not authorization to publish. No receipt,
// capacity settlement or ready state survives a later transaction failure.
func (r *Repository) finalizeRecordingAudio(ctx context.Context, tree *sealedtree.SQLStore, key []byte, nodeVault *vault.Vault, userID, recordingID string, receipt protocol.OpaqueCapacityReceipt, signature string, audit store.KaraokeAudit, check func(context.Context, queryer, recordingAudioIntent) error) (bool, error) {
	var already bool
	if r == nil || ctx == nil || tree == nil || !validCapacityKey(key) || nodeVault == nil || !nodeIDPattern.MatchString(userID) || !nodeIDPattern.MatchString(recordingID) || signature == "" || check == nil {
		return false, store.ErrRecordingState
	}
	err := r.withSelectedMutation(ctx, tree, func(c context.Context, q queryer, mutation *sealedtree.CoordinatedMutation) error {
		intent, _, _, found, err := r.readRecordingAudioIntentTx(c, q, key, recordingID)
		if err != nil || !found || intent.UserID != userID || check(c, q, intent) != nil {
			return store.ErrRecordingState
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
		if err != nil || row == nil || row.UserID != userID || row.MemberID != intent.MemberID || row.Bytes != intent.Bytes || row.State != intent.State {
			return store.ErrRecordingState
		}
		if intent.State == "ready" && (row.SHA256 == nil || *row.SHA256 != intent.Digest) {
			return store.ErrRecordingState
		}
		if err = mutation.CheckRecordingAudioBlobTx(c, q, intent.BlobID); err != nil {
			return err
		}
		if err = r.recordRecordingAudioReceiptTx(c, q, key, nodeVault, intent, receipt, signature); err != nil {
			return err
		}
		already, err = mutation.CompleteRecordingAudioTx(c, q, key, nodeVault, userID, recordingID, receipt, signature)
		if err != nil || already != (intent.State == "ready") {
			return store.ErrRecordingState
		}
		if !already {
			if err = r.markRecordingAudioReadyTx(c, q, key, intent); err != nil {
				return err
			}
			result, e := q.ExecContext(c, `UPDATE karaoke_recordings SET state='ready',sha256=?,updated_at=? WHERE recording_id=? AND user_id=? AND storage_member_id=? AND state='pending'`, intent.Digest, time.Now().Unix(), recordingID, userID, intent.MemberID)
			if e != nil {
				return e
			}
			if n, e := result.RowsAffected(); e != nil || n != 1 {
				return store.ErrRecordingState
			}
			audit.UserID, audit.Action, audit.Result = userID, "recording-finalize", "success"
			audit.Detail = map[string]any{"recording_id": recordingID, "size_bytes": intent.Bytes, "storage_member_id": intent.MemberID}
			if err = r.karaokeAudit(c, q, audit); err != nil {
				return err
			}
		}
		if err = check(c, q, intent); err != nil {
			return err
		}
		return c.Err()
	})
	if err != nil {
		return false, err
	}
	return already, nil
}
