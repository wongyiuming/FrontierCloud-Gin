package business

import (
	"context"
	"encoding/hex"
	"io"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/selectedupload"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// uploadRecordingAudioLocal is an unregistered trusted-Master composition.
// The caller must supply a real readiness gate, authenticated account/session
// check and the actual local Owner receiver. A failed or canceled call may have
// published bytes: retain the intent and reconcile rather than assuming that
// the upload or quota was rolled back. Remote Owner routing and cancellation
// are deliberately not provided here.
func (r *Repository) uploadRecordingAudioLocal(ctx context.Context, tree *sealedtree.SQLStore, key []byte, nodeVault *vault.Vault, gate SelectedUploadRuntimeGate, owner SelectedLocalOwner, userID, recordingID, action string, deadline selectedupload.ReadDeadline, body io.ReadCloser, audit store.KaraokeAudit, check func(context.Context, queryer, recordingAudioIntent) error) (bool, error) {
	return r.uploadRecordingAudioLocalChecked(ctx, tree, key, nodeVault, gate, owner, userID, recordingID, action, -1, deadline, body, audit, check, nil)
}

func (r *Repository) uploadRecordingAudioLocalChecked(ctx context.Context, tree *sealedtree.SQLStore, key []byte, nodeVault *vault.Vault, gate SelectedUploadRuntimeGate, owner SelectedLocalOwner, userID, recordingID, action string, contentLength int64, deadline selectedupload.ReadDeadline, body io.ReadCloser, audit store.KaraokeAudit, check func(context.Context, queryer, recordingAudioIntent) error, afterOwner func(context.Context) error) (bool, error) {
	if r == nil || ctx == nil || tree == nil || !validCapacityKey(key) || nodeVault == nil || selectedNil(gate) || selectedNil(owner) || !nodeIDPattern.MatchString(userID) || !nodeIDPattern.MatchString(recordingID) || (action != "upload" && action != "recover") || deadline == nil || body == nil || check == nil {
		return false, store.ErrRecordingState
	}
	if _, ok := ctx.Deadline(); !ok {
		return false, store.ErrRecordingState
	}
	lease, err := gate.AcquireSelectedUpload(ctx, tree)
	if err != nil || selectedNil(lease) {
		return false, store.ErrNodeState
	}
	defer lease.Release()
	if err = lease.Check(ctx); err != nil {
		return false, store.ErrNodeState
	}
	scope, _, err := r.bindRecordingAudioScope(ctx, tree, key, userID, recordingID, func(c context.Context, q queryer, intent recordingAudioIntent) error {
		if contentLength >= 0 && ((action == "upload" && contentLength != intent.Bytes) || (action == "recover" && contentLength != 0)) {
			return store.ErrRecordingState
		}
		return check(c, q, intent)
	})
	if err != nil {
		return false, err
	}
	var intent recordingAudioIntent
	err = r.withSelectedMutation(ctx, tree, func(c context.Context, q queryer, mutation *sealedtree.CoordinatedMutation) error {
		var found bool
		var e error
		intent, _, _, found, e = r.readRecordingAudioIntentTx(c, q, key, recordingID)
		if e != nil || !found || intent.State != "pending" || intent.UserID != userID || intent.MemberID != intent.MasterID || intent.OperationID != scope.OperationID || scope.RelationshipID != "" || scope.RelationshipBinding != "" || contentLength >= 0 && ((action == "upload" && contentLength != intent.Bytes) || (action == "recover" && contentLength != 0)) || check(c, q, intent) != nil || lease.Check(c) != nil {
			return store.ErrRecordingState
		}
		identity, e := readNode(c, q, r.lock())
		if e != nil || identity.ID != intent.MasterID || capacityMasterBinding(identity) != scope.MasterBinding {
			return store.ErrNodeState
		}
		binding, e := r.recordingAudioOwnerBinding(c, q, key, identity, intent.MemberID)
		if e != nil || binding != intent.OwnerBinding || mutation.CheckRecordingAudioBlobTx(c, q, intent.BlobID) != nil {
			return store.ErrNodeState
		}
		return c.Err()
	})
	if err != nil || lease.Check(ctx) != nil {
		return false, store.ErrRecordingState
	}
	alias := hex.EncodeToString(capacityMAC(key, "recording-audio-local-alias-v1", []byte(intent.OperationID)))
	meta := intent.Encryption
	claim := protocol.SelectedStorageUpload{
		Master: intent.MasterID, Owner: intent.MemberID, MediaID: alias, ObjectID: intent.BlobID,
		UploadID: intent.RecordingID, OperationID: intent.OperationID, Generation: scope.Generation,
		StageID: scope.StageID, PublishChallenge: scope.PublishChallenge, CleanupChallenge: scope.CleanupChallenge,
		ContentSHA256: intent.Digest, Size: intent.Bytes, Policy: "Local", Revision: 1, Encryption: &meta,
	}
	if alias == intent.BlobID || alias == intent.OperationID {
		return false, store.ErrRecordingState
	}
	receipt, signature, err := owner.SelectedLocalOperation(ctx, claim, deadline, body, action)
	if err != nil {
		return false, err
	}
	if err = lease.Check(ctx); err != nil {
		return false, store.ErrNodeState
	}
	if afterOwner != nil && afterOwner(ctx) != nil {
		return false, store.ErrRecordingState
	}
	return r.finalizeRecordingAudio(ctx, tree, key, nodeVault, userID, recordingID, receipt, signature, audit, func(c context.Context, q queryer, actual recordingAudioIntent) error {
		if e := lease.Check(c); e != nil {
			return e
		}
		return check(c, q, actual)
	})
}
