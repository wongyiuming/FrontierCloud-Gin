package business

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// ErrRecordingNotDirect permits an existing Local handler to handle only an
// authenticated, exact recording row already placed on the Master.
var ErrRecordingNotDirect = errors.New("recording uses Master local storage")

// DeleteRecordingAudioDirect hides a completed recording before contacting its
// exact Owner. The Owner's signed cleanup receipt settles quota once. Failure
// leaves deleting state for the same account to retry. Pending reservations
// have a separate cancellation lifecycle and cannot use this operation.
func (s *SelectedUploadRuntime) DeleteRecordingAudioDirect(ctx context.Context, tree *sealedtree.SQLStore, expected store.PublicIngress, user store.KaraokeUser, browser, recordingID string, audit store.KaraokeAudit, checkAccount func(context.Context) error, send func(context.Context, string, string) (protocol.OpaqueCapacityReceipt, string, error)) (bool, error) {
	if ctx == nil || checkAccount == nil || send == nil || !nodeIDPattern.MatchString(recordingID) || checkAccount(ctx) != nil {
		return false, store.ErrRecordingState
	}
	actualBrowser, sessionID, _, valid := mediacrypto.DirectSessionFromContext(ctx).Values()
	if !valid || actualBrowser != browser {
		return false, store.ErrRecordingState
	}
	lease, err := s.recordingAudioDirectLease(ctx, tree)
	if err != nil {
		return false, err
	}
	defer lease.Release()
	_, _, done, err := s.recordingAudioDirectCleanupTicket(ctx, expected, user, browser, sessionID, recordingID, lease, false)
	if err != nil {
		return false, err
	}
	if checkAccount(ctx) != nil || lease.Check(ctx) != nil {
		return false, store.ErrRecordingState
	}
	if done {
		return true, nil
	}
	check := func(c context.Context, q queryer, intent recordingAudioIntent) error {
		_, err := s.checkRecordingAudioDirectIntent(c, q, expected, user, browser, sessionID, intent, lease)
		return err
	}
	if _, err = s.stageRecordingAudioDeletionChecked(ctx, tree, user.ID, recordingID, audit, check); err != nil {
		return false, err
	}
	origin, capability, done, err := s.recordingAudioDirectCleanupTicket(ctx, expected, user, browser, sessionID, recordingID, lease, true)
	if err != nil {
		return false, err
	}
	if checkAccount(ctx) != nil || lease.Check(ctx) != nil {
		return false, store.ErrRecordingState
	}
	if done {
		return true, nil
	}
	receipt, signature, err := send(ctx, origin, capability)
	if err != nil {
		return false, err
	}
	if checkAccount(ctx) != nil || lease.Check(ctx) != nil {
		return false, store.ErrRecordingState
	}
	already, err := s.finishRecordingAudioDeletionChecked(ctx, tree, user.ID, recordingID, receipt, signature, audit, check)
	if err != nil {
		return false, err
	}
	if checkAccount(ctx) != nil || lease.Check(ctx) != nil {
		return false, store.ErrRecordingState
	}
	return already, nil
}

func (s *SelectedUploadRuntime) recordingAudioDirectCleanupTicket(ctx context.Context, expected store.PublicIngress, user store.KaraokeUser, browser, sessionID, recordingID string, lease SelectedUploadRuntimeLease, issue bool) (string, string, bool, error) {
	var origin, capability string
	var done bool
	err := s.repo.withSelectedMutation(ctx, s.tree, func(c context.Context, q queryer, mutation *sealedtree.CoordinatedMutation) error {
		master, err := s.checkRecordingAudioSessionTx(c, q, expected, user, browser, sessionID)
		if err != nil || lease.Check(c) != nil {
			return store.ErrRecordingState
		}
		intent, _, _, found, err := s.repo.readRecordingAudioIntentTx(c, q, s.key, recordingID)
		if err != nil || !found || intent.UserID != user.ID || intent.MasterID != master.ID {
			return store.ErrRecordingState
		}
		row, err := recordingLookup(q.QueryRowContext(c, "SELECT "+recordingColumns+" FROM karaoke_recordings WHERE recording_id=?"+s.repo.lock(), recordingID))
		if err != nil || row == nil || row.UserID != user.ID || row.MemberID != intent.MemberID || row.Bytes != intent.Bytes || row.State != intent.State {
			return store.ErrRecordingState
		}
		if intent.MemberID == master.ID {
			return ErrRecordingNotDirect
		}
		if (intent.State != "ready" && intent.State != "deleting" && intent.State != "deleted") ||
			row.SHA256 == nil || *row.SHA256 != intent.Digest ||
			mutation.CheckRecordingAudioCompletionTx(c, q, intent.UserID, intent.RecordingID, intent.OperationID, intent.BlobID) != nil {
			return store.ErrRecordingState
		}
		if intent.State == "ready" || intent.State == "deleting" && !issue {
			return c.Err()
		}
		claim, err := s.repo.recordingAudioCleanupClaimTx(c, q, s.key, intent)
		if err != nil {
			return err
		}
		if intent.State == "deleted" {
			marker, err := recordingAudioCleanupMarker(s.key, recordingAudioCleanupReceipt(claim))
			if err != nil || !capacityIDExists(c, q, marker, s.repo.lock()) {
				return store.ErrRecordingState
			}
			done = true
			return c.Err()
		}
		owner, err := s.checkRecordingAudioDirectIntent(c, q, expected, user, browser, sessionID, intent, lease)
		if err != nil {
			return err
		}
		origin, capability, err = s.signRecordingAudioDirectCleanup(c, q, owner, expected, user.ID, browser, sessionID, claim)
		return err
	})
	if err != nil {
		return "", "", false, err
	}
	return origin, capability, done, nil
}

func (s *SelectedUploadRuntime) signRecordingAudioDirectCleanup(c context.Context, q queryer, owner recordingAudioDirectOwner, expected store.PublicIngress, userID, browser, sessionID string, claim protocol.SelectedStorageUpload) (string, string, error) {
	if owner.member.RelationshipID == nil || *owner.member.RelationshipID != claim.Relationship {
		return "", "", store.ErrNodeState
	}
	relation, err := scanRelation(q.QueryRowContext(c, "SELECT "+relationColumns+" FROM node_relationships WHERE relationship_id=?"+s.repo.lock(), claim.Relationship))
	if err != nil || relation.PeerID != claim.Owner {
		return "", "", store.ErrNodeState
	}
	credential, err := s.vault.Unseal(relation.Credential)
	if err != nil {
		return "", "", store.ErrNodeState
	}
	_, _, sessionExpiry, valid := mediacrypto.DirectSessionFromContext(c).Values()
	now := time.Now().Unix()
	if !valid || sessionExpiry <= now {
		return "", "", store.ErrRecordingState
	}
	association, err := json.Marshal([4]string{userID, browser, sessionID, claim.OperationID})
	if err != nil {
		return "", "", err
	}
	defer clear(association)
	origin := owner.policy.AppliedOrigin
	claim.ResourceOrigin, claim.AdminOrigin = origin, expected.PublicOrigin
	claim.AdminBinding = hex.EncodeToString(capacityMAC(s.key, "recording-audio-direct-session-v1", association))
	claim.RecordingIngressNode, claim.RecordingIngressGeneration = expected.NodeID, expected.Generation
	claim.Revision, claim.ExpiresAt = owner.policy.Revision, min(now+protocol.TokenSeconds, sessionExpiry)
	capability, err := protocol.SignSelectedRecordingCleanup(credential, claim, now)
	return origin, capability, err
}
