package business

import (
	"context"
	"encoding/json"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// CancelRecordingAudioDirect stops publication before asking the exact Owner
// to drain the operation and remove its staged bytes. The same signed cleanup
// can be retried after a lost response. Quota is released only once.
func (s *SelectedUploadRuntime) CancelRecordingAudioDirect(ctx context.Context, tree *sealedtree.SQLStore, expected store.PublicIngress, user store.KaraokeUser, browser, recordingID string, audit store.KaraokeAudit, checkAccount func(context.Context) error, send func(context.Context, string, string) (protocol.OpaqueCapacityReceipt, string, error)) (bool, error) {
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

	// A successful retry may arrive after the Owner is no longer reachable.
	already, err := s.settleRecordingAudioDirectCancel(ctx, expected, user, browser, sessionID, recordingID, audit, lease, protocol.OpaqueCapacityReceipt{}, "")
	if err != nil || already {
		return already, err
	}
	var owner recordingAudioDirectOwner
	var origin, capability string
	_, _, err = s.repo.bindRecordingAudioScopeChecked(ctx, tree, s.key, user.ID, recordingID, true, func(c context.Context, q queryer, intent recordingAudioIntent) error {
		var e error
		owner, e = s.checkRecordingAudioDirectIntent(c, q, expected, user, browser, sessionID, intent, lease)
		return e
	}, func(c context.Context, q queryer, intent recordingAudioIntent, scope OpaqueCapacityScope) error {
		if intent.State == "pending" {
			if e := s.repo.transitionRecordingAudioTx(c, q, s.key, intent, "pending", "cancel_pending"); e != nil {
				return e
			}
		}
		claim, e := recordingAudioCleanupClaim(s.key, intent, scope)
		if e != nil {
			return e
		}
		origin, capability, e = s.signRecordingAudioDirectCleanup(c, q, owner, expected, user.ID, browser, sessionID, claim)
		return e
	})
	if err != nil {
		return false, err
	}
	if checkAccount(ctx) != nil || lease.Check(ctx) != nil {
		return false, store.ErrRecordingState
	}
	receipt, signature, err := send(ctx, origin, capability)
	if err != nil {
		return false, err
	}
	if signature == "" || checkAccount(ctx) != nil || lease.Check(ctx) != nil {
		return false, store.ErrRecordingState
	}
	return s.settleRecordingAudioDirectCancel(ctx, expected, user, browser, sessionID, recordingID, audit, lease, receipt, signature)
}

func (s *SelectedUploadRuntime) settleRecordingAudioDirectCancel(ctx context.Context, expected store.PublicIngress, user store.KaraokeUser, browser, sessionID, recordingID string, audit store.KaraokeAudit, lease SelectedUploadRuntimeLease, receipt protocol.OpaqueCapacityReceipt, signature string) (bool, error) {
	var already bool
	err := s.repo.withSelectedMutation(ctx, s.tree, func(c context.Context, q queryer, mutation *sealedtree.CoordinatedMutation) error {
		master, err := s.checkRecordingAudioSessionTx(c, q, expected, user, browser, sessionID)
		if err != nil || lease.Check(c) != nil {
			return store.ErrRecordingState
		}
		intent, _, _, found, err := s.repo.readRecordingAudioIntentTx(c, q, s.key, recordingID)
		if err != nil || !found || intent.UserID != user.ID || intent.MasterID != master.ID || intent.MemberID == master.ID {
			return store.ErrRecordingState
		}
		row, err := recordingLookup(q.QueryRowContext(c, "SELECT "+recordingColumns+" FROM karaoke_recordings WHERE recording_id=?"+s.repo.lock(), recordingID))
		if err != nil || row == nil || row.UserID != user.ID || row.MemberID != intent.MemberID || row.Bytes != intent.Bytes || row.SHA256 != nil {
			return store.ErrRecordingState
		}
		if signature == "" && (intent.State == "pending" || intent.State == "cancel_pending") && row.State == "pending" {
			return c.Err()
		}
		if (intent.State != "cancel_pending" || row.State != "pending") && (intent.State != "cancelled" || row.State != "deleted") {
			return store.ErrRecordingState
		}
		scope, scopeID, err := s.repo.readRecordingAudioCleanupScopeTx(c, q, s.key, intent)
		if err != nil || scope.Settled || scope.CompletionBinding != "" || scope.PublishedSignature != "" {
			return store.ErrRecordingState
		}
		claim, err := recordingAudioCleanupClaim(s.key, intent, scope)
		if err != nil {
			return err
		}
		want := recordingAudioCleanupReceipt(claim)
		marker, err := recordingAudioCleanupMarker(s.key, want)
		if err != nil {
			return err
		}
		if intent.State == "cancelled" {
			if scope.CleanupSignature == "" || !capacityIDExists(c, q, marker, s.repo.lock()) ||
				signature != "" && (signature != scope.CleanupSignature || receipt != want) {
				return store.ErrRecordingState
			}
			already = true
			return c.Err()
		}
		if scope.CleanupSignature != "" || receipt != want || signature == "" {
			return store.ErrRecordingState
		}
		if _, err = s.checkRecordingAudioDirectIntent(c, q, expected, user, browser, sessionID, intent, lease); err != nil {
			return err
		}
		// The Owner receipt proves cleanup, and this check independently
		// proves publication never committed on the Master.
		if err = mutation.CheckUnstartedRecordingAudioTx(c, q, intent.Encryption, intent.Binding, intent.OperationID, intent.BlobID); err != nil {
			return err
		}
		payload, err := receipt.Payload()
		if err != nil {
			return store.ErrRecordingState
		}
		public, err := s.recordingAudioCleanupPublicKey(c, q, master, intent, claim)
		if err != nil || protocol.Verify(public, payload, signature) != nil {
			return store.ErrRecordingState
		}
		scope.CleanupSignature = signature
		if err = s.finishRecordingAudioDirectCancelTx(c, q, intent, scope, scopeID, marker, row.UpdatedAt, audit); err != nil {
			return err
		}
		if lease.Check(c) != nil {
			return store.ErrNodeState
		}
		return c.Err()
	})
	if err != nil {
		return false, err
	}
	return already, nil
}

func (s *SelectedUploadRuntime) finishRecordingAudioDirectCancelTx(c context.Context, q queryer, intent recordingAudioIntent, scope OpaqueCapacityScope, scopeID, marker string, updatedAt int64, audit store.KaraokeAudit) error {
	raw, err := json.Marshal(scope)
	if err != nil {
		return err
	}
	defer clear(raw)
	index := opaqueCapacityIndex(s.key, intent.OperationID)
	nextID, sealed, err := sealCapacityRecord(s.key, index, raw)
	if err != nil {
		return err
	}
	for _, id := range []string{marker, nextID} {
		if _, err = q.ExecContext(c, "INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)", id); err != nil {
			return store.ErrRecordingState
		}
	}
	changed, err := q.ExecContext(c, "UPDATE sealed_tree_capacity_scopes SET encryption_id=?,sealed=? WHERE operation_index=? AND encryption_id=?", nextID, sealed, index, scopeID)
	if err != nil {
		return err
	}
	if n, e := changed.RowsAffected(); e != nil || n != 1 {
		return store.ErrRecordingState
	}
	if err = s.repo.refundRecordingAudioReservationTx(c, q, s.key, intent); err != nil {
		return err
	}
	if err = s.repo.transitionRecordingAudioTx(c, q, s.key, intent, "cancel_pending", "cancelled"); err != nil {
		return err
	}
	changed, err = q.ExecContext(c, "UPDATE karaoke_recordings SET state='deleted',updated_at=? WHERE recording_id=? AND user_id=? AND storage_member_id=? AND state='pending' AND sha256 IS NULL AND updated_at=?", time.Now().Unix(), intent.RecordingID, intent.UserID, intent.MemberID, updatedAt)
	if err != nil {
		return err
	}
	if n, e := changed.RowsAffected(); e != nil || n != 1 {
		return store.ErrRecordingState
	}
	audit.UserID, audit.Action, audit.Result = intent.UserID, "recording-cancel", "success"
	audit.Detail = map[string]any{"recording_id": intent.RecordingID, "size_bytes": intent.Bytes}
	return s.repo.karaokeAudit(c, q, audit)
}
