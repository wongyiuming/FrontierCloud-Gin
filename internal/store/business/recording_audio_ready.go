package business

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/opaqueledger"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// recordingAudioReady checks a previously settled recording against its
// encrypted intent, exact Owner signature and authenticated tree completion.
// The caller must independently authorize the current account and browser.
func (s *SelectedUploadRuntime) recordingAudioReady(ctx context.Context, expected store.PublicIngress, user store.KaraokeUser, browser, sessionID, recordingID string) (bool, error) {
	return s.recordingAudioReadyWithInfo(ctx, expected, user, browser, sessionID, recordingID, nil, nil, false, false)
}

func (s *SelectedUploadRuntime) recordingAudioReadyWithInfo(ctx context.Context, expected store.PublicIngress, user store.KaraokeUser, browser, sessionID, recordingID string, out *recordingAudioIntent, titleOut *string, allowAnotherBrowser, allowDeleting bool) (bool, error) {
	binding, err := store.RecordingAudioPreparationBinding(user.ID, browser, recordingID)
	if err != nil {
		return false, store.ErrRecordingState
	}
	return s.recordingAudioReadyChecked(ctx, user.ID, recordingID, out, titleOut, allowDeleting, func(c context.Context, q queryer, intent recordingAudioIntent) error {
		if (!allowAnotherBrowser && intent.Binding != binding) || intent.MemberID != intent.MasterID {
			return store.ErrRecordingState
		}
		return s.checkRecordingAudioAuthorityTx(c, q, expected, user, browser, sessionID, intent.MemberID)
	}, nil)
}

func (s *SelectedUploadRuntime) recordingAudioReadyChecked(ctx context.Context, userID, recordingID string, out *recordingAudioIntent, titleOut *string, allowDeleting bool, check, admit func(context.Context, queryer, recordingAudioIntent) error) (bool, error) {
	ready := false
	err := s.repo.withSelectedMutation(ctx, s.tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
		intent, title, _, found, e := s.repo.readRecordingAudioIntentTx(c, q, s.key, recordingID)
		if e != nil || !found || intent.UserID != userID || check(c, q, intent) != nil {
			return store.ErrRecordingState
		}
		row, e := recordingLookup(q.QueryRowContext(c, "SELECT "+recordingColumns+" FROM karaoke_recordings WHERE recording_id=?"+s.repo.lock(), recordingID))
		if e != nil || row == nil || row.UserID != userID || row.MemberID != intent.MemberID || row.State != intent.State || row.Bytes != intent.Bytes {
			return store.ErrRecordingState
		}
		if intent.State == "pending" {
			return c.Err()
		}
		if !(intent.State == "ready" || allowDeleting && intent.State == "deleting") || row.SHA256 == nil || *row.SHA256 != intent.Digest || m.CheckRecordingAudioCompletionTx(c, q, intent.UserID, intent.RecordingID, intent.OperationID, intent.BlobID) != nil {
			return store.ErrRecordingState
		}
		if _, _, err := s.repo.verifyRecordingAudioPublishedTx(c, q, s.key, s.vault, intent); err != nil || check(c, q, intent) != nil {
			return store.ErrRecordingState
		}
		if admit != nil {
			if err := admit(c, q, intent); err != nil {
				return err
			}
		}
		ready = true
		if out != nil {
			*out = intent
		}
		if titleOut != nil {
			*titleOut = title
		}
		return c.Err()
	})
	return ready, err
}

// verifyRecordingAudioPublishedTx reuses the recording's bound capacity scope
// and verifies the exact persisted Owner publication in a caller-owned SQL
// snapshot. The caller checks the separate tree completion and business row.
func (r *Repository) verifyRecordingAudioPublishedTx(ctx context.Context, q queryer, key []byte, nodeVault *vault.Vault, intent recordingAudioIntent) (OpaqueCapacityScope, protocol.OpaqueCapacityReceipt, error) {
	var zero protocol.OpaqueCapacityReceipt
	scope, _, err := r.readRecordingAudioCleanupScopeTx(ctx, q, key, intent)
	if err != nil || !scope.Settled || scope.PublishedSignature == "" || scope.CleanupSignature != "" {
		return OpaqueCapacityScope{}, zero, store.ErrRecordingState
	}
	receipt := protocol.OpaqueCapacityReceipt{
		Kind: "opaque-capacity-published-v1", MasterID: intent.MasterID, OwnerID: intent.MemberID,
		RelationshipID: scope.RelationshipID, RelationshipBinding: scope.RelationshipBinding,
		Generation: scope.Generation, OperationID: intent.OperationID, StageID: scope.StageID,
		BlobID: intent.BlobID, Digest: intent.Digest, Challenge: scope.PublishChallenge, Bytes: intent.Bytes, State: "published",
	}
	if opaqueledger.VerifyPublished(ctx, q, key, nodeVault, receipt, scope.PublishedSignature, r.lock()) != nil {
		return OpaqueCapacityScope{}, zero, store.ErrRecordingState
	}
	return scope, receipt, nil
}
