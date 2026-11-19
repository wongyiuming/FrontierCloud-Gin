//go:build linux

package business

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/selectedupload"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// RecordingAudioCleanupOwner and RecordingAudioCleanupVolume are supplied by
// trusted startup from the actual Local node and media service, not a request.
type RecordingAudioCleanupOwner interface {
	PrepareRecordingCleanup(context.Context, protocol.SelectedStorageUpload) (*selectedupload.CleanupBlobProof, error)
	CleanupRecordingWithProof(context.Context, protocol.SelectedStorageUpload, selectedupload.CleanupMediaLease, *selectedupload.CleanupBlobProof, selectedupload.ReadDeadline, io.ReadCloser, func(context.Context) error) (protocol.OpaqueCapacityReceipt, string, error)
}
type RecordingAudioCleanupVolume interface {
	TryRecordingCleanupLease(context.Context) (selectedupload.CleanupMediaLease, func(), error)
}

// recordingAudioDeletionSnapshot verifies account and tree identity and
// reconstructs only server-held state. A completed result additionally needs
// the keyed Owner-receipt verification marker committed with the refund.
func (s *SelectedUploadRuntime) recordingAudioDeletionSnapshot(ctx context.Context, expected store.PublicIngress, user store.KaraokeUser, browser, sessionID, recordingID string) (protocol.SelectedStorageUpload, bool, error) {
	var claim protocol.SelectedStorageUpload
	var done bool
	err := s.repo.withSelectedMutation(ctx, s.tree, func(c context.Context, q queryer, mutation *sealedtree.CoordinatedMutation) error {
		intent, _, _, found, e := s.repo.readRecordingAudioIntentTx(c, q, s.key, recordingID)
		if e != nil || !found || intent.UserID != user.ID || s.checkRecordingAudioAuthorityTx(c, q, expected, user, browser, sessionID, intent.MemberID) != nil {
			return store.ErrRecordingState
		}
		if intent.State == "ready" {
			return c.Err()
		}
		if intent.State != "deleting" && intent.State != "deleted" {
			return store.ErrRecordingState
		}
		if mutation.CheckRecordingAudioCompletionTx(c, q, intent.UserID, intent.RecordingID, intent.OperationID, intent.BlobID) != nil {
			return store.ErrRecordingState
		}
		identity, e := readNode(c, q, s.repo.lock())
		if e != nil || identity.ID != intent.MasterID {
			return store.ErrNodeState
		}
		if intent.State == "deleting" {
			ownerBinding, e := s.repo.recordingAudioOwnerBinding(c, q, s.key, identity, intent.MemberID)
			if e != nil || ownerBinding != intent.OwnerBinding {
				return store.ErrNodeState
			}
		}
		row, e := recordingLookup(q.QueryRowContext(c, "SELECT "+recordingColumns+" FROM karaoke_recordings WHERE recording_id=?"+s.repo.lock(), recordingID))
		if e != nil || row == nil || row.UserID != user.ID || row.MemberID != intent.MemberID || row.Bytes != intent.Bytes || row.State != intent.State || row.SHA256 == nil || *row.SHA256 != intent.Digest {
			return store.ErrRecordingState
		}
		claim, e = s.repo.recordingAudioCleanupClaimTx(c, q, s.key, intent)
		if e != nil {
			return e
		}
		if intent.State == "deleted" {
			marker, e := recordingAudioCleanupMarker(s.key, recordingAudioCleanupReceipt(claim))
			if e != nil || !capacityIDExists(c, q, marker, s.repo.lock()) {
				return store.ErrRecordingState
			}
			done = true
		}
		return c.Err()
	})
	return claim, done, err
}

// DeleteRecordingAudioLocal is a trusted runtime operation, not an HTTP route.
// It marks ready state deleting, hashes the exact file without the Owner
// fence, then takes Owner and a nonblocking media-volume lease to perform the
// signed cleanup. Quota is refunded only after signature verification in the
// final SQL transaction. Busy, revoked or interrupted attempts retain their
// durable state and must be retried; pending uploads are not handled here.
func (s *SelectedUploadRuntime) DeleteRecordingAudioLocal(ctx context.Context, tree *sealedtree.SQLStore, expected store.PublicIngress, user store.KaraokeUser, browser, recordingID string, owner RecordingAudioCleanupOwner, volume RecordingAudioCleanupVolume, deadline selectedupload.ReadDeadline, audit store.KaraokeAudit, checkAccount func(context.Context) error) (bool, error) {
	if s == nil || s.repo == nil || ctx == nil || tree == nil || tree != s.tree || s.crypto == nil || s.vault == nil || selectedNil(s.gate) || selectedNil(owner) || selectedNil(volume) || selectedNil(deadline) || checkAccount == nil || checkAccount(ctx) != nil {
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
	if lease.Check(ctx) != nil {
		lease.Release()
		return false, store.ErrNodeState
	}
	_, done, err := s.recordingAudioDeletionSnapshot(ctx, expected, user, browser, sessionID, recordingID)
	lease.Release()
	if err != nil {
		return false, err
	}
	if done {
		if checkAccount(ctx) != nil {
			return false, store.ErrRecordingState
		}
		return true, nil
	}
	if _, err = s.stageRecordingAudioDeletion(ctx, tree, expected, user, browser, recordingID, audit, checkAccount); err != nil {
		return false, err
	}
	lease, err = s.gate.AcquireSelectedUpload(ctx, tree)
	if err != nil || selectedNil(lease) {
		return false, store.ErrNodeState
	}
	leaseHeld := true
	defer func() {
		if leaseHeld {
			lease.Release()
		}
	}()
	if lease.Check(ctx) != nil {
		return false, store.ErrNodeState
	}
	claim, done, err := s.recordingAudioDeletionSnapshot(ctx, expected, user, browser, sessionID, recordingID)
	if err != nil {
		return false, err
	}
	if done {
		if checkAccount(ctx) != nil {
			return false, store.ErrRecordingState
		}
		return true, nil
	}
	proof, err := owner.PrepareRecordingCleanup(ctx, claim)
	if err != nil && !errors.Is(err, selectedupload.ErrCleanupBlobMissing) {
		return false, err
	}
	if proof != nil {
		defer proof.Close()
	}
	if checkAccount(ctx) != nil || lease.Check(ctx) != nil {
		return false, store.ErrRecordingState
	}
	var receipt protocol.OpaqueCapacityReceipt
	var signature string
	err = s.repo.WithOwnerControlExclusive(ctx, func(held context.Context) error {
		current, already, e := s.recordingAudioDeletionSnapshot(held, expected, user, browser, sessionID, recordingID)
		if e != nil || already || !reflect.DeepEqual(current, claim) || lease.Check(held) != nil {
			return store.ErrRecordingState
		}
		media, release, e := volume.TryRecordingCleanupLease(held)
		if e != nil {
			return e
		}
		if selectedNil(media) || release == nil {
			if release != nil {
				release()
			}
			return store.ErrNodeState
		}
		defer release()
		receipt, signature, e = owner.CleanupRecordingWithProof(held, claim, media, proof, deadline, io.NopCloser(bytes.NewReader(nil)), func(c context.Context) error {
			actual, id, _, ok := mediacrypto.DirectSessionFromContext(c).Values()
			if !ok || actual != browser || id != sessionID || lease.Check(c) != nil {
				return store.ErrRecordingState
			}
			return c.Err()
		})
		return e
	})
	if err != nil {
		return false, err
	}
	if lease.Check(ctx) != nil || checkAccount(ctx) != nil {
		return false, store.ErrRecordingState
	}
	lease.Release()
	leaseHeld = false
	return s.finishRecordingAudioDeletion(ctx, tree, expected, user, browser, recordingID, receipt, signature, audit, checkAccount)
}
