//go:build linux

package node

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/selectedupload"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// PrepareRecordingCleanup hashes a trusted Master's exact Local claim outside
// the Owner lease. Its result is not deletion authority and must be closed.
func (r *SelectedLocalReceiver) PrepareRecordingCleanup(ctx context.Context, claim protocol.SelectedStorageUpload) (*selectedupload.CleanupBlobProof, error) {
	if !r.valid(ctx) || claim.Policy != "Local" || claim.Master != r.service.identity.ID || claim.Owner != claim.Master || claim.Relationship != "" || claim.RelationshipBinding != "" || claim.ResourceOrigin != "" || claim.Revision != 1 || claim.Encryption == nil || claim.Encryption.Validate() != nil || claim.Encryption.CiphertextSize != claim.Size {
		return nil, ErrCapability
	}
	root := r.volume.(interface{ InventoryRoot() *os.Root }).InventoryRoot()
	proof, err := selectedupload.PrepareCleanupBlob(ctx, root, claim)
	if err != nil {
		return nil, err
	}
	if !r.valid(ctx) {
		proof.Close()
		return nil, ErrCapability
	}
	return proof, nil
}

// CleanupRecordingWithProof must run within the repository's genuine Owner
// exclusive scope and an exact exclusive media-volume lease, after the Master
// has durably marked the same recording deleting. Its receipt only proves the
// Owner tombstone and unlink; the Master must separately settle quota.
func (r *SelectedLocalReceiver) CleanupRecordingWithProof(ctx context.Context, claim protocol.SelectedStorageUpload, media selectedupload.CleanupMediaLease, proof *selectedupload.CleanupBlobProof, deadline selectedupload.ReadDeadline, body io.ReadCloser, authorize func(context.Context) error) (protocol.OpaqueCapacityReceipt, string, error) {
	var zero protocol.OpaqueCapacityReceipt
	if !r.valid(ctx) || media == nil || deadline == nil || body == nil || authorize == nil || claim.Policy != "Local" || claim.Master != r.service.identity.ID || claim.Owner != claim.Master || claim.Relationship != "" || claim.RelationshipBinding != "" || claim.ResourceOrigin != "" || claim.Revision != 1 || claim.Encryption == nil || claim.Encryption.Validate() != nil || claim.Encryption.CiphertextSize != claim.Size {
		return zero, "", ErrCapability
	}
	coordinator, ok := r.service.repo.(interface {
		AcquireOwnerControlShared(context.Context) (store.OwnerControlLease, error)
		CheckRecordingOwnerExclusive(context.Context) error
	})
	if !ok || coordinator.CheckRecordingOwnerExclusive(ctx) != nil {
		return zero, "", ErrCapability
	}
	root := r.volume.(interface{ InventoryRoot() *os.Root }).InventoryRoot()
	if media.CheckCleanupRoot(ctx, root) != nil {
		return zero, "", ErrCapability
	}
	lease, err := coordinator.AcquireOwnerControlShared(ctx)
	if err != nil {
		return zero, "", ErrCapability
	}
	var receipt protocol.OpaqueCapacityReceipt
	var signature string
	err = selectedupload.RunOperationCleanupWithProof(ctx, lease, media, deadline, body, 24*time.Hour, root, r.service.identity.vault, claim, proof, authorize, func(c context.Context) error {
		receipt = protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-cleaned-v1", MasterID: claim.Master, OwnerID: claim.Owner, Generation: claim.Generation, OperationID: claim.OperationID, StageID: claim.StageID, BlobID: claim.ObjectID, Digest: claim.ContentSHA256, Challenge: claim.CleanupChallenge, Bytes: claim.Size, State: "cleaned"}
		payload, e := receipt.Payload()
		if e != nil {
			return ErrCapability
		}
		identity, e := r.service.repo.ReadIdentity(c)
		if e != nil || identity.ID != claim.Master || identity.Role != "Master" || coordinator.CheckRecordingOwnerExclusive(c) != nil || media.CheckCleanupRoot(c, root) != nil {
			return ErrCapability
		}
		signed, e := r.service.identity.signed(identity, payload)
		if e != nil {
			return e
		}
		signature = signed.Signature
		return nil
	})
	if err != nil {
		return zero, "", err
	}
	return receipt, signature, nil
}
