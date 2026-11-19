//go:build linux

package node

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/selectedupload"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// SelectedLocalReceiver is tied to the actual Master service, volume and Owner
// fence. Its caller must pass a claim read from an authenticated pending
// reservation under the Master tree and readiness gate, never from a browser.
type SelectedLocalReceiver struct {
	service *Service
	fence   *ownerfence.Fence
	volume  any
}

func NewSelectedLocalReceiver(ctx context.Context, service *Service, fence *ownerfence.Fence) (*SelectedLocalReceiver, error) {
	if service == nil || fence == nil {
		return nil, ErrCapability
	}
	r := &SelectedLocalReceiver{service: service, fence: fence, volume: service.volume}
	if !r.valid(ctx) {
		return nil, ErrCapability
	}
	return r, nil
}
func (r *SelectedLocalReceiver) valid(ctx context.Context) bool {
	if r == nil || ctx == nil || ctx.Err() != nil || r.service == nil || r.service.repo == nil || r.service.identity == nil || r.fence == nil || !sameLegacyVolume(r.service.volume, r.volume) {
		return false
	}
	v, ok := r.volume.(interface {
		VerifyLegacyOwnerVolume(context.Context, store.NodeRepository, *Identity, *ownerfence.Fence) error
		InventoryRoot() *os.Root
	})
	if !ok || v.InventoryRoot() == nil || v.VerifyLegacyOwnerVolume(ctx, r.service.repo, r.service.identity, r.fence) != nil {
		return false
	}
	id, err := r.service.repo.ReadIdentity(ctx)
	return err == nil && id.Role == "Master" && id.ID == r.service.identity.ID
}
func (r *SelectedLocalReceiver) SelectedLocalFree(ctx context.Context) (int64, error) {
	if !r.valid(ctx) {
		return 0, ErrCapability
	}
	_, free, err := fsutil.DiskUsage(r.volume.(interface{ InventoryRoot() *os.Root }).InventoryRoot())
	return free, err
}
func (r *SelectedLocalReceiver) SelectedLocalOperation(ctx context.Context, claim protocol.SelectedStorageUpload, deadline selectedupload.ReadDeadline, body io.ReadCloser, action string) (protocol.OpaqueCapacityReceipt, string, error) {
	var zero protocol.OpaqueCapacityReceipt
	if !r.valid(ctx) || deadline == nil || body == nil || claim.Policy != "Local" || claim.Encryption == nil || claim.Encryption.Validate() != nil || claim.Encryption.CiphertextSize != claim.Size || claim.Master != r.service.identity.ID || claim.Owner != claim.Master || claim.Relationship != "" || claim.RelationshipBinding != "" || claim.ResourceOrigin != "" || claim.Revision != 1 {
		return zero, "", ErrCapability
	}
	coordinator, ok := r.service.repo.(interface {
		AcquireOwnerControlShared(context.Context) (store.OwnerControlLease, error)
	})
	if !ok {
		return zero, "", ErrCapability
	}
	lease, err := coordinator.AcquireOwnerControlShared(ctx)
	if err != nil {
		return zero, "", ErrCapability
	}
	if !r.valid(ctx) || lease.Check(ctx) != nil {
		lease.Release()
		return zero, "", ErrCapability
	}
	root := r.volume.(interface{ InventoryRoot() *os.Root }).InventoryRoot()
	sign := func(c context.Context, kind, state, challenge string) (protocol.OpaqueCapacityReceipt, string, error) {
		receipt := protocol.OpaqueCapacityReceipt{Kind: kind, MasterID: claim.Master, OwnerID: claim.Owner, Generation: claim.Generation, OperationID: claim.OperationID, StageID: claim.StageID, BlobID: claim.ObjectID, Digest: claim.ContentSHA256, Challenge: challenge, Bytes: claim.Size, State: state}
		payload, e := receipt.Payload()
		if e != nil {
			return zero, "", ErrCapability
		}
		identity, e := r.service.repo.ReadIdentity(c)
		if e != nil || identity.ID != claim.Master || identity.Role != "Master" || lease.Check(c) != nil {
			return zero, "", ErrCapability
		}
		signed, e := r.service.identity.signed(identity, payload)
		if e != nil {
			return zero, "", e
		}
		return receipt, signed.Signature, nil
	}
	var receipt protocol.OpaqueCapacityReceipt
	var signature string
	if action == "cleanup" {
		err = selectedupload.RunOperationCleanup(ctx, lease, deadline, body, 24*time.Hour, root, r.service.identity.vault, claim, func(c context.Context) error {
			var e error
			receipt, signature, e = sign(c, "opaque-capacity-cleaned-v1", "cleaned", claim.CleanupChallenge)
			return e
		})
	} else if action == "upload" || action == "recover" {
		pub, e := sealedtree.NewBlobPublisher(root)
		if e != nil {
			lease.Release()
			return zero, "", e
		}
		var prepared *sealedtree.PreparedBlob
		recoverExisting := action == "recover"
		err = selectedupload.RunOperationStaged(ctx, lease, deadline, body, 24*time.Hour, root, r.service.identity.vault, claim, recoverExisting, func(c context.Context) (func(), error) {
			if recoverExisting {
				return nil, nil
			}
			prepared, e = pub.Prepare(c, claim.OperationID, claim.ObjectID, claim.Size, claim.ContentSHA256, body)
			if e != nil {
				return nil, e
			}
			return func() { _ = prepared.Close() }, nil
		}, func(c context.Context) error {
			if recoverExisting {
				e = pub.PublishStaged(c, claim.OperationID, claim.ObjectID, claim.Size, claim.ContentSHA256)
			} else {
				e = prepared.Publish(c)
			}
			if e != nil {
				return e
			}
			receipt, signature, e = sign(c, "opaque-capacity-published-v1", "published", claim.PublishChallenge)
			return e
		})
	} else {
		lease.Release()
		return zero, "", ErrCapability
	}
	if err != nil {
		return zero, "", err
	}
	return receipt, signature, nil
}
