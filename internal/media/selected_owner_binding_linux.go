//go:build linux

package media

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func selectedOwnerBinding(claim protocol.SelectedStorageUpload) (OpaqueOwnerBinding, error) {
	if claim.Policy != "Direct" && claim.Policy != "Relay" || claim.Encryption == nil || claim.Encryption.Validate() != nil || claim.Encryption.CiphertextSize != claim.Size {
		return OpaqueOwnerBinding{}, store.ErrNodeState
	}
	descriptor, err := protocol.IngressMediaDescriptor(claim.Size, claim.Encryption)
	if err != nil {
		return OpaqueOwnerBinding{}, store.ErrNodeState
	}
	revision, err := protocol.OpaquePlacementRevisionFromDescriptor(claim.MediaID, claim.ObjectID, claim.ContentSHA256, descriptor, claim.Size)
	if err != nil {
		return OpaqueOwnerBinding{}, store.ErrNodeState
	}
	b := OpaqueOwnerBinding{MasterID: claim.Master, OwnerID: claim.Owner, RelationshipID: claim.Relationship, Alias: claim.MediaID, Blob: claim.ObjectID, Revision: revision, Digest: claim.ContentSHA256, Descriptor: descriptor, Size: claim.Size}
	if !b.Valid() {
		return OpaqueOwnerBinding{}, store.ErrNodeState
	}
	return b, nil
}

// PublishSelectedOwnerBinding is called only inside the already authenticated
// Owner policy and operation leases, after the opaque blob is durable. The
// binding is revalidated against its bytes before a signed receipt can escape.
func (s *Service) PublishSelectedOwnerBinding(ctx context.Context, claim protocol.SelectedStorageUpload) error {
	binding, err := selectedOwnerBinding(claim)
	if err != nil {
		return err
	}
	return s.RegisterOpaqueOwnerBinding(ctx, binding)
}

// CancelSelectedOwnerBinding durably fences even an upload cancelled before its
// first byte. Caller holds the same authenticated policy and operation leases;
// it must have already persisted the operation cancellation tombstone.
func (s *Service) CancelSelectedOwnerBinding(ctx context.Context, claim protocol.SelectedStorageUpload) error {
	binding, err := selectedOwnerBinding(claim)
	if err != nil || s == nil || ctx == nil || len(claim.OperationID) != 64 {
		return store.ErrNodeState
	}
	operationBytes, err := hex.DecodeString(claim.OperationID)
	if err != nil || len(operationBytes) != 32 || hex.EncodeToString(operationBytes) != claim.OperationID {
		return store.ErrNodeState
	}
	digest := sha256.Sum256(append([]byte("frontiercloud:selected-cancel-alias:v1\x00"), operationBytes...))
	operationID := hex.EncodeToString(digest[:16])
	release, err := s.acquire(ctx, true)
	if err != nil {
		return err
	}
	defer release()
	if err = s.opaqueRegistryDir(false); err != nil {
		return err
	}
	var active OpaqueOwnerBinding
	err = s.readOpaqueRecord(opaqueRegistryFile(binding.Alias, ".active"), &active)
	if err == nil {
		if active != binding {
			return store.ErrNodeState
		}
		return s.revokeOpaqueOwnerBindingLocked(ctx, operationID, binding)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return store.ErrNodeState
	}
	var reserved OpaqueOwnerBinding
	err = s.readOpaqueRecord(opaqueBlobReservation(binding.Blob), &reserved)
	if err == nil && reserved != binding || err != nil && !errors.Is(err, os.ErrNotExist) {
		return store.ErrNodeState
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.writeOpaqueRecordLocked(opaqueRegistryFile(binding.Alias, ".revoked"), opaqueRevocation{OperationID: operationID, Binding: binding})
}
