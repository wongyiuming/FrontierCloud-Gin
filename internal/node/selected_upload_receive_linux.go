//go:build linux

package node

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/selectedupload"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type selectedOwnerRegistry interface {
	InventoryRoot() *os.Root
	PublishSelectedOwnerBinding(context.Context, protocol.SelectedStorageUpload) error
	CancelSelectedOwnerBinding(context.Context, protocol.SelectedStorageUpload) error
}

func (s *Service) selectedRegistry(root *os.Root) (selectedOwnerRegistry, error) {
	if s == nil || root == nil {
		return nil, ErrCapability
	}
	registry, ok := s.volume.(selectedOwnerRegistry)
	if !ok || registry.InventoryRoot() == nil {
		return nil, ErrCapability
	}
	actual, err := registry.InventoryRoot().Stat(".")
	requested, otherErr := root.Stat(".")
	if err != nil || otherErr != nil || !os.SameFile(actual, requested) {
		return nil, ErrCapability
	}
	return registry, nil
}

// receiveSelectedDirect is an unregistered Owner path. It admits the actual
// paired Master ticket under the Owner policy fence, records the encrypted
// operation intent, writes opaque bytes once, syncs the final blob and signs an
// exact receipt with this Owner's durable identity. It does not commit Master
// metadata. If the response is lost or any error occurs after linking, the
// operation must be reconciled; callers must not assume a rollback or delete.
func (s *Service) receiveSelectedDirect(ctx context.Context, token, origin string, deadline selectedupload.ReadDeadline, body io.ReadCloser, maximum time.Duration, root *os.Root) (protocol.OpaqueCapacityReceipt, string, error) {
	return s.selectedDirect(ctx, token, origin, deadline, body, maximum, root, false)
}

// recoverSelectedDirect accepts only a fresh authorized ticket for an existing
// intent. The entire saved stage is re-read and hashed before any receipt is
// reissued. Partial or missing bytes fail closed, retaining reservations.
func (s *Service) recoverSelectedDirect(ctx context.Context, token, origin string, deadline selectedupload.ReadDeadline, body io.ReadCloser, maximum time.Duration, root *os.Root) (protocol.OpaqueCapacityReceipt, string, error) {
	return s.selectedDirect(ctx, token, origin, deadline, body, maximum, root, true)
}

func (s *Service) selectedDirect(ctx context.Context, token, origin string, deadline selectedupload.ReadDeadline, body io.ReadCloser, maximum time.Duration, root *os.Root, recoverExisting bool) (protocol.OpaqueCapacityReceipt, string, error) {
	var receipt protocol.OpaqueCapacityReceipt
	if s == nil || s.identity == nil || s.identity.vault == nil || root == nil || deadline == nil || body == nil {
		return receipt, "", ErrCapability
	}
	claim, lease, err := s.AdmitSelectedDirectUpload(ctx, token)
	if err != nil {
		return receipt, "", err
	}
	if !s.selectedOriginAuthorized(ctx, claim, origin) || claim.ExpiresAt <= time.Now().Unix() || lease.Check(ctx) != nil {
		lease.Release()
		return receipt, "", ErrCapability
	}
	return s.runSelectedAdmitted(ctx, claim, lease, deadline, body, maximum, root, recoverExisting)
}

func (s *Service) runSelectedAdmitted(ctx context.Context, claim protocol.SelectedStorageUpload, lease store.OwnerControlLease, deadline selectedupload.ReadDeadline, body io.ReadCloser, maximum time.Duration, root *os.Root, recoverExisting bool) (protocol.OpaqueCapacityReceipt, string, error) {
	var receipt protocol.OpaqueCapacityReceipt
	registry, err := s.selectedRegistry(root)
	if err != nil {
		lease.Release()
		return receipt, "", err
	}
	publisher, err := sealedtree.NewBlobPublisher(root)
	if err != nil {
		lease.Release()
		return receipt, "", ErrCapability
	}
	var prepared *sealedtree.PreparedBlob
	var signature string
	err = selectedupload.RunOperationStaged(ctx, lease, deadline, body, maximum, root, s.identity.vault, claim, recoverExisting, func(c context.Context) (func(), error) {
		if recoverExisting {
			return nil, nil
		}
		prepared, err = publisher.Prepare(c, claim.OperationID, claim.ObjectID, claim.Size, claim.ContentSHA256, body)
		if err != nil {
			return nil, err
		}
		return func() { _ = prepared.Close() }, nil
	}, func(c context.Context) error {
		if recoverExisting {
			err = publisher.PublishStaged(c, claim.OperationID, claim.ObjectID, claim.Size, claim.ContentSHA256)
		} else {
			err = prepared.Publish(c)
		}
		if err != nil {
			return err
		}
		if err = lease.Check(c); err != nil {
			return err
		}
		if err = registry.PublishSelectedOwnerBinding(c, claim); err != nil {
			return err
		}
		if err = lease.Check(c); err != nil {
			return err
		}
		receipt = protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-published-v1", MasterID: claim.Master, OwnerID: claim.Owner, RelationshipID: claim.Relationship, RelationshipBinding: claim.RelationshipBinding, Generation: claim.Generation, OperationID: claim.OperationID, StageID: claim.StageID, BlobID: claim.ObjectID, Digest: claim.ContentSHA256, Challenge: claim.PublishChallenge, Bytes: claim.Size, State: "published"}
		payload, err := receipt.Payload()
		if err != nil {
			return ErrCapability
		}
		relation, err := s.repo.Relationship(c, claim.Relationship)
		if err != nil {
			return ErrCapability
		}
		signed, err := s.signOpaqueOwnerReceipt(c, relation, claim.Master, claim.Owner, claim.Relationship, payload)
		if err != nil {
			return err
		}
		signature = signed.Signature
		return nil
	})
	if err != nil {
		return protocol.OpaqueCapacityReceipt{}, "", err
	}
	return receipt, signature, nil
}

// cleanupSelectedDirect is unregistered. The caller must obtain a distinct
// cleanup ticket only after the Master has durably marked cancellation.
// A signed receipt is returned only after the Owner has drained the operation,
// synced its tombstone and removed both private paths. An error is ambiguous.
func (s *Service) cleanupSelectedDirect(ctx context.Context, token, origin string, deadline selectedupload.ReadDeadline, body io.ReadCloser, maximum time.Duration, root *os.Root) (protocol.OpaqueCapacityReceipt, string, error) {
	var receipt protocol.OpaqueCapacityReceipt
	if s == nil || s.identity == nil || s.identity.vault == nil || root == nil || deadline == nil || body == nil {
		return receipt, "", ErrCapability
	}
	claim, lease, err := s.admitSelectedDirectCleanup(ctx, token)
	if err != nil {
		return receipt, "", err
	}
	if !s.selectedOriginAuthorized(ctx, claim, origin) || claim.ExpiresAt <= time.Now().Unix() || lease.Check(ctx) != nil {
		lease.Release()
		return receipt, "", ErrCapability
	}
	return s.cleanupSelectedAdmitted(ctx, claim, lease, deadline, body, maximum, root)
}

func (s *Service) cleanupSelectedAdmitted(ctx context.Context, claim protocol.SelectedStorageUpload, lease store.OwnerControlLease, deadline selectedupload.ReadDeadline, body io.ReadCloser, maximum time.Duration, root *os.Root) (protocol.OpaqueCapacityReceipt, string, error) {
	var receipt protocol.OpaqueCapacityReceipt
	registry, err := s.selectedRegistry(root)
	if err != nil {
		lease.Release()
		return receipt, "", err
	}
	var signature string
	err = selectedupload.RunOperationCleanupGuarded(ctx, lease, deadline, body, maximum, root, s.identity.vault, claim, func(c context.Context) error {
		return registry.CancelSelectedOwnerBinding(c, claim)
	}, func(c context.Context) error {
		receipt = protocol.OpaqueCapacityReceipt{Kind: "opaque-capacity-cleaned-v1", MasterID: claim.Master, OwnerID: claim.Owner, RelationshipID: claim.Relationship, RelationshipBinding: claim.RelationshipBinding, Generation: claim.Generation, OperationID: claim.OperationID, StageID: claim.StageID, BlobID: claim.ObjectID, Digest: claim.ContentSHA256, Challenge: claim.CleanupChallenge, Bytes: claim.Size, State: "cleaned"}
		payload, err := receipt.Payload()
		if err != nil {
			return ErrCapability
		}
		relation, err := s.repo.Relationship(c, claim.Relationship)
		if err != nil {
			return ErrCapability
		}
		signed, err := s.signOpaqueOwnerReceipt(c, relation, claim.Master, claim.Owner, claim.Relationship, payload)
		if err != nil {
			return err
		}
		signature = signed.Signature
		return nil
	})
	if err != nil {
		return protocol.OpaqueCapacityReceipt{}, "", err
	}
	return receipt, signature, nil
}

// selectedOriginAuthorized binds the authenticated heartbeat observation to
// both the browser Origin and the Master-signed capability at admission.
func (s *Service) selectedOriginAuthorized(ctx context.Context, claim protocol.SelectedStorageUpload, origin string) bool {
	observed, err := s.FreshSelectedAdminOrigin(ctx, claim.Relationship)
	return err == nil && origin != "" && observed == origin && claim.AdminOrigin == origin
}
