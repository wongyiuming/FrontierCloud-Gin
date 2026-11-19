package media

import (
	"context"
	"reflect"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// ConfigureOpaqueDeletionReadiness is startup-only. The lease must fence
// authorization, retention/recovery and dependent quota/lyrics state through
// owner deletion and receipt commit. No production caller is installed while
// those contracts remain incomplete.
func (s *Service) ConfigureOpaqueDeletionReadiness(acquire func(context.Context, sealedtree.RevocationIntent) (node.IngressPrerequisiteLease, error)) {
	if s != nil {
		s.opaqueDeletionReady = acquire
	}
}

// ConfigureOpaqueOwnerControlReadiness is startup-only. Its lease must fence
// the exact relationship instance against re-pair through the owner request
// AND tree ACK commit. The callback is held before the tree ACK transaction,
// so it must follow the final globally verified control-to-tree lock order.
// No production implementation is installed until that ordering is proven.
func (s *Service) ConfigureOpaqueOwnerControlReadiness(acquire func(context.Context, sealedtree.RevocationIntent) (node.IngressPrerequisiteLease, error)) {
	if s != nil {
		s.opaqueOwnerControlReady = acquire
	}
}

func (s *Service) acquireOpaqueOwnerControl(ctx context.Context, intent sealedtree.RevocationIntent) (node.IngressPrerequisiteLease, error) {
	if s.opaqueOwnerControlReady == nil {
		return nil, store.ErrNodeState
	}
	lease, err := s.opaqueOwnerControlReady(ctx, intent)
	if err != nil || !validOpaqueDeletionLease(lease) {
		if validOpaqueDeletionLease(lease) {
			lease.Release()
		}
		return nil, store.ErrNodeState
	}
	if lease.Check(ctx) != nil {
		lease.Release()
		return nil, store.ErrNodeState
	}
	return lease, nil
}

func validOpaqueDeletionLease(lease node.IngressPrerequisiteLease) bool {
	if lease == nil {
		return false
	}
	value := reflect.ValueOf(lease)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !value.IsNil()
	default:
		return true
	}
}

// ConfirmOpaqueOwnerRevocation resumes an already-durable Master intent,
// obtains the paired owner's durable tombstone ACK, then records its signature
// under the exclusive tree transaction. It intentionally does not delete or
// migrate content, clear the pending intent, or re-enable authorization.
// On every failure the pending intent remains available for explicit retry.
func (s *Service) ConfirmOpaqueOwnerRevocation(ctx context.Context, tree *sealedtree.SQLStore, objectID string) error {
	if s == nil || s.control == nil || tree == nil || ctx == nil {
		return store.ErrNodeState
	}
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		return err
	}
	intent, exists, err := tree.RecoverOpaqueRevocationWithLease(ctx, lease, objectID)
	lease.Release()
	if err != nil {
		return err
	}
	if !exists {
		return store.ErrNodeState
	}
	controlLease, err := s.acquireOpaqueOwnerControl(ctx, intent)
	if err != nil {
		return err
	}
	defer controlLease.Release()
	ctx = store.WithOpaqueControlAuthority(ctx, intent.RelationshipBinding, controlLease)
	return s.confirmOpaqueOwnerRevocation(ctx, tree, objectID, intent, controlLease.Check)
}

func (s *Service) confirmOpaqueOwnerRevocation(ctx context.Context, tree *sealedtree.SQLStore, objectID string, intent sealedtree.RevocationIntent, check func(context.Context) error) error {
	if intent.OwnerSignature != "" {
		return nil
	} // Recovery has reverified the pinned signature.
	receipt := protocol.OpaqueRevocationReceipt{Kind: "opaque-alias-revoke-v1", OperationID: intent.OperationID, MasterID: intent.MasterID, OwnerID: intent.OwnerID, RelationshipID: intent.RelationshipID, Alias: intent.Alias, Blob: intent.BlobID, Revision: intent.Revision, State: "revoked"}
	signed, err := s.control.RequestOpaqueOwnerRevocationReceipt(ctx, receipt, intent.RelationshipBinding)
	if err != nil {
		return err
	}
	if check(ctx) != nil {
		return store.ErrNodeState
	}
	return tree.RecordOpaqueRevocationAck(ctx, objectID, receipt, signed.Signature)
}

// ConfirmOpaqueOwnerDeletion resumes a previously acknowledged delete intent
// and records the owner's distinct durable unlink proof. It leaves pending
// Master metadata, quota and lyrics untouched until their lifecycle is wired.
func (s *Service) ConfirmOpaqueOwnerDeletion(ctx context.Context, tree *sealedtree.SQLStore, objectID string) error {
	if s == nil || s.control == nil || tree == nil || ctx == nil || !IsAdminResourceContext(ctx) || s.opaqueDeletionReady == nil {
		return store.ErrNodeState
	}
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		return err
	}
	intent, exists, err := tree.RecoverOpaqueRevocationWithLease(ctx, lease, objectID)
	lease.Release()
	if err != nil {
		return err
	}
	if !exists || intent.Action != "delete" || intent.OwnerSignature == "" {
		return store.ErrNodeState
	}
	prerequisite, err := s.opaqueDeletionReady(ctx, intent)
	if err != nil || !validOpaqueDeletionLease(prerequisite) {
		if validOpaqueDeletionLease(prerequisite) {
			prerequisite.Release()
		}
		return store.ErrNodeState
	}
	defer prerequisite.Release()
	if prerequisite.Check(ctx) != nil {
		return store.ErrNodeState
	}
	controlLease, err := s.acquireOpaqueOwnerControl(ctx, intent)
	if err != nil {
		return err
	}
	defer controlLease.Release()
	ctx = store.WithOpaqueControlAuthority(ctx, intent.RelationshipBinding, controlLease)
	return s.confirmOpaqueOwnerDeletion(ctx, tree, objectID, intent, func(c context.Context) error {
		if prerequisite.Check(c) != nil || controlLease.Check(c) != nil {
			return store.ErrNodeState
		}
		return nil
	})
}

func (s *Service) confirmOpaqueOwnerDeletion(ctx context.Context, tree *sealedtree.SQLStore, objectID string, intent sealedtree.RevocationIntent, check func(context.Context) error) error {
	if intent.DeletionSignature != "" {
		return nil
	}
	receipt := protocol.OpaqueDeletionReceipt{Kind: "opaque-blob-delete-v1", OperationID: intent.OperationID, MasterID: intent.MasterID, OwnerID: intent.OwnerID, RelationshipID: intent.RelationshipID, Alias: intent.Alias, Blob: intent.BlobID, Revision: intent.Revision, State: "deleted", PublicationOperation: intent.FollowerPublication}
	signed, err := s.control.RequestOpaqueOwnerDeletionReceipt(ctx, receipt, intent.RelationshipBinding)
	if err != nil {
		return err
	}
	if check(ctx) != nil {
		return store.ErrNodeState
	}
	return tree.RecordOpaqueDeletionReceipt(ctx, objectID, receipt, signed.Signature)
}

// AdvanceOpaqueFollowerMediaDeletion performs the two remote steps for one
// already-authorized, exact durable selection. The caller retains the
// relationship-instance fence and its runtime check throughout; this method
// opens no tree writer until the remote operation returns a signed proof.
func (s *Service) AdvanceOpaqueFollowerMediaDeletion(ctx context.Context, tree *sealedtree.SQLStore, objectID, operationID string, owner store.OwnerControlLease, checkRuntime func(context.Context) error) error {
	if s == nil || s.control == nil || tree == nil || ctx == nil || owner == nil || checkRuntime == nil {
		return store.ErrNodeState
	}
	check := func(c context.Context) error {
		if owner.Check(c) != nil || checkRuntime(c) != nil {
			return store.ErrNodeState
		}
		return nil
	}
	read := func(c context.Context) (sealedtree.RevocationIntent, error) {
		if check(c) != nil {
			return sealedtree.RevocationIntent{}, store.ErrNodeState
		}
		lease, err := tree.AcquireReadFence(c)
		if err != nil {
			return sealedtree.RevocationIntent{}, err
		}
		defer lease.Release()
		intent, found, err := tree.RecoverOpaqueRevocationWithLease(c, lease, objectID)
		if err != nil || !found || !intent.SelectedDelete || intent.Action != "delete" || intent.OperationID != operationID || check(c) != nil {
			return sealedtree.RevocationIntent{}, store.ErrNodeState
		}
		return intent, nil
	}
	intent, err := read(ctx)
	if err != nil {
		return err
	}
	authorized := store.WithOpaqueControlAuthority(ctx, intent.RelationshipBinding, owner)
	if intent.OwnerSignature == "" {
		if err := s.confirmOpaqueOwnerRevocation(authorized, tree, objectID, intent, check); err != nil {
			return err
		}
		priorBinding := intent.RelationshipBinding
		intent, err = read(authorized)
		if err != nil || intent.OwnerSignature == "" || intent.RelationshipBinding != priorBinding {
			return store.ErrNodeState
		}
	}
	return s.confirmOpaqueOwnerDeletion(authorized, tree, objectID, intent, check)
}
