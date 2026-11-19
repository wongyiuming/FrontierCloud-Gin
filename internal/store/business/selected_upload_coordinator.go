package business

import (
	"context"
	"fmt"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// withSelectedMutation owns the only database transaction used by this
// not-yet-connected selected upload path. The order is Owner control,
// ingress writer, tree mutation, then SQLite BEGIN IMMEDIATE. All operations
// inside fn must be database-only and must roll back on any error. The caller
// must supply a bounded context and authenticate the Admin independently.
// MySQL and unconfigured Owner/tree fences fail closed until implemented.
func (r *Repository) withSelectedMutation(ctx context.Context, tree *sealedtree.SQLStore, fn func(context.Context, queryer, *sealedtree.CoordinatedMutation) error) error {
	if r == nil || ctx == nil || tree == nil || fn == nil || r.backend != "sqlite" {
		return store.ErrNodeState
	}
	if _, ok := ctx.Deadline(); !ok {
		return store.ErrNodeState
	}
	r.ownerControlMu.RLock()
	configured := r.ownerControlAcquire != nil
	r.ownerControlMu.RUnlock()
	if !configured {
		return store.ErrNodeState
	}
	return r.WithOwnerControlExclusive(ctx, func(heldCtx context.Context) error {
		held, ok := heldCtx.Value(ownerControlContextKey{}).(*ownerControlContext)
		if !ok || held == nil || held.repository != r || !validOwnerControlLease(held.lease) {
			return store.ErrNodeState
		}
		release, err := r.ingressLease(heldCtx, true)
		if err != nil {
			return err
		}
		defer release()
		return tree.WithCoordinatedMutation(heldCtx, r.db, func(m *sealedtree.CoordinatedMutation) error {
			return r.write(heldCtx, func(q queryer) error {
				if err := r.checkOwnerControlMarker(heldCtx, q, held.lease); err != nil {
					return err
				}
				if err := fn(heldCtx, q, m); err != nil {
					return err
				}
				if err := held.lease.Check(heldCtx); err != nil {
					return store.ErrNodeState
				}
				return heldCtx.Err()
			})
		})
	})
}

// prepareSelectedCoordinated is a private, not-yet-registered composition of
// the real tree pending record and capacity reservation. check must enforce
// current Admin authorization, directory affinity and encryption file-ID
// admission in this same transaction; no production implementation is wired.
// A retry uses its stable upload ID to recover the identical operation rather
// than allocating new blob IDs. Owner bytes and final settlement are separate.
func (r *Repository) prepareSelectedCoordinated(ctx context.Context, tree *sealedtree.SQLStore, key []byte, entry sealedtree.Entry, placement sealedtree.Placement, facts sealedtree.Facts, free int64, check func(context.Context, queryer, *sealedtree.CoordinatedMutation, sealedtree.SelectedPending) error, commitments ...[]string) (sealedtree.PreparedFile, bool, error) {
	var out sealedtree.PreparedFile
	if r == nil || ctx == nil || tree == nil || !validCapacityKey(key) || free < 0 || facts.PendingSelectedUpload == nil || check == nil {
		return out, false, store.ErrNodeState
	}
	// Scan the authenticated category without holding the global ingress
	// writer. The one-shot proof is rechecked inside the final transaction;
	// any intervening tree mutation requires a fresh admission attempt.
	proof, err := tree.PreflightCategoryAndOwner(ctx, entry.ParentID, placement.OwnerID)
	if err != nil {
		return out, false, fmt.Errorf("selected preflight: %w", err)
	}
	return r.prepareSelectedAfterPreflight(ctx, tree, proof, key, entry, placement, facts, free, check, commitments...)
}

// prepareSelectedAfterPreflight consumes the process-local proof once inside
// the final fenced transaction. It is private and is not an upload endpoint.
func (r *Repository) prepareSelectedAfterPreflight(ctx context.Context, tree *sealedtree.SQLStore, proof *sealedtree.CategoryOwnerPreflight, key []byte, entry sealedtree.Entry, placement sealedtree.Placement, facts sealedtree.Facts, free int64, check func(context.Context, queryer, *sealedtree.CoordinatedMutation, sealedtree.SelectedPending) error, commitments ...[]string) (sealedtree.PreparedFile, bool, error) {
	var out sealedtree.PreparedFile
	var already bool
	if r == nil || ctx == nil || tree == nil || proof == nil || !validCapacityKey(key) || free < 0 || facts.PendingSelectedUpload == nil || check == nil || len(commitments) > 1 || facts.PendingSelectedUpload.Policy == "S3" && len(commitments) != 1 || facts.PendingSelectedUpload.Policy != "S3" && len(commitments) != 0 {
		return out, false, store.ErrNodeState
	}
	bound, stop, err := proof.BindContext(ctx)
	if err != nil {
		return out, false, err
	}
	defer stop()
	err = r.withSelectedMutation(bound, tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
		admission := facts.PendingSelectedUpload
		// The proof is a concurrency guard, not authorization: the callback
		// and selectedCapacityPreparation still recheck Admin and current policy.
		if e := m.ConsumeCategoryOwnerPreflightTx(c, q, proof, entry.ParentID, placement.OwnerID); e != nil {
			return fmt.Errorf("selected consume preflight: %w", e)
		}
		historical, found, e := r.recoverSelectedOpaqueCapacityTx(c, q, key, admission.UploadID)
		if e != nil {
			return e
		}
		if found {
			cap := historical.Capacity.capacity()
			pending, e := m.ReadSelectedFileTx(c, q, cap.OperationID)
			if e != nil {
				return store.ErrNodeState
			}
			descriptor, e := protocol.IngressMediaDescriptor(placement.Bytes, placement.Encryption)
			if e != nil || pending.Descriptor != descriptor || pending.ObjectID != entry.ObjectID || pending.ParentID != entry.ParentID || pending.Name != entry.Name || pending.Placement.OwnerID != placement.OwnerID || pending.Placement.Bytes != placement.Bytes || pending.Placement.SHA256 != placement.SHA256 || pending.Admission != *admission || verifySelectedPendingBinding(key, historical, pending) != nil {
				return store.ErrNodeState
			}
			if e = check(c, q, m, pending); e != nil {
				return e
			}
			identity, e := readNode(c, q, r.lock())
			if e != nil {
				return e
			}
			// Recovery must not reuse a valid old reservation after the applied
			// relationship, policy revision or origin has changed.
			if e = r.selectedCapacityPreparation(c, key, cap, admission.UploadID, entry.ParentID, admission.AdminBinding, admission.Policy, admission.Revision, admission.Origin, historical.PendingBinding)(q, identity); e != nil {
				return e
			}
			if admission.Policy == "S3" {
				if _, e = r.ensureSelectedS3ReservationTx(c, q, key, historical, pending, false, commitments...); e != nil {
					return e
				}
			}
			if e = proof.CheckContext(c); e != nil {
				return e
			}
			out = sealedtree.PreparedFile{OperationID: pending.OperationID, BlobID: pending.Placement.BlobID, ReadAlias: pending.Placement.ReadAlias}
			already = true
			return nil
		}
		prepared, e := m.PrepareFileTx(c, q, entry, placement, facts)
		if e != nil {
			return fmt.Errorf("selected tree prepare: %w", e)
		}
		pending, e := m.ReadSelectedFileTx(c, q, prepared.OperationID)
		if e != nil {
			return fmt.Errorf("selected pending read: %w", e)
		}
		if e = check(c, q, m, pending); e != nil {
			return fmt.Errorf("selected admission check: %w", e)
		}
		binding, e := selectedPendingBinding(key, pending)
		if e != nil {
			return e
		}
		identity, e := readNode(c, q, r.lock())
		if e != nil {
			return e
		}
		capacity := OpaqueCapacityIntent{OperationID: prepared.OperationID, MasterID: identity.ID, MemberID: pending.Placement.OwnerID, BlobID: prepared.BlobID, Digest: pending.Placement.SHA256, Bytes: pending.Placement.Bytes}
		if !validOpaqueCapacity(capacity) || capacity.Bytes <= 0 {
			return store.ErrNodeState
		}
		index := opaqueCapacityIndex(key, capacity.OperationID)
		enc, sealed, e := sealOpaqueCapacity(key, index, capacity)
		if e != nil {
			return e
		}
		prior, e := r.reserveOpaqueCapacityTx(c, q, key, capacity, free, r.selectedCapacityPreparation(c, key, capacity, admission.UploadID, entry.ParentID, admission.AdminBinding, admission.Policy, admission.Revision, admission.Origin, binding), index, enc, sealed, admission.Policy == "S3")
		if e != nil {
			return fmt.Errorf("selected capacity reservation: %w", e)
		}
		if prior {
			return store.ErrNodeState
		}
		if admission.Policy == "S3" {
			selected, found, err := r.recoverSelectedOpaqueCapacityTx(c, q, key, admission.UploadID)
			if err != nil || !found {
				return store.ErrNodeState
			}
			if _, err = r.ensureSelectedS3ReservationTx(c, q, key, selected, pending, true, commitments...); err != nil {
				return err
			}
		}
		if e = proof.CheckContext(c); e != nil {
			return e
		}
		out = prepared
		return nil
	})
	if err != nil {
		return sealedtree.PreparedFile{}, false, err
	}
	return out, already, nil
}
