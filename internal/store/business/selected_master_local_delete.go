package business

import (
	"context"
	"reflect"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type MasterLocalMediaDeletionExecutor interface {
	ClearOpaqueMasterLocalDeletionStage(context.Context, store.OwnerControlLease, string, sealedtree.Placement, func(context.Context) error) error
	PrepareOpaqueMasterLocalMediaDelete(context.Context, string, sealedtree.Placement) (sealedtree.MasterLocalDeletePrepared, error)
}

// QueueMasterLocalMediaDeletion commits the exact pending operation before
// a worker hashes or opens the volume for mutation.
func (s *SelectedUploadRuntime) QueueMasterLocalMediaDeletion(ctx context.Context, sessionHash string, target store.SelectedMediaDeleteTarget, audit store.AdminAudit) (store.SelectedMediaDeleteItem, error) {
	var out store.SelectedMediaDeleteItem
	lease, err := s.lease(ctx, sessionHash)
	if err != nil {
		return out, err
	}
	defer lease.Release()
	isLyric := strings.HasPrefix(target.Path, "lyrics/")
	var preflight *sealedtree.MasterLocalLyricDeletePreflight
	if isLyric && target.OperationID == "" {
		preflight, err = s.tree.PreflightMasterLocalLyricDeletion(ctx, target)
		if err != nil {
			return out, err
		}
	}
	err = s.repo.withSelectedMutation(ctx, s.tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
		if err := lease.Check(c); err != nil {
			return err
		}
		var item store.SelectedMediaDeleteItem
		var queued bool
		var err error
		if isLyric {
			lyricAudit := audit
			lyricAudit.SessionHash = sessionHash
			item, queued, err = m.QueueMasterLocalLyricDeletionTx(c, q, target, preflight, lyricAudit)
		} else {
			item, queued, err = m.QueueMasterLocalMediaDeletionTx(c, q, target)
		}
		if err != nil {
			return err
		}
		if queued {
			audit.SessionHash, audit.Action, audit.Result, audit.TargetCount = sessionHash, "opaque-media-delete-request", "pending", 1
			audit.SourceSummary, audit.Detail = "", ""
			if err := appendAudit(c, q, audit); err != nil {
				return err
			}
		}
		out = item
		return lease.Check(c)
	})
	if err != nil {
		return store.SelectedMediaDeleteItem{}, err
	}
	return out, nil
}

// AdvanceMasterLocalMediaDeletion resumes the exact pending operation. The
// ciphertext scan runs outside Owner/ingress/tree locks. The short physical
// phase holds Owner -> ingress -> tree -> volume; settlement is a separate
// retryable transaction authenticated against the same placement.
func (s *SelectedUploadRuntime) AdvanceMasterLocalMediaDeletion(ctx context.Context, sessionHash string, item store.SelectedMediaDeleteItem, audit store.AdminAudit, executor MasterLocalMediaDeletionExecutor) error {
	ready, err := s.lease(ctx, sessionHash)
	if err != nil {
		return err
	}
	defer ready.Release()
	audit.SessionHash = sessionHash
	return s.advanceMasterLocalMediaDeletion(ctx, ready, item, audit, executor)
}

// AdvancePendingMasterLocalMediaDeletion is for the supervised runtime
// worker. It cannot enqueue work or act as an Admin user.
func (s *SelectedUploadRuntime) AdvancePendingMasterLocalMediaDeletion(ctx context.Context, item store.SelectedMediaDeleteItem, executor MasterLocalMediaDeletionExecutor) error {
	if s == nil || s.repo == nil || s.tree == nil || selectedNil(s.gate) || ctx == nil || ctx.Err() != nil {
		return store.ErrNodeState
	}
	if _, ok := ctx.Deadline(); !ok {
		return store.ErrNodeState
	}
	ready, err := s.gate.AcquireSelectedUpload(ctx, s.tree)
	if err != nil || selectedNil(ready) {
		return store.ErrNodeState
	}
	defer ready.Release()
	return s.advanceMasterLocalMediaDeletion(ctx, ready, item, store.AdminAudit{}, executor)
}

func (s *SelectedUploadRuntime) advanceMasterLocalMediaDeletion(ctx context.Context, ready SelectedUploadRuntimeLease, item store.SelectedMediaDeleteItem, audit store.AdminAudit, executor MasterLocalMediaDeletionExecutor) error {
	if selectedNil(executor) || item.State != store.SelectedMediaDeletePending || !nodeHashPattern.MatchString(item.ResourceID) || !nodeIDPattern.MatchString(item.OperationID) || ready.Check(ctx) != nil {
		return store.ErrNodeState
	}
	fence, err := s.tree.AcquireReadFence(ctx)
	if err != nil {
		return err
	}
	snapshot, done, err := s.tree.ReadMasterLocalMediaDeletionWithLease(ctx, fence, item)
	fence.Release()
	if err != nil || done {
		return err
	}
	if operation := snapshot.PublicationOperation; operation != "" {
		err = s.withMasterLocalMediaDeletionFence(ctx, ready, item, snapshot, func(c context.Context, owner store.OwnerControlLease, authorize func(context.Context) error) error {
			return executor.ClearOpaqueMasterLocalDeletionStage(c, owner, operation, snapshot.Placement, authorize)
		})
		if err != nil {
			return err
		}
	}
	proof, err := executor.PrepareOpaqueMasterLocalMediaDelete(ctx, item.OperationID, snapshot.Placement)
	if err != nil {
		return err
	}
	if selectedNil(proof) {
		return store.ErrNodeState
	}
	err = s.withMasterLocalMediaDeletionFence(ctx, ready, item, snapshot, proof.Delete)
	closeErr := proof.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	r := s.repo
	return r.withSelectedMutation(ctx, s.tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
		if err := ready.Check(c); err != nil {
			return err
		}
		deleted, err := m.FinalizeMasterLocalMediaDeletionTx(c, q, item, snapshot.Placement)
		if err != nil || deleted.Already {
			return err
		}
		if err = r.refundDeletedMediaBytesTx(c, q, deleted.OwnerID, "MasterLocal", deleted.Bytes); err != nil {
			return err
		}
		audit.Action, audit.Result, audit.TargetCount = "opaque-media-delete", "success", 1
		audit.SourceSummary, audit.Detail = "", ""
		if err = appendAudit(c, q, audit); err != nil {
			return err
		}
		return ready.Check(c)
	})
}

func (s *SelectedUploadRuntime) withMasterLocalMediaDeletionFence(ctx context.Context, ready SelectedUploadRuntimeLease, item store.SelectedMediaDeleteItem, snapshot sealedtree.MasterLocalMediaDeletionSnapshot, run func(context.Context, store.OwnerControlLease, func(context.Context) error) error) error {
	r := s.repo
	return r.WithOwnerControlExclusive(ctx, func(held context.Context) error {
		return r.WithOrderedIngressTree(held, s.tree, func(c context.Context) error {
			scope, ok := c.Value(orderedIngressTreeKey{}).(*orderedIngressTreeScope)
			if !ok || scope == nil {
				return store.ErrNodeState
			}
			authorize := func(checkCtx context.Context) error {
				if ready.Check(checkCtx) != nil || r.CheckOrderedIngressTree(checkCtx, s.tree, scope.owner) != nil {
					return store.ErrNodeState
				}
				current, done, err := s.tree.ReadMasterLocalMediaDeletionWithLease(checkCtx, scope.tree, item)
				if err != nil || done || !reflect.DeepEqual(current, snapshot) {
					return store.ErrNodeState
				}
				return nil
			}
			return run(c, scope.owner, authorize)
		})
	})
}
