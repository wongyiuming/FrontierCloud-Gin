package business

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// QueueFollowerMediaDeletions persists an entire validated selection before
// any network requests. The operation is independent of the Admin session
// that will eventually resume it.
func (s *SelectedUploadRuntime) QueueFollowerMediaDeletions(ctx context.Context, sessionHash string, targets []store.SelectedMediaDeleteTarget, audit store.AdminAudit) (store.SelectedMediaDeleteResult, error) {
	return s.queueMediaDeletionBatch(ctx, sessionHash, targets, audit, 200, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation, target store.SelectedMediaDeleteTarget) (store.SelectedMediaDeleteItem, bool, error) {
		if target.Directory {
			return store.SelectedMediaDeleteItem{}, false, sealedtree.ErrInvalid
		}
		return m.QueueFollowerMediaDeletionTx(c, q, target)
	})
}

// QueueMediaDeletions commits a complete exact selection across storage
// kinds before a worker attempts any physical delete.
func (s *SelectedUploadRuntime) QueueMediaDeletions(ctx context.Context, sessionHash string, targets []store.SelectedMediaDeleteTarget, audit store.AdminAudit) (store.SelectedMediaDeleteResult, error) {
	return s.queueMediaDeletions(ctx, sessionHash, targets, audit, nil)
}

func (s *SelectedUploadRuntime) queueMediaDeletions(ctx context.Context, sessionHash string, targets []store.SelectedMediaDeleteTarget, audit store.AdminAudit, backends map[string]sealedtree.MediaDeletionBackend) (store.SelectedMediaDeleteResult, error) {
	if len(targets) == 0 || len(targets) > 200 {
		return store.SelectedMediaDeleteResult{}, sealedtree.ErrInvalid
	}
	lease, err := s.lease(ctx, sessionHash)
	if err != nil {
		return store.SelectedMediaDeleteResult{}, err
	}
	lease.Release()
	leaves := make([]store.SelectedMediaDeleteTarget, 0, len(targets))
	directories := make([]store.SelectedMediaDeleteTarget, 0)
	plans := make([]*sealedtree.DirectoryDeletePreflight, 0)
	for _, target := range targets {
		if target.Directory {
			plan, err := s.tree.PreflightDirectoryDeletion(ctx, target)
			if err != nil {
				return store.SelectedMediaDeleteResult{}, err
			}
			directories = append(directories, target)
			plans = append(plans, plan)
			leaves = append(leaves, plan.Leaves()...)
		} else {
			leaves = append(leaves, target)
		}
		if len(leaves) > sealedtree.DirectoryDeleteLeafLimit {
			return store.SelectedMediaDeleteResult{}, sealedtree.ErrDirectoryDeleteLimit
		}
	}
	var preflight *sealedtree.MasterLocalLyricDeleteBatchPreflight
	if len(leaves) != 0 {
		preflight, err = s.tree.PreflightMasterLocalLyricDeletions(ctx, leaves)
		if err != nil {
			return store.SelectedMediaDeleteResult{}, err
		}
	}
	var admission *sealedtree.MasterLocalLyricDeleteAdmission
	var folderAdmission *sealedtree.DirectoryDeleteAdmission
	audit.SessionHash = sessionHash
	// Detach references before any selected track receives its delete intent.
	sort.SliceStable(leaves, func(i, j int) bool {
		return strings.HasPrefix(leaves[i].Path, "lyrics/") && !strings.HasPrefix(leaves[j].Path, "lyrics/")
	})
	ordered := append(leaves, directories...)
	result, err := s.queueMediaDeletionBatch(ctx, sessionHash, ordered, audit, 200+sealedtree.DirectoryDeleteLeafLimit, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation, target store.SelectedMediaDeleteTarget) (store.SelectedMediaDeleteItem, bool, error) {
		if admission == nil {
			admission, err = m.AdmitMasterLocalLyricDeletionsTx(c, q, preflight)
			if err != nil {
				return store.SelectedMediaDeleteItem{}, false, err
			}
			if len(plans) != 0 {
				folderAdmission, err = m.AdmitDirectoryDeletionsTx(c, q, plans)
				if err != nil {
					return store.SelectedMediaDeleteItem{}, false, err
				}
			}
		}
		if target.Directory {
			return m.QueueDirectoryDeletionTx(c, q, target, folderAdmission)
		}
		backend, err := m.ClassifyMediaDeletionTx(c, q, target)
		if err != nil {
			return store.SelectedMediaDeleteItem{}, false, err
		}
		if backends != nil {
			backends[target.ResourceID] = backend
		}
		switch backend {
		case sealedtree.MediaDeletionFollower:
			return m.QueueFollowerMediaDeletionTx(c, q, target)
		case sealedtree.MediaDeletionMasterLocal:
			if strings.HasPrefix(target.Path, "lyrics/") {
				return m.QueueMasterLocalLyricDeletionAdmittedTx(c, q, target, admission, audit)
			}
			return m.QueueMasterLocalMediaDeletionTx(c, q, target)
		case sealedtree.MediaDeletionS3:
			if s3 := s.SelectedS3(); s3 != nil {
				return s3.queueMediaDeletionTx(c, q, m, target)
			}
		}
		return store.SelectedMediaDeleteItem{}, false, store.ErrNodeState
	})
	if err != nil {
		return result, err
	}
	byID := make(map[string]store.SelectedMediaDeleteItem, len(result.Items))
	for _, item := range result.Items {
		byID[item.ResourceID] = item
	}
	visible := store.SelectedMediaDeleteResult{Items: make([]store.SelectedMediaDeleteItem, 0, len(targets))}
	for _, target := range targets {
		visible.Items = append(visible.Items, byID[target.ResourceID])
	}
	return visible, nil
}

type MediaDeletionExecutor interface {
	FollowerMediaDeletionExecutor
	MasterLocalMediaDeletionExecutor
}

// DeleteMedia queues the whole selection before attempting any physical work.
// Retry and background recovery retain each exact operation and backend.
func (s *SelectedUploadRuntime) DeleteMedia(ctx context.Context, sessionHash string, targets []store.SelectedMediaDeleteTarget, audit store.AdminAudit, executor MediaDeletionExecutor) (store.SelectedMediaDeleteResult, error) {
	if selectedNil(executor) {
		return store.SelectedMediaDeleteResult{}, store.ErrNodeState
	}
	backends := make(map[string]sealedtree.MediaDeletionBackend, len(targets))
	result, err := s.queueMediaDeletions(ctx, sessionHash, targets, audit, backends)
	if err != nil {
		return result, err
	}
	for i, item := range result.Items {
		if ctx.Err() != nil {
			break
		}
		if item.State != store.SelectedMediaDeletePending {
			continue
		}
		if item.Directory {
			audit.SessionHash = sessionHash
			if done, err := s.finishDirectoryDeletion(ctx, item, audit); err == nil && done {
				result.Items[i].State = store.SelectedMediaDeleteDeleted
			}
			continue
		}
		switch backends[item.ResourceID] {
		case sealedtree.MediaDeletionFollower:
			err = s.AdvanceFollowerMediaDeletion(ctx, sessionHash, item, audit, executor)
		case sealedtree.MediaDeletionMasterLocal:
			err = s.AdvanceMasterLocalMediaDeletion(ctx, sessionHash, item, audit, executor)
		default:
			continue // S3 grants drain in the supervised worker before removal.
		}
		if err == nil {
			result.Items[i].State = store.SelectedMediaDeleteDeleted
		}
	}
	return result, nil
}

func (s *SelectedUploadRuntime) queueMediaDeletionBatch(ctx context.Context, sessionHash string, targets []store.SelectedMediaDeleteTarget, audit store.AdminAudit, limit int, queue func(context.Context, queryer, *sealedtree.CoordinatedMutation, store.SelectedMediaDeleteTarget) (store.SelectedMediaDeleteItem, bool, error)) (store.SelectedMediaDeleteResult, error) {
	var out store.SelectedMediaDeleteResult
	if len(targets) == 0 || len(targets) > limit {
		return out, sealedtree.ErrInvalid
	}
	lease, err := s.lease(ctx, sessionHash)
	if err != nil {
		return out, err
	}
	defer lease.Release()
	err = s.repo.withSelectedMutation(ctx, s.tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
		if err := lease.Check(c); err != nil {
			return err
		}
		objects := make(map[string]bool, len(targets))
		paths := make(map[string]bool, len(targets))
		queued := 0
		for _, target := range targets {
			if objects[target.ResourceID] || paths[target.Path] {
				return sealedtree.ErrInvalid
			}
			objects[target.ResourceID], paths[target.Path] = true, true
			item, changed, err := queue(c, q, m, target)
			if err != nil {
				return err
			}
			out.Items = append(out.Items, item)
			if changed {
				queued++
			}
		}
		if queued != 0 {
			audit.SessionHash, audit.Action, audit.Result, audit.TargetCount = sessionHash, "opaque-media-delete-request", "pending", queued
			audit.SourceSummary, audit.Detail = "", ""
			if err := appendAudit(c, q, audit); err != nil {
				return err
			}
		}
		return lease.Check(c)
	})
	if err != nil {
		return store.SelectedMediaDeleteResult{}, err
	}
	return out, nil
}

// refundDeletedMediaBytesTx reconciles committed bytes only. The opaque
// capacity account tracks outstanding reservations, not completed objects.
func (r *Repository) refundDeletedMediaBytesTx(ctx context.Context, q queryer, memberID, expectedKind string, bytes int64) error {
	member, err := scanMember(q.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?"+r.lock(), memberID))
	if err != nil || member.Kind != expectedKind || bytes < 0 || member.Used < bytes {
		return store.ErrNodeState
	}
	result, err := q.ExecContext(ctx, `UPDATE cluster_storage_members SET used_bytes=used_bytes-? WHERE member_id=? AND member_kind=? AND used_bytes=?`, bytes, memberID, expectedKind, member.Used)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return store.ErrNodeState
	}
	return nil
}

type FollowerMediaDeletionExecutor interface {
	AdvanceOpaqueFollowerMediaDeletion(context.Context, *sealedtree.SQLStore, string, string, store.OwnerControlLease, func(context.Context) error) error
}

// DeleteFollowerMedia accepts an exact selection and makes a bounded attempt
// to finish it. Failure after the queue commits is reported as pending and
// the same operation can be resumed by a later authorized request.
func (s *SelectedUploadRuntime) DeleteFollowerMedia(ctx context.Context, sessionHash string, targets []store.SelectedMediaDeleteTarget, audit store.AdminAudit, executor FollowerMediaDeletionExecutor) (store.SelectedMediaDeleteResult, error) {
	if selectedNil(executor) {
		return store.SelectedMediaDeleteResult{}, store.ErrNodeState
	}
	result, err := s.QueueFollowerMediaDeletions(ctx, sessionHash, targets, audit)
	if err != nil {
		return result, err
	}
	for i, item := range result.Items {
		if ctx.Err() != nil {
			break
		}
		if item.State == store.SelectedMediaDeletePending && s.AdvanceFollowerMediaDeletion(ctx, sessionHash, item, audit, executor) == nil {
			result.Items[i].State = store.SelectedMediaDeleteDeleted
		}
	}
	return result, nil
}

// AdvanceFollowerMediaDeletion resumes the already-durable operation. Release
// the shared Owner fence after the remote proof before taking the exclusive
// Owner/ingress/tree transaction for the catalog and quota settlement.
func (s *SelectedUploadRuntime) AdvanceFollowerMediaDeletion(ctx context.Context, sessionHash string, item store.SelectedMediaDeleteItem, audit store.AdminAudit, executor FollowerMediaDeletionExecutor) error {
	if selectedNil(executor) || item.State != store.SelectedMediaDeletePending || !nodeHashPattern.MatchString(item.ResourceID) || !nodeIDPattern.MatchString(item.OperationID) {
		return store.ErrNodeState
	}
	lease, err := s.lease(ctx, sessionHash)
	if err != nil {
		return err
	}
	defer lease.Release()
	return s.advanceFollowerMediaDeletion(ctx, sessionHash, item.ResourceID, item.OperationID, audit, executor, lease)
}

func (s *SelectedUploadRuntime) advanceFollowerMediaDeletion(ctx context.Context, sessionHash, objectID, operationID string, audit store.AdminAudit, executor FollowerMediaDeletionExecutor, lease SelectedUploadRuntimeLease) error {
	owner, err := s.repo.AcquireOwnerControlShared(ctx)
	if err != nil {
		return err
	}
	err = executor.AdvanceOpaqueFollowerMediaDeletion(ctx, s.tree, objectID, operationID, owner, lease.Check)
	owner.Release()
	if err != nil {
		return err
	}
	_, err = s.finishNativeMediaDeletion(ctx, sessionHash, objectID, operationID, audit, lease)
	return err
}

// FinishNativeMediaDeletion is the last step of an authenticated Admin
// deletion. It requires the durable owner receipt and commits quota and
// audit together with removal from the catalog. It cannot start deletion.
func (s *SelectedUploadRuntime) FinishNativeMediaDeletion(ctx context.Context, sessionHash, objectID, operationID string, audit store.AdminAudit) (bool, error) {
	lease, err := s.lease(ctx, sessionHash)
	if err != nil {
		return false, err
	}
	defer lease.Release()
	return s.finishNativeMediaDeletion(ctx, sessionHash, objectID, operationID, audit, lease)
}

func (s *SelectedUploadRuntime) finishNativeMediaDeletion(ctx context.Context, sessionHash, objectID, operationID string, audit store.AdminAudit, lease SelectedUploadRuntimeLease) (bool, error) {
	already := false
	err := s.repo.withSelectedMutation(ctx, s.tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
		if lease.Check(c) != nil {
			return store.ErrNodeState
		}
		deleted, err := m.FinalizeOpaqueMediaDeletionTx(c, q, objectID, operationID)
		if err != nil {
			return err
		}
		if deleted.Already {
			already = true
			return lease.Check(c)
		}
		if err = s.repo.refundDeletedMediaBytesTx(c, q, deleted.OwnerID, "Follower", deleted.Bytes); err != nil {
			return err
		}
		audit.SessionHash, audit.Action, audit.Result, audit.TargetCount = sessionHash, "opaque-media-delete", "success", 1
		audit.SourceSummary, audit.Detail = "", ""
		if err = appendAudit(c, q, audit); err != nil {
			return err
		}
		return lease.Check(c)
	})
	return already && err == nil, err
}

// RunFollowerMediaDeletions resumes only Admin-queued Follower deletions.
// It keeps no owner or tree lease while sleeping and uses the existing
// bounded encrypted revocation index across restarts.
func (s *SelectedUploadRuntime) RunFollowerMediaDeletions(ctx context.Context, executor FollowerMediaDeletionExecutor) {
	if s == nil || s.repo == nil || s.tree == nil || selectedNil(s.gate) || selectedNil(executor) || ctx == nil {
		return
	}
	after := ""
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for ctx.Err() == nil {
		after = s.resumeFollowerMediaDeletionPage(ctx, executor, after)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (s *SelectedUploadRuntime) resumeFollowerMediaDeletionPage(ctx context.Context, executor FollowerMediaDeletionExecutor, after string) string {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	read, err := s.tree.AcquireReadFence(c)
	if err != nil {
		cancel()
		return after
	}
	items, next, err := s.tree.ListOpaqueRevocationsWithLease(c, read, after, 8)
	read.Release()
	cancel()
	if err != nil {
		return after
	}
	for _, item := range items {
		if ctx.Err() != nil {
			break
		}
		intent := item.Intent
		if !intent.SelectedDelete || intent.Action != "delete" || intent.MasterID == intent.OwnerID {
			continue
		}
		c, cancel := context.WithTimeout(ctx, protocol.OpaqueDeletionVerificationTimeout+20*time.Second)
		lease, err := s.gate.AcquireSelectedUpload(c, s.tree)
		if !selectedNil(lease) {
			if err == nil && lease.Check(c) == nil {
				_ = s.advanceFollowerMediaDeletion(c, "", item.ObjectID, intent.OperationID, store.AdminAudit{}, executor, lease)
			}
			lease.Release()
		}
		cancel()
	}
	return next
}
