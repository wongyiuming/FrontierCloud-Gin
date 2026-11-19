package business

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/opaqueledger"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const selectedS3DeletionDrain = time.Duration(store.S3GrantSeconds+1) * time.Second

// QueueMediaDeletion records an exact Admin request without contacting the
// provider. The tree hides the pending file but keeps its path and capacity.
func (s *SelectedS3Coordinator) QueueMediaDeletion(ctx context.Context, adminHash string, target store.SelectedMediaDeleteTarget, audit store.AdminAudit) (store.SelectedMediaDeleteItem, error) {
	var out store.SelectedMediaDeleteItem
	if s == nil || s.upload == nil || ctx == nil || target.Path == "" || len(target.Path) > 4096 ||
		!nodeHashPattern.MatchString(target.ResourceID) || target.OperationID != "" && !nodeIDPattern.MatchString(target.OperationID) {
		return out, store.ErrNodeState
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	admin, err := s.upload.lease(ctx, adminHash)
	if err != nil {
		return out, err
	}
	defer admin.Release()
	r := s.upload.repo
	err = r.withSelectedMutation(ctx, s.upload.tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
		if admin.Check(c) != nil {
			return store.ErrNodeState
		}
		item, queued, err := s.queueMediaDeletionTx(c, q, m, target)
		if err != nil {
			return err
		}
		if queued {
			audit.SessionHash, audit.Action, audit.Result, audit.TargetCount = adminHash, "selected-s3-media-delete", "pending", 1
			audit.SourceSummary, audit.Detail = "", ""
			if err = appendAudit(c, q, audit); err != nil {
				return err
			}
		}
		out = item
		return admin.Check(c)
	})
	if err != nil {
		return store.SelectedMediaDeleteItem{}, err
	}
	return out, nil
}

// queueMediaDeletionTx performs only the database portion so a mixed Admin
// selection can be committed together with Local and Follower requests.
func (s *SelectedS3Coordinator) queueMediaDeletionTx(ctx context.Context, q queryer, m *sealedtree.CoordinatedMutation, target store.SelectedMediaDeleteTarget) (store.SelectedMediaDeleteItem, bool, error) {
	var out store.SelectedMediaDeleteItem
	if target.OperationID != "" {
		deleted, err := m.S3MediaDeletionRecordedTx(ctx, q, target.ResourceID, target.OperationID, target.Path)
		if err != nil {
			return out, false, err
		}
		if deleted {
			return store.SelectedMediaDeleteItem{SelectedMediaDeleteTarget: target, State: store.SelectedMediaDeleteDeleted}, false, nil
		}
	}
	view, err := m.ReadS3MediaDeletionTx(ctx, q, target.ResourceID)
	if err != nil || view.Path != target.Path || target.OperationID != "" && target.OperationID != view.Pending.OperationID {
		return out, false, sealedtree.ErrConflict
	}
	if _, err = s.verifyMediaDeletionTarget(ctx, q, m, view); err != nil {
		return out, false, err
	}
	intent, err := m.QueueS3MediaDeletionTx(ctx, q, view)
	if err != nil {
		return out, false, err
	}
	target.OperationID = intent.OperationID
	return store.SelectedMediaDeleteItem{SelectedMediaDeleteTarget: target, State: store.SelectedMediaDeletePending}, view.Pending.OperationID == "", nil
}

// Verify against the original publication ledger; an encrypted placement
// alone is insufficient to authorize provider mutation or a quota refund.
func (s *SelectedS3Coordinator) verifyMediaDeletionTarget(ctx context.Context, q queryer, m *sealedtree.CoordinatedMutation, target sealedtree.S3MediaDeletionTarget) (store.S3Member, error) {
	var empty store.S3Member
	r, key, placement := s.upload.repo, s.upload.key, target.Placement
	identity, err := readNode(ctx, q, r.lock())
	if err != nil || identity.Role != "Master" || placement.Encryption == nil {
		return empty, store.ErrNodeState
	}
	selected, _, found, err := r.selectedIntentAnyTx(ctx, q, key, placement.Proof.SessionID)
	capacity := selected.Capacity.capacity()
	if err != nil || !found || selected.State != "completed" || selected.Policy != "S3" ||
		capacity.MasterID != identity.ID || selected.MasterBinding != capacityMasterBinding(identity) ||
		capacity.MemberID != placement.MemberID || capacity.Bytes != placement.Proof.Bytes {
		return empty, store.ErrNodeState
	}
	intent, found, err := r.readSelectedS3IntentTx(ctx, q, key, capacity.OperationID)
	if err != nil || !found || intent.State != "completed" || !intent.ProofRecorded || intent.UploadID != selected.UploadID ||
		intent.ObjectID != placement.ObjectID || intent.MemberID != capacity.MemberID || intent.BlobID != capacity.BlobID ||
		intent.Bytes != capacity.Bytes || intent.Digest != capacity.Digest || intent.LocationBinding != selected.RelationshipBinding ||
		intent.ProviderProof != placement.Proof || intent.Encryption != *placement.Encryption {
		return empty, store.ErrNodeState
	}
	committed, err := m.ReadSelectedS3CompletedTx(ctx, q, intent.OperationID, intent.ObjectID, intent.BlobID)
	if err != nil || !reflect.DeepEqual(committed, placement) {
		return empty, store.ErrNodeState
	}
	var object, blob, mac string
	if q.QueryRowContext(ctx, `SELECT object_index,blob_index,receipt_mac FROM sealed_tree_operation_ids WHERE operation_id=? AND completed=1`,
		intent.OperationID).Scan(&object, &blob, &mac) != nil || opaqueledger.CompletionBinding(object, blob, mac) != selected.CompletionBinding {
		return empty, store.ErrNodeState
	}
	member, err := r.s3Member(ctx, q, intent.MemberID, r.lock())
	location := s3store.Config{Endpoint: member.Location.Endpoint, Bucket: member.Location.Bucket, Region: member.Location.Region,
		Prefix: member.Location.Prefix, AddressStyle: member.Location.Style}
	if err != nil || member.Kind != "S3" || member.Transport != "S3" || member.RelationshipID != nil ||
		member.Used < intent.Bytes || !placement.MatchesCurrentMember(member.ID, location) {
		return empty, store.ErrNodeState
	}
	return member, nil
}

func (s *SelectedS3Coordinator) settleMediaDeletion(ctx context.Context, pending sealedtree.PendingS3MediaDeletion, observedAt time.Time) error {
	if observedAt.IsZero() || time.Since(observedAt) < selectedS3DeletionDrain {
		return s3media.ErrPending
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tree, r := s.upload.tree, s.upload.repo
	gate, err := s.ready.AcquireSelectedS3(ctx, tree, pending.Intent.UploadID)
	if err != nil || selectedNil(gate) {
		return store.ErrNodeState
	}
	defer gate.Release()
	var target sealedtree.S3MediaDeletionTarget
	var member store.S3Member
	already := false
	err = r.withSelectedMutation(ctx, tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
		if gate.Check(c) != nil {
			return store.ErrNodeState
		}
		var e error
		already, e = m.S3MediaDeletionRecordedTx(c, q, pending.ObjectID, pending.Intent.OperationID, pending.Path)
		if e != nil || already {
			return e
		}
		target, e = m.ReadS3MediaDeletionTx(c, q, pending.ObjectID)
		if e != nil || target.Pending != pending.Intent || target.Path != pending.Path {
			return sealedtree.ErrConflict
		}
		member, e = s.verifyMediaDeletionTarget(c, q, m, target)
		return e
	})
	if err != nil || already {
		return err
	}
	binding, err := selectedS3MemberIdentityBinding(s.upload.key, member)
	if err != nil {
		return err
	}
	check := func(c context.Context) error {
		if gate.Check(c) != nil {
			return store.ErrNodeState
		}
		current, e := r.S3Member(c, member.ID)
		actual, bindErr := selectedS3MemberIdentityBinding(s.upload.key, current)
		if e != nil || bindErr != nil || actual != binding {
			return store.ErrNodeState
		}
		return c.Err()
	}
	if err = s.provider.WithSelectedProvider(ctx, member, func(c context.Context, provider s3store.Provider) error {
		return s3media.DeleteSelectedPublishedObject(c, provider, target.Placement.Proof, check)
	}); err != nil {
		return err
	}
	return r.withSelectedMutation(ctx, tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
		if gate.Check(c) != nil {
			return store.ErrNodeState
		}
		current, err := s.verifyMediaDeletionTarget(c, q, m, target)
		actual, bindErr := selectedS3MemberIdentityBinding(s.upload.key, current)
		if err != nil || bindErr != nil || actual != binding {
			return store.ErrNodeState
		}
		if err = m.FinalizeS3MediaDeletionTx(c, q, target); err != nil {
			return err
		}
		if err = r.refundDeletedMediaBytesTx(c, q, member.ID, "S3", target.Placement.Proof.Bytes); err != nil {
			return err
		}
		if err = appendAudit(c, q, store.AdminAudit{Action: "selected-s3-media-delete", Result: "success", TargetCount: 1}); err != nil {
			return err
		}
		return gate.Check(c)
	})
}

func (s *SelectedS3Coordinator) scanMediaDeletions(ctx context.Context, after string) ([]sealedtree.PendingS3MediaDeletion, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	lease, err := s.upload.tree.AcquireReadFence(ctx)
	if err != nil {
		return nil, "", err
	}
	defer lease.Release()
	return s.upload.tree.ListS3MediaDeletionsWithLease(ctx, lease, after, 32)
}

// RunMediaDeletions resumes durable work under the normal Master lifecycle.
// Each bounded snapshot waits a full monotonic bearer lifetime after it is
// observed, including after restart. No lock is held while grants drain.
func (s *SelectedS3Coordinator) RunMediaDeletions(ctx context.Context) {
	if s == nil || s.upload == nil || ctx == nil {
		return
	}
	after := ""
	for ctx.Err() == nil {
		batch, next, err := s.scanMediaDeletions(ctx, after)
		if err != nil {
			slog.Warn("S3 media deletion scan deferred")
		} else if len(batch) > 0 {
			observedAt := time.Now()
			if !waitS3Deletion(ctx, selectedS3DeletionDrain) {
				return
			}
			for _, pending := range batch {
				if err = s.settleMediaDeletion(ctx, pending, observedAt); err != nil && ctx.Err() == nil && !errors.Is(err, s3media.ErrPending) {
					slog.Warn("S3 media deletion remains pending")
				}
			}
		}
		after = next
		if !waitS3Deletion(ctx, 15*time.Second) {
			return
		}
	}
}

func waitS3Deletion(ctx context.Context, interval time.Duration) bool {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return ctx.Err() == nil
	}
}
