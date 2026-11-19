package business

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func selectedS3CancelBinding(key []byte, intent selectedS3Intent, version, etag string) (string, error) {
	if !validCapacityKey(key) || !validSelectedS3Intent(intent) || !selectedS3Text(version, 1024) || !selectedS3Text(etag, 512) {
		return "", store.ErrNodeState
	}
	raw, err := json.Marshal(struct {
		Operation      string `json:"operation"`
		Upload         string `json:"upload"`
		Member         string `json:"member"`
		Key            string `json:"key"`
		Owner          string `json:"owner"`
		ProviderUpload string `json:"provider_upload"`
		Version        string `json:"version"`
		ETag           string `json:"etag"`
	}{intent.OperationID, intent.UploadID, intent.MemberID, intent.Key, intent.Owner, intent.ProviderUploadID, version, etag})
	if err != nil {
		return "", store.ErrNodeState
	}
	defer clear(raw)
	return hex.EncodeToString(capacityMAC(key, "selected-s3-cancellation", raw)), nil
}

// requestSelectedS3Cancel durably prevents finalization before provider cleanup.
func (s *SelectedS3Coordinator) requestSelectedS3Cancel(ctx context.Context, uploadID string, u, ready SelectedUploadRuntimeLease) (selectedS3Intent, store.S3Member, error) {
	var intent selectedS3Intent
	var member store.S3Member
	r := s.upload.repo
	err := r.withSelectedMutation(ctx, s.upload.tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
		if u.Check(c) != nil || ready.Check(c) != nil {
			return store.ErrNodeState
		}
		selected, oldID, found, err := r.selectedIntentAnyTx(c, q, s.upload.key, uploadID)
		if err != nil || !found || selected.Policy != "S3" || selected.State != "pending" || r.selectedFinalizePolicyTx(c, q, s.upload.key, selected) != nil {
			return store.ErrNodeState
		}
		pending, err := m.ReadSelectedFileTx(c, q, selected.Capacity.OperationID)
		if err != nil || verifySelectedPendingBinding(s.upload.key, selected, pending) != nil {
			return store.ErrNodeState
		}
		intent, err = r.ensureSelectedS3ReservationTx(c, q, s.upload.key, selected, pending, false)
		if err != nil {
			return err
		}
		member, err = r.s3Member(c, q, intent.MemberID, r.lock())
		if err != nil {
			return err
		}
		if !selected.CancelRequested {
			selected.CancelRequested = true
			raw, e := json.Marshal(selected)
			if e != nil {
				return store.ErrNodeState
			}
			id, sealed, e := sealCapacityRecord(s.upload.key, opaqueCapacityIndex(s.upload.key, intent.OperationID), raw)
			clear(raw)
			if e != nil {
				return e
			}
			if _, e = q.ExecContext(c, `INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)`, id); e != nil {
				return e
			}
			res, e := q.ExecContext(c, `UPDATE selected_upload_intents SET encryption_id=?,sealed=? WHERE operation_index=? AND encryption_id=? AND state='pending'`, id, sealed, opaqueCapacityIndex(s.upload.key, intent.OperationID), oldID)
			if e != nil {
				return e
			}
			if n, e := res.RowsAffected(); e != nil || n != 1 {
				return store.ErrNodeState
			}
		}
		next := intent
		switch intent.Phase {
		case "creating":
			next.Phase = "create_unknown"
		case "uploading", "completing":
			next.Phase = "aborting"
		case "reserved", "create_unknown", "aborting":
		default:
			return store.ErrNodeState
		}
		if next.Phase != intent.Phase {
			next.Revision++
			if err = r.writeSelectedS3IntentTx(c, q, s.upload.key, next, func(_ context.Context, _ queryer, old selectedS3Intent, exists bool) error {
				if !exists || old != intent {
					return store.ErrNodeState
				}
				return nil
			}); err != nil {
				return err
			}
			intent = next
		}
		return c.Err()
	})
	return intent, member, err
}

// finishSelectedS3Cancel releases tree and quota only after either a reserved
// operation was never started, or the provider adapter proved exact cleanup.
func (r *Repository) finishSelectedS3Cancel(ctx context.Context, tree *sealedtree.SQLStore, key []byte, uploadID string, expected selectedS3Intent, version, etag string, checkAdmin func(context.Context) error) error {
	if checkAdmin == nil || expected.Phase != "reserved" && expected.Phase != "aborting" {
		return store.ErrNodeState
	}
	binding, err := selectedS3CancelBinding(key, expected, version, etag)
	if err != nil {
		return err
	}
	return r.withSelectedMutation(ctx, tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
		if err := checkAdmin(c); err != nil {
			return err
		}
		selected, oldID, found, err := r.selectedIntentAnyTx(c, q, key, uploadID)
		if err != nil || !found || selected.Policy != "S3" || selected.State != "pending" || !selected.CancelRequested || r.selectedFinalizePolicyTx(c, q, key, selected) != nil {
			return store.ErrNodeState
		}
		capacity := selected.Capacity.capacity()
		pending, err := m.ReadSelectedFileTx(c, q, capacity.OperationID)
		if err != nil || verifySelectedPendingBinding(key, selected, pending) != nil {
			return store.ErrNodeState
		}
		current, found, err := r.readSelectedS3IntentTx(c, q, key, capacity.OperationID)
		if err != nil || !found || current != expected || current.GrantUntil > time.Now().Unix() || current.Phase == "reserved" && (current.ProviderUploadID != "" || current.GrantUntil != 0) {
			return store.ErrNodeState
		}
		parent, found, err := r.readSelectedParentScope(c, q, key, selected.ParentID, capacity.MemberID)
		var parentID string
		if err != nil || !found || q.QueryRowContext(c, `SELECT encryption_id FROM selected_upload_parent_scopes WHERE parent_index=?`+r.lock(), selectedParentIndex(key, selected.ParentID)).Scan(&parentID) != nil {
			return store.ErrNodeState
		}
		account, accountID, found, err := r.readOpaqueCapacityAccount(c, q, key, capacity.MemberID, r.lock())
		member, memberErr := scanMember(q.QueryRowContext(c, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?"+r.lock(), capacity.MemberID))
		if err != nil || !found || memberErr != nil || account.Total < capacity.Bytes || account.Revision == math.MaxInt64 || member.Reserved < account.Total {
			return store.ErrNodeState
		}
		if err = m.CancelSelectedTx(c, q, capacity.OperationID, func(p sealedtree.SelectedPending) error { return verifySelectedPendingBinding(key, selected, p) }); err != nil {
			return err
		}
		if parent.Count == 1 {
			if parent.Bytes != capacity.Bytes {
				return store.ErrNodeState
			}
			res, e := q.ExecContext(c, `DELETE FROM selected_upload_parent_scopes WHERE parent_index=? AND encryption_id=?`, selectedParentIndex(key, selected.ParentID), parentID)
			if e != nil {
				return e
			}
			if n, e := res.RowsAffected(); e != nil || n != 1 {
				return store.ErrNodeState
			}
		} else {
			if parent.Count < 2 || parent.Bytes-capacity.Bytes < parent.Count-1 {
				return store.ErrNodeState
			}
			parent.Count--
			parent.Bytes -= capacity.Bytes
			if err = r.writeSelectedParentScope(c, q, key, parent, true); err != nil {
				return err
			}
		}
		account.Total -= capacity.Bytes
		account.Revision++
		raw, err := json.Marshal(account)
		if err != nil {
			return store.ErrNodeState
		}
		newID, sealed, err := sealCapacityRecord(key, opaqueCapacityMemberIndex(key, capacity.MemberID), raw)
		clear(raw)
		if err != nil {
			return err
		}
		if _, err = q.ExecContext(c, `INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)`, newID); err != nil {
			return err
		}
		result, err := q.ExecContext(c, `UPDATE sealed_tree_capacity_accounts SET encryption_id=?,sealed=? WHERE member_index=? AND encryption_id=?`, newID, sealed, opaqueCapacityMemberIndex(key, capacity.MemberID), accountID)
		if err != nil {
			return err
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			return store.ErrNodeState
		}
		result, err = q.ExecContext(c, `UPDATE cluster_storage_members SET reserved_bytes=reserved_bytes-? WHERE member_id=? AND reserved_bytes=?`, capacity.Bytes, capacity.MemberID, member.Reserved)
		if err != nil {
			return err
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			return store.ErrNodeState
		}
		if _, err = q.ExecContext(c, `DELETE FROM selected_s3_parts WHERE operation_index=?`, opaqueCapacityIndex(key, capacity.OperationID)); err != nil {
			return err
		}
		done := current
		done.Phase, done.State, done.CancellationBinding = "cancelled", "cancelled", binding
		done.Revision++
		if err = r.writeSelectedS3IntentTx(c, q, key, done, func(_ context.Context, _ queryer, old selectedS3Intent, exists bool) error {
			if !exists || old != current {
				return store.ErrNodeState
			}
			return nil
		}); err != nil {
			return err
		}
		selected.State, selected.CompletionBinding = "cancelled", binding
		raw, err = json.Marshal(selected)
		if err != nil {
			return store.ErrNodeState
		}
		id, selectedSealed, err := sealCapacityRecord(key, opaqueCapacityIndex(key, capacity.OperationID), raw)
		clear(raw)
		if err != nil {
			return err
		}
		if _, err = q.ExecContext(c, `INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)`, id); err != nil {
			return err
		}
		result, err = q.ExecContext(c, `UPDATE selected_upload_intents SET encryption_id=?,sealed=?,state='cancelled' WHERE operation_index=? AND encryption_id=? AND state='pending'`, id, selectedSealed, opaqueCapacityIndex(key, capacity.OperationID), oldID)
		if err != nil {
			return err
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			return store.ErrNodeState
		}
		return c.Err()
	})
}

// Cancel records cancellation before contacting the provider, waits for every
// outstanding signed part URL to expire, and only then verifies exact cleanup.
// The real readiness implementation must hold the per-operation cross-process
// lock throughout this method; otherwise it must not enable this coordinator.
func (s *SelectedS3Coordinator) Cancel(ctx context.Context, sessionHash, uploadID string) (SelectedS3Status, error) {
	var zero SelectedS3Status
	status, err := s.Status(ctx, sessionHash, uploadID)
	if err != nil {
		return zero, err
	}
	if status.State == "cancelled" || status.State == "deleted" {
		return status, nil
	}
	if status.State == "published" {
		return zero, store.ErrNodeState
	}
	u, ready, err := s.lease(ctx, sessionHash, uploadID)
	if err != nil {
		return zero, err
	}
	defer u.Release()
	readyHeld := true
	defer func() {
		if readyHeld {
			ready.Release()
		}
	}()
	intent, member, err := s.requestSelectedS3Cancel(ctx, uploadID, u, ready)
	if err != nil {
		return zero, err
	}
	if intent.GrantUntil > time.Now().Unix() {
		return zero, s3media.ErrPending
	}
	if intent.Phase == "create_unknown" {
		var providerID string
		err = s.provider.WithSelectedProvider(ctx, member, func(c context.Context, provider s3store.Provider) error {
			var e error
			providerID, e = s3media.DiscoverSelectedUpload(c, provider, intent.Key, intent.CreatedAt)
			return e
		})
		if err != nil {
			return zero, err
		}
		err = s.withPendingState(ctx, uploadID, u, ready, true, func(c context.Context, q queryer, current selectedS3Intent, _ store.S3Member) error {
			if current != intent {
				return store.ErrNodeState
			}
			found := current
			found.Phase, found.ProviderUploadID = "uploading", providerID
			found.Revision++
			if err := s.upload.repo.writeSelectedS3IntentTx(c, q, s.upload.key, found, func(_ context.Context, _ queryer, old selectedS3Intent, exists bool) error {
				if !exists || old != current {
					return store.ErrNodeState
				}
				return nil
			}); err != nil {
				return err
			}
			next := found
			next.Phase = "aborting"
			next.Revision++
			if err := s.upload.repo.writeSelectedS3IntentTx(c, q, s.upload.key, next, func(_ context.Context, _ queryer, old selectedS3Intent, exists bool) error {
				if !exists || old != found {
					return store.ErrNodeState
				}
				return nil
			}); err != nil {
				return err
			}
			intent = next
			return nil
		})
		if err != nil {
			return zero, err
		}
	}
	version, etag := "", ""
	if intent.Phase == "aborting" {
		err = s.provider.WithSelectedProvider(ctx, member, func(c context.Context, provider s3store.Provider) error {
			var e error
			version, etag, e = s3media.CleanupSelectedObject(c, provider, intent.Key, intent.ProviderUploadID, intent.Owner)
			return e
		})
		if err != nil {
			return zero, err
		}
	} else if intent.Phase != "reserved" {
		return zero, store.ErrNodeState
	}
	err = s.upload.repo.finishSelectedS3Cancel(ctx, s.upload.tree, s.upload.key, uploadID, intent, version, etag, func(c context.Context) error {
		if u.Check(c) != nil || ready.Check(c) != nil {
			return store.ErrNodeState
		}
		return nil
	})
	if err != nil {
		return zero, err
	}
	status.State, status.Reservation.ExpectedBytes, status.Parts = "cancelled", intent.Bytes, []SelectedS3PartView{}
	ready.Release()
	readyHeld = false
	if err = s.finishRecovery(ctx); err != nil {
		return zero, err
	}
	return status, nil
}
