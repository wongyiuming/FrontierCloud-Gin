package business

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// RecordingAudioExpiryCursor is a bounded worker cursor, not client input or
// an authorization. A completed scan returns its zero value; starting again
// revisits scoped/temporarily busy rows without starving later pages.
type RecordingAudioExpiryCursor struct {
	UpdatedAt   int64
	RecordingID string
}

type RecordingAudioExpiryPage struct {
	Scanned int
	Expired int
	Next    RecordingAudioExpiryCursor
	More    bool
}

// ExpireUnstartedRecordingAudioPage scans at most limit rows using keyset
// pagination. Each row is independently revalidated under the real fences;
// legacy/unmatched and scoped records are never silently deleted. The caller
// is a trusted background coordinator and must bound rate and cancellation.
// Scoped cleanup and account-deletion reconciliation are still required
// before this worker can be installed as the complete production lifecycle.
func (s *SelectedUploadRuntime) ExpireUnstartedRecordingAudioPage(ctx context.Context, tree *sealedtree.SQLStore, cursor RecordingAudioExpiryCursor, limit int) (RecordingAudioExpiryPage, error) {
	var result RecordingAudioExpiryPage
	if s == nil || s.repo == nil || ctx == nil || tree == nil || tree != s.tree || limit < 1 || limit > 50 || cursor.UpdatedAt < 0 || (cursor.UpdatedAt == 0 && cursor.RecordingID != "") || (cursor.UpdatedAt > 0 && !nodeIDPattern.MatchString(cursor.RecordingID)) {
		return result, store.ErrRecordingState
	}
	cutoff := time.Now().Unix() - 3600
	rows, err := s.repo.db.QueryContext(ctx, `SELECT user_id,recording_id,updated_at FROM karaoke_recordings WHERE state='pending' AND updated_at<=? AND (updated_at>? OR (updated_at=? AND recording_id>?)) ORDER BY updated_at,recording_id LIMIT ?`, cutoff, cursor.UpdatedAt, cursor.UpdatedAt, cursor.RecordingID, limit+1)
	if err != nil {
		return result, err
	}
	type candidate struct {
		user, id string
		updated  int64
	}
	var candidates []candidate
	for rows.Next() {
		var v candidate
		if err = rows.Scan(&v.user, &v.id, &v.updated); err != nil {
			rows.Close()
			return result, err
		}
		candidates = append(candidates, v)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return result, err
	}
	if err = rows.Close(); err != nil {
		return result, err
	}
	result.More = len(candidates) > limit
	if result.More {
		candidates = candidates[:limit]
	}
	for _, v := range candidates {
		if !nodeIDPattern.MatchString(v.user) || !nodeIDPattern.MatchString(v.id) || v.updated <= 0 || v.updated > cutoff {
			return result, store.ErrRecordingState
		}
		expired, e := s.expireUnstartedRecordingAudio(ctx, tree, v.user, v.id)
		if e != nil {
			return result, e
		}
		result.Scanned++
		if expired {
			result.Expired++
		}
		result.Next = RecordingAudioExpiryCursor{UpdatedAt: v.updated, RecordingID: v.id}
	}
	if !result.More {
		result.Next = RecordingAudioExpiryCursor{}
	}
	return result, nil
}

// expireUnstartedRecordingAudio is a private system cleanup transaction. It
// only refunds an hour-old pending reservation if no Owner scope was ever
// issued; a scoped/active upload needs a separate signed cleanup workflow.
// The file ID, blob ID, capacity intent and keyed cancellation tombstone are
// retained permanently. This is not yet installed in the background worker.
func (s *SelectedUploadRuntime) expireUnstartedRecordingAudio(ctx context.Context, tree *sealedtree.SQLStore, userID, recordingID string) (bool, error) {
	if s == nil || s.repo == nil || ctx == nil || tree == nil || tree != s.tree || selectedNil(s.gate) || !nodeIDPattern.MatchString(userID) || !nodeIDPattern.MatchString(recordingID) {
		return false, store.ErrRecordingState
	}
	lease, err := s.gate.AcquireSelectedUpload(ctx, tree)
	if err != nil || selectedNil(lease) {
		return false, store.ErrNodeState
	}
	defer lease.Release()
	if lease.Check(ctx) != nil {
		return false, store.ErrNodeState
	}
	expired := false
	err = s.repo.withSelectedMutation(ctx, tree, func(c context.Context, q queryer, mutation *sealedtree.CoordinatedMutation) error {
		row, e := recordingLookup(q.QueryRowContext(c, "SELECT "+recordingColumns+" FROM karaoke_recordings WHERE recording_id=?"+s.repo.lock(), recordingID))
		if e != nil {
			return e
		}
		cutoff := time.Now().Unix() - 3600
		if row == nil || row.UserID != userID || row.State != "pending" || row.UpdatedAt <= 0 || row.UpdatedAt > cutoff {
			return nil
		}
		intent, _, _, found, e := s.repo.readRecordingAudioIntentTx(c, q, s.key, recordingID)
		if e != nil {
			return e
		}
		if !found || intent.MemberID != intent.MasterID {
			return nil
		}
		if intent.State != "pending" || intent.UserID != userID || row.MemberID != intent.MemberID || row.Bytes != intent.Bytes || row.SHA256 != nil {
			return store.ErrRecordingState
		}
		identity, e := readNode(c, q, s.repo.lock())
		if e != nil || identity.Role != "Master" || identity.ID != intent.MasterID {
			return store.ErrNodeState
		}
		binding, e := s.repo.recordingAudioOwnerBinding(c, q, s.key, identity, intent.MemberID)
		if e != nil || binding != intent.OwnerBinding {
			return store.ErrNodeState
		}
		index := opaqueCapacityIndex(s.key, intent.OperationID)
		var count int
		if q.QueryRowContext(c, `SELECT COUNT(*) FROM sealed_tree_capacity_scopes WHERE operation_index=?`+s.repo.lock(), index).Scan(&count) != nil {
			return store.ErrRecordingState
		}
		if count != 0 {
			return nil
		}
		if mutation.CheckUnstartedRecordingAudioTx(c, q, intent.Encryption, intent.Binding, intent.OperationID, intent.BlobID) != nil {
			return store.ErrRecordingState
		}
		capacity := OpaqueCapacityIntent{OperationID: intent.OperationID, MasterID: intent.MasterID, MemberID: intent.MemberID, BlobID: intent.BlobID, Digest: intent.Digest, Bytes: intent.Bytes}
		raw, e := json.Marshal(capacity)
		if e != nil {
			return e
		}
		marker := hex.EncodeToString(capacityMAC(s.key, "recording-audio-unstarted-expiry-v1", raw))
		clear(raw)
		if _, e = q.ExecContext(c, `INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)`, marker); e != nil {
			return store.ErrRecordingState
		}
		if e = s.repo.refundRecordingAudioReservationTx(c, q, s.key, intent); e != nil {
			return e
		}
		if e = s.repo.transitionRecordingAudioTx(c, q, s.key, intent, "pending", "cancelled"); e != nil {
			return e
		}
		updated, e := q.ExecContext(c, `UPDATE karaoke_recordings SET state='deleted',updated_at=? WHERE recording_id=? AND user_id=? AND state='pending' AND updated_at=?`, time.Now().Unix(), recordingID, userID, row.UpdatedAt)
		if e != nil {
			return e
		}
		if n, e := updated.RowsAffected(); e != nil || n != 1 {
			return store.ErrRecordingState
		}
		audit := store.KaraokeAudit{UserID: userID, Action: "recording-expire", Result: "success", Detail: map[string]any{"recording_id": recordingID, "size_bytes": intent.Bytes}}
		if e = s.repo.karaokeAudit(c, q, audit); e != nil {
			return e
		}
		if lease.Check(c) != nil {
			return store.ErrNodeState
		}
		expired = true
		return c.Err()
	})
	if err != nil {
		return false, err
	}
	return expired, nil
}

// refundRecordingAudioReservationTx consumes exactly one pending recording's
// quota. The caller must prove cleanup or that no Owner scope was ever issued
// and commit the terminal intent and public row in this transaction.
func (r *Repository) refundRecordingAudioReservationTx(c context.Context, q queryer, key []byte, intent recordingAudioIntent) error {
	index := opaqueCapacityIndex(key, intent.OperationID)
	var memberIndex, blobIndex, id string
	var sealed []byte
	if q.QueryRowContext(c, `SELECT member_index,blob_index,encryption_id,sealed FROM sealed_tree_capacity_intents WHERE operation_index=?`+r.lock(), index).Scan(&memberIndex, &blobIndex, &id, &sealed) != nil || !capacityIDExists(c, q, id, r.lock()) {
		return store.ErrRecordingState
	}
	capacity, e := openOpaqueCapacity(key, index, id, sealed)
	if e != nil || capacity.OperationID != intent.OperationID || capacity.MasterID != intent.MasterID || capacity.MemberID != intent.MemberID || capacity.BlobID != intent.BlobID || capacity.Digest != intent.Digest || capacity.Bytes != intent.Bytes || memberIndex != opaqueCapacityMemberIndex(key, intent.MemberID) || blobIndex != opaqueCapacityBlobIndex(key, intent.BlobID) {
		return store.ErrRecordingState
	}
	account, accountID, exists, e := r.readOpaqueCapacityAccount(c, q, key, intent.MemberID, r.lock())
	member, memberErr := scanMember(q.QueryRowContext(c, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?"+r.lock(), intent.MemberID))
	user, userErr := scanUser(q.QueryRowContext(c, "SELECT "+userColumns+" FROM karaoke_users WHERE user_id=?"+r.lock(), intent.UserID))
	if e != nil || !exists || memberErr != nil || userErr != nil || account.Total < intent.Bytes || account.Revision == math.MaxInt64 || member.Reserved < account.Total || user.Used < intent.Bytes || user.Quota < user.Used {
		return store.ErrRecordingState
	}
	account.Total -= intent.Bytes
	account.Revision++
	accountRaw, e := json.Marshal(account)
	if e != nil {
		return e
	}
	defer clear(accountRaw)
	newID, newSealed, e := sealCapacityRecord(key, memberIndex, accountRaw)
	if e != nil {
		return e
	}
	if _, e = q.ExecContext(c, `INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)`, newID); e != nil {
		return store.ErrRecordingState
	}
	updated, e := q.ExecContext(c, `UPDATE sealed_tree_capacity_accounts SET encryption_id=?,sealed=? WHERE member_index=? AND encryption_id=?`, newID, newSealed, memberIndex, accountID)
	if e != nil {
		return e
	}
	if n, e := updated.RowsAffected(); e != nil || n != 1 {
		return store.ErrRecordingState
	}
	updated, e = q.ExecContext(c, `UPDATE cluster_storage_members SET reserved_bytes=reserved_bytes-?,updated_at=? WHERE member_id=? AND reserved_bytes=?`, intent.Bytes, time.Now().Unix(), intent.MemberID, member.Reserved)
	if e != nil {
		return e
	}
	if n, e := updated.RowsAffected(); e != nil || n != 1 {
		return store.ErrRecordingState
	}
	updated, e = q.ExecContext(c, `UPDATE karaoke_users SET used_bytes=used_bytes-?,updated_at=? WHERE user_id=? AND used_bytes=?`, intent.Bytes, time.Now().Unix(), intent.UserID, user.Used)
	if e != nil {
		return e
	}
	if n, e := updated.RowsAffected(); e != nil || n != 1 {
		return store.ErrRecordingState
	}
	return nil
}
