package business

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// This opt-in primitive is not installed by product startup. Its table and
// request_protected marker require a separately validated schema upgrade.
// Product startup must install the protected expiry query only after every
// participant, the schema migration and recovery have been verified.
type recordingRequestIntent struct {
	user, request, requestMAC, recording, owner, recordMAC, bindingMAC string
}

func recordingRequestHMAC(key []byte, domain string, fields ...[]byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(domain))
	var length [8]byte
	for _, field := range fields {
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		_, _ = mac.Write(length[:])
		_, _ = mac.Write(field)
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func recordingRequestPayloadMAC(key []byte, user, request string, body []byte) string {
	return recordingRequestHMAC(key, "frontiercloud:recording-request:v1\x00", []byte(user), []byte(request), body)
}

func recordingRequestBindingMAC(key []byte, value recordingRequestIntent) string {
	return recordingRequestHMAC(key, "frontiercloud:recording-request-binding:v1\x00", []byte(value.user), []byte(value.request), []byte(value.requestMAC), []byte(value.recording), []byte(value.owner), []byte(value.recordMAC))
}

func recordingRequestRecordMAC(key []byte, record store.Recording) (string, error) {
	lyrics, err := store.EncodeRecordingReservation(record)
	if err != nil {
		return "", err
	}
	return recordingRequestHMAC(key, "frontiercloud:recording-request-record:v1\x00", []byte(record.ID), []byte(record.UserID), []byte(record.MemberID), []byte(record.Filename), []byte(record.ContentType), []byte(strconv.FormatInt(record.Bytes, 10)), []byte(record.Title), lyrics), nil
}

func validRecordingRequestIdentity(user, request string, key []byte) bool {
	return nodeIDPattern.MatchString(user) && nodeIDPattern.MatchString(request) && len(key) == 32
}

func (r *Repository) readRecordingRequestIntent(ctx context.Context, q queryer, user, request string, key []byte) (*recordingRequestIntent, error) {
	var value recordingRequestIntent
	err := q.QueryRowContext(ctx, `SELECT user_id,request_id,request_mac,recording_id,owner_id,record_mac,binding_mac FROM recording_request_intents WHERE user_id=? AND request_id=?`+r.lock(), user, request).Scan(&value.user, &value.request, &value.requestMAC, &value.recording, &value.owner, &value.recordMAC, &value.bindingMAC)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if value.user != user || value.request != request || !nodeHashPattern.MatchString(value.requestMAC) || !nodeIDPattern.MatchString(value.recording) || !nodeIDPattern.MatchString(value.owner) || !nodeHashPattern.MatchString(value.recordMAC) || !nodeHashPattern.MatchString(value.bindingMAC) || !hmac.Equal([]byte(value.bindingMAC), []byte(recordingRequestBindingMAC(key, value))) {
		return nil, store.ErrRecordingState
	}
	return &value, nil
}

func (r *Repository) recordingRequestOrphan(ctx context.Context, q queryer, user, request string) (bool, error) {
	var id string
	err := q.QueryRowContext(ctx, "SELECT recording_id FROM karaoke_recordings WHERE user_id=? AND request_id=?"+r.lock(), user, request).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (r *Repository) recordingRequestRow(ctx context.Context, q queryer, intent *recordingRequestIntent, key []byte) (store.Recording, error) {
	var empty store.Recording
	if intent == nil {
		return empty, store.ErrRecordingMissing
	}
	record, err := recordingLookup(q.QueryRowContext(ctx, "SELECT "+recordingColumns+" FROM karaoke_recordings WHERE recording_id=?"+r.lock(), intent.recording))
	if err != nil {
		return empty, err
	}
	// A missing row is a retained terminal tombstone, never permission to
	// create a new reservation with the same request ID.
	if record == nil || record.ID != intent.recording || record.UserID != intent.user || record.MemberID != intent.owner || record.State != "pending" && record.State != "ready" {
		return empty, store.ErrRecordingState
	}
	var protected int
	var request sql.NullString
	if err := q.QueryRowContext(ctx, "SELECT request_protected,request_id FROM karaoke_recordings WHERE recording_id=?"+r.lock(), intent.recording).Scan(&protected, &request); err != nil || protected != 1 || !request.Valid || request.String != intent.request {
		return empty, store.ErrRecordingState
	}
	if record.State == "pending" {
		actual, err := recordingRequestRecordMAC(key, *record)
		if err != nil || !hmac.Equal([]byte(actual), []byte(intent.recordMAC)) {
			return empty, store.ErrRecordingState
		}
	}
	return *record, nil
}

func (r *Repository) recordingRequestAccounting(ctx context.Context, q queryer, record store.Recording, user store.KaraokeUser) (store.StorageMember, error) {
	var empty store.StorageMember
	member, err := scanMember(q.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?"+r.lock(), record.MemberID))
	if err != nil || member.ID != record.MemberID || record.Bytes <= 0 || user.Used < record.Bytes || record.State == "pending" && member.Reserved < record.Bytes || record.State == "ready" && member.Used < record.Bytes {
		return empty, store.ErrRecordingState
	}
	return member, nil
}

// ReserveRecordingRequest is only for a validated, authenticated new request
// protocol. Its stable key must come from a Master-only independently managed
// secret, not from a peer, browser, media key, or the encrypted-tree key.
func (r *Repository) ReserveRecordingRequest(ctx context.Context, request string, body, key []byte, value store.Recording, free int64, audit store.KaraokeAudit) (result store.Recording, member store.StorageMember, err error) {
	if ctx == nil || !validRecordingRequestIdentity(value.UserID, request, key) || len(body) == 0 || len(body) > store.MaxRecordingMetadata+8192 || !validRecording(value) || free < 0 {
		return result, member, store.ErrRecordingState
	}
	requestMAC := recordingRequestPayloadMAC(key, value.UserID, request, body)
	err = r.write(ctx, func(q queryer) error {
		if e := r.accountMaster(ctx, q); e != nil {
			return e
		}
		user, e := scanUser(q.QueryRowContext(ctx, "SELECT "+userColumns+" FROM karaoke_users WHERE user_id=?"+r.lock(), value.UserID))
		if errors.Is(e, sql.ErrNoRows) {
			return store.ErrUserMissing
		}
		if e != nil {
			return e
		}
		if user.Status != "active" {
			return store.ErrUserBlocked
		}
		intent, e := r.readRecordingRequestIntent(ctx, q, value.UserID, request, key)
		if e != nil {
			return e
		}
		if intent != nil {
			if !hmac.Equal([]byte(intent.requestMAC), []byte(requestMAC)) {
				return store.ErrRecordingState
			}
			result, e = r.recordingRequestRow(ctx, q, intent, key)
			if e != nil {
				return e
			}
			member, e = r.recordingRequestAccounting(ctx, q, result, user)
			return e
		}
		// The reservation marker is independently durable. If the intent is
		// missing but its protected row remains, never create a replacement.
		orphan, e := r.recordingRequestOrphan(ctx, q, value.UserID, request)
		if e != nil {
			return e
		}
		if orphan {
			return store.ErrRecordingState
		}
		if e = r.reserveRecordingTx(ctx, q, value, free, audit, &result, &member); e != nil {
			return e
		}
		marked, e := q.ExecContext(ctx, "UPDATE karaoke_recordings SET request_protected=1,request_id=? WHERE recording_id=? AND request_protected=0 AND request_id IS NULL", request, result.ID)
		if e != nil {
			return e
		}
		if count, e := marked.RowsAffected(); e != nil || count != 1 {
			return store.ErrRecordingState
		}
		intent = &recordingRequestIntent{user: value.UserID, request: request, requestMAC: requestMAC, recording: result.ID, owner: result.MemberID}
		intent.recordMAC, e = recordingRequestRecordMAC(key, result)
		if e != nil {
			return e
		}
		intent.bindingMAC = recordingRequestBindingMAC(key, *intent)
		_, e = q.ExecContext(ctx, `INSERT INTO recording_request_intents(user_id,request_id,request_mac,recording_id,owner_id,record_mac,binding_mac,created_at) VALUES(?,?,?,?,?,?,?,?)`, intent.user, intent.request, intent.requestMAC, intent.recording, intent.owner, intent.recordMAC, intent.bindingMAC, time.Now().Unix())
		return e
	})
	if err != nil {
		return store.Recording{}, store.StorageMember{}, err
	}
	return result, member, nil
}

// LookupRecordingRequest enables authenticated recovery without persisting the
// original request or automatically recreating a missing reservation.
func (r *Repository) LookupRecordingRequest(ctx context.Context, user, request string, key []byte) (result store.Recording, err error) {
	if ctx == nil || !validRecordingRequestIdentity(user, request, key) {
		return result, store.ErrRecordingState
	}
	err = r.write(ctx, func(q queryer) error {
		if e := r.accountMaster(ctx, q); e != nil {
			return e
		}
		account, e := scanUser(q.QueryRowContext(ctx, "SELECT "+userColumns+" FROM karaoke_users WHERE user_id=?"+r.lock(), user))
		if errors.Is(e, sql.ErrNoRows) {
			return store.ErrUserMissing
		}
		if e != nil {
			return e
		}
		if account.Status != "active" {
			return store.ErrUserBlocked
		}
		intent, e := r.readRecordingRequestIntent(ctx, q, user, request, key)
		if e != nil {
			return e
		}
		if intent == nil {
			orphan, e := r.recordingRequestOrphan(ctx, q, user, request)
			if e != nil {
				return e
			}
			if orphan {
				return store.ErrRecordingState
			}
			return store.ErrRecordingMissing
		}
		result, e = r.recordingRequestRow(ctx, q, intent, key)
		if e != nil {
			return e
		}
		_, e = r.recordingRequestAccounting(ctx, q, result, account)
		return e
	})
	if err != nil {
		return store.Recording{}, err
	}
	return result, nil
}

// StageExpiredLegacyRecordings mirrors the old expiry policy for legacy rows
// while excluding protected and inconsistent request-ID rows. It is not wired
// into the cleanup worker until the schema and all cooperating processes share
// this contract. Unknown new reservations are not evidence of empty storage.
func (r *Repository) StageExpiredLegacyRecordings(ctx context.Context, limit int) error {
	if ctx == nil {
		return store.ErrRecordingState
	}
	return r.write(ctx, func(q queryer) error {
		if err := r.accountMaster(ctx, q); err != nil {
			return err
		}
		now := time.Now().Unix()
		rows, err := q.QueryContext(ctx, `SELECT recording_id FROM karaoke_recordings WHERE state='pending' AND updated_at<=? AND request_protected=0 AND request_id IS NULL AND NOT EXISTS (SELECT 1 FROM recording_request_intents i WHERE i.recording_id=karaoke_recordings.recording_id) ORDER BY updated_at,recording_id LIMIT ?`+r.lock(), now-3600, min(100, max(1, limit)))
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err = rows.Close(); err != nil {
			return err
		}
		for _, id := range ids {
			if _, err = q.ExecContext(ctx, `UPDATE karaoke_recordings SET state='deleting',updated_at=? WHERE recording_id=? AND state='pending' AND request_protected=0 AND request_id IS NULL AND NOT EXISTS (SELECT 1 FROM recording_request_intents i WHERE i.recording_id=karaoke_recordings.recording_id)`, now, id); err != nil {
				return err
			}
		}
		return nil
	})
}

var _ store.RecordingRequestRepository = (*Repository)(nil)
