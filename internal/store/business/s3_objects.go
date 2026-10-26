package business

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (r *Repository) S3RequestAbort(ctx context.Context, id string, a store.AdminAudit) (result store.S3Upload, err error) {
	err = r.write(ctx, func(q queryer) error {
		if err := s3Master(ctx, q, r.lock()); err != nil {
			return err
		}
		v, err := r.s3Upload(ctx, q, id, r.lock())
		if err != nil {
			return err
		}
		if v.State == "published" {
			return nodeConflict("published S3 objects require managed deletion")
		}
		if v.State == "aborted" || v.State == "aborting" {
			result = v
			return nil
		}
		if _, err = q.ExecContext(ctx, "UPDATE s3_uploads SET state='aborting',revision=revision+1,updated_at=? WHERE upload_id=?", time.Now().Unix(), id); err != nil {
			return err
		}
		a.Action, a.Result, a.TargetCount = "s3-upload-abort", "pending", 1
		if err = appendMutationAudit(ctx, q, a, []string{v.Reservation.Path}); err != nil {
			return err
		}
		result, err = r.s3Upload(ctx, q, id, "")
		return err
	})
	return
}

func s3AbsenceBinding(proof store.S3AbsenceProof, key, session, object, member, media string) bool {
	return proof.ObjectAbsent && proof.MultipartAbsent && proof.Key == key && proof.SessionID == session &&
		proof.ObjectID == object && proof.MemberID == member && proof.MediaID == media &&
		s3Opaque(proof.VersionID, 1024) && s3Opaque(proof.ETag, 512) && s3Opaque(proof.ProviderUploadID, 2048)
}

func (r *Repository) S3FinishAbort(ctx context.Context, id string, revision int64, proof store.S3AbsenceProof, a store.AdminAudit) (result store.S3Upload, err error) {
	err = r.write(ctx, func(q queryer) error {
		if err := s3Master(ctx, q, r.lock()); err != nil {
			return err
		}
		v, err := r.s3Upload(ctx, q, id, r.lock())
		if err != nil {
			return err
		}
		if v.State == "aborted" {
			result = v
			return nil
		}
		if err = s3Revision(v.Revision, revision); err != nil {
			return err
		}
		now := time.Now().Unix()
		if v.State != "aborting" || v.GrantUntil > now || v.CreateUncertain && v.ProviderUploadID == "" {
			return nodeConflict("S3 abort still has live grants or unresolved creation")
		}
		if !s3AbsenceBinding(proof, v.Key, id, v.ObjectID, v.Reservation.MemberID, v.Reservation.MediaID) || proof.ProviderUploadID != v.ProviderUploadID {
			return nodeConflict("S3 abort proof differs from its exact owned key and upload")
		}
		if v.Proof.ETag != "" && (proof.ETag != v.Proof.ETag || proof.VersionID != v.Proof.VersionID) {
			return nodeConflict("S3 abort object version changed")
		}
		var objects int64
		if err = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM global_media_objects WHERE media_id=?", v.Reservation.MediaID).Scan(&objects); err != nil {
			return err
		}
		if objects != 0 {
			return nodeConflict("S3 abort cannot release published quota")
		}
		member, err := r.s3Member(ctx, q, v.Reservation.MemberID, r.lock())
		if err != nil {
			return err
		}
		if v.Reservation.State != "reserved" || member.Reserved < v.Reservation.ExpectedBytes {
			return nodeConflict("S3 abort reservation accounting is inconsistent")
		}
		if _, err = q.ExecContext(ctx, "UPDATE cluster_storage_members SET reserved_bytes=reserved_bytes-?,updated_at=? WHERE member_id=?", v.Reservation.ExpectedBytes, now, member.ID); err != nil {
			return err
		}
		if _, err = q.ExecContext(ctx, "UPDATE cluster_upload_sessions SET state='cancelled',path_locator=NULL,updated_at=? WHERE upload_id=?", now, id); err != nil {
			return err
		}
		if err = retireEncryption(ctx, q, v.Reservation.MediaID); err != nil {
			return err
		}
		if _, err = q.ExecContext(ctx, "UPDATE s3_uploads SET state='aborted',create_uncertain=0,revision=revision+1,error_code='',updated_at=? WHERE upload_id=?", now, id); err != nil {
			return err
		}
		a.Action, a.Result, a.TargetCount = "s3-upload-aborted", "success", 1
		if err = appendMutationAudit(ctx, q, a, []string{v.Reservation.Path}); err != nil {
			return err
		}
		result, err = r.s3Upload(ctx, q, id, "")
		return err
	})
	return
}

func (r *Repository) s3Object(ctx context.Context, q queryer, id, lock string) (v store.S3Object, err error) {
	if !nodeHashPattern.MatchString(id) {
		return v, nodeConflict("invalid S3 object identity")
	}
	var media, member, key, object, raw string
	var created, updated int64
	err = q.QueryRowContext(ctx, "SELECT media_id,member_id,object_key,object_id,proof_json,state,revision,grant_until,error_code,created_at,updated_at FROM s3_objects WHERE media_id=?"+lock, id).Scan(
		&media, &member, &key, &object, &raw, &v.State, &v.Revision, &v.GrantUntil, &v.ErrorCode, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		err = s3Missing("object")
	}
	if err != nil {
		return
	}
	if len(raw) > 16384 || json.Unmarshal([]byte(raw), &v.Proof) != nil {
		return v, nodeConflict("invalid persisted S3 object proof")
	}
	v.Media, err = scanGlobal(q.QueryRowContext(ctx, "SELECT "+globalColumns+globalTables+" WHERE g.media_id=?"+lock, id))
	if err != nil {
		return
	}
	if media != id || v.Media.MemberID != member || v.Media.ObjectID != object || v.Media.Transport != "S3" ||
		v.Proof.Key != key || v.Proof.ObjectID != object || v.Proof.MemberID != member || v.Proof.MediaID != media ||
		v.Proof.Bytes != v.Media.Bytes || v.Proof.ETag != v.Media.ETag || v.Proof.SessionID == "" {
		return v, nodeConflict("S3 object proof and catalog binding differ")
	}
	metadata, err := readEncryption(ctx, q, id, lock)
	if err != nil {
		return v, err
	}
	v.Encrypted = metadata != nil
	return
}

func (r *Repository) S3Object(ctx context.Context, id string) (store.S3Object, error) {
	if err := s3Master(ctx, r.db, ""); err != nil {
		return store.S3Object{}, err
	}
	return r.s3Object(ctx, r.db, id, "")
}

func (r *Repository) S3IssueReadGrant(ctx context.Context, id string, requestedUntil int64) (result store.S3Object, err error) {
	err = r.write(ctx, func(q queryer) error {
		if err := s3Master(ctx, q, r.lock()); err != nil {
			return err
		}
		now := time.Now().Unix()
		if requestedUntil <= now || requestedUntil > now+store.S3GrantSeconds {
			return nodeConflict("S3 read authorization exceeds its bounded horizon")
		}
		v, err := r.s3Object(ctx, q, id, r.lock())
		if err != nil {
			return err
		}
		if v.State != "active" || v.Media.State != "active" {
			return nodeConflict("S3 object has pending mutation")
		}
		member, err := r.s3Member(ctx, q, v.Media.MemberID, r.lock())
		if err != nil {
			return err
		}
		if member.CleanupOnly || member.SealedCredentials == "" || member.ProbeState != "ready" || member.ProbeRevision != member.Revision || member.CredentialExpiresAt != 0 && member.CredentialExpiresAt <= now {
			return nodeConflict("S3 object has no current read credentials")
		}
		until := requestedUntil
		if member.CredentialExpiresAt != 0 {
			until = min(until, member.CredentialExpiresAt)
		}
		if _, err = q.ExecContext(ctx, "UPDATE s3_objects SET grant_until=?,updated_at=? WHERE media_id=?", max(v.GrantUntil, until), now, id); err != nil {
			return err
		}
		result, err = r.s3Object(ctx, q, id, "")
		return err
	})
	return
}

func (r *Repository) S3StartDelete(ctx context.Context, id string, a store.AdminAudit) (result store.S3Object, err error) {
	err = r.write(ctx, func(q queryer) error {
		if err := s3Master(ctx, q, r.lock()); err != nil {
			return err
		}
		v, err := r.s3Object(ctx, q, id, r.lock())
		if err != nil {
			return err
		}
		if v.State == "deleting" && v.Media.State == "pending_delete" {
			// Repeated failures rotate behind older pending work without minting
			// another delete revision, authorization horizon or pending audit.
			if _, err = q.ExecContext(ctx, "UPDATE s3_objects SET updated_at=? WHERE media_id=?", time.Now().Unix(), id); err != nil {
				return err
			}
			result = v
			return nil
		}
		if v.State != "active" || v.Media.State != "active" && v.Media.State != "pending_delete" {
			return nodeConflict("S3 object has another mutation")
		}
		if err = r.checkGlobalRenameScopes(ctx, q, []store.DeleteItem{{Path: v.Media.Path}}); err != nil {
			return err
		}
		now := time.Now().Unix()
		if _, err = q.ExecContext(ctx, "UPDATE global_media_objects SET state='pending_delete',updated_at=? WHERE media_id=?", now, id); err != nil {
			return err
		}
		if _, err = q.ExecContext(ctx, "UPDATE s3_objects SET state='deleting',revision=revision+1,error_code='',updated_at=? WHERE media_id=?", now, id); err != nil {
			return err
		}
		a.Action, a.Result, a.TargetCount = "s3-object-delete", "pending", 1
		if err = appendMutationAudit(ctx, q, a, []string{v.Media.Path}); err != nil {
			return err
		}
		result, err = r.s3Object(ctx, q, id, "")
		return err
	})
	return
}

func (r *Repository) S3FinishDelete(ctx context.Context, id string, revision int64, proof store.S3AbsenceProof, a store.AdminAudit) error {
	return r.write(ctx, func(q queryer) error {
		if err := s3Master(ctx, q, r.lock()); err != nil {
			return err
		}
		var count int64
		if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM s3_objects WHERE media_id=?", id).Scan(&count); err != nil {
			return err
		}
		if count == 0 {
			return nil
		}
		v, err := r.s3Object(ctx, q, id, r.lock())
		if err != nil {
			return err
		}
		if err = s3Revision(v.Revision, revision); err != nil {
			return err
		}
		if v.State != "deleting" || v.Media.State != "pending_delete" || v.GrantUntil > time.Now().Unix() {
			return nodeConflict("S3 deletion still has an active read or write grant")
		}
		if !s3AbsenceBinding(proof, v.Proof.Key, v.Proof.SessionID, v.Proof.ObjectID, v.Proof.MemberID, v.Proof.MediaID) ||
			proof.VersionID != v.Proof.VersionID || proof.ETag != v.Proof.ETag {
			return nodeConflict("S3 deletion absence has a different object version")
		}
		if err = r.completeGlobalDeleteProof(ctx, q, id, a, true); err != nil {
			return err
		}
		_, err = q.ExecContext(ctx, "DELETE FROM s3_objects WHERE media_id=?", id)
		return err
	})
}

func (r *Repository) S3PendingDeletes(ctx context.Context, limit int) ([]store.S3Object, error) {
	if err := s3Master(ctx, r.db, ""); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 500 {
		limit = 50
	}
	rows, err := r.db.QueryContext(ctx, "SELECT o.media_id FROM s3_objects o JOIN global_media_objects g ON g.media_id=o.media_id WHERE o.state='deleting' OR g.state='pending_delete' ORDER BY o.updated_at,o.media_id LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	result := []store.S3Object{}
	for _, id := range ids {
		v, err := r.s3Object(ctx, r.db, id, "")
		if err != nil {
			return nil, err
		}
		result = append(result, v)
	}
	return result, nil
}

var _ store.S3Repository = (*Repository)(nil)
