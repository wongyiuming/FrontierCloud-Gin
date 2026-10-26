package business

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const s3UploadColumns = "upload_id,member_id,object_key,object_id,provider_upload_id,state,revision,credential_revision,create_uncertain,grant_until,absolute_expires_at,confirmed_bytes,proof_json,error_code,created_at,updated_at"
const s3PartColumns = "part_number,size_bytes,checksum_sha256,etag,confirmed,grant_until"

func (r *Repository) reserveS3(ctx context.Context, q queryer, reservation store.UploadReservation) error {
	member, err := r.s3Member(ctx, q, reservation.MemberID, r.lock())
	if err != nil {
		return err
	}
	if member.CleanupOnly || member.Enabled == 0 || member.ProbeState != "ready" || member.ProbeRevision != member.Revision {
		return nodeConflict("S3 member no longer admits placement")
	}
	now := time.Now().Unix()
	_, err = q.ExecContext(ctx, "INSERT INTO s3_uploads("+s3UploadColumns+") VALUES (?,?,?,?,'','reserved',1,?,0,0,?,0,'{}','',?,?)",
		reservation.ID, reservation.MemberID, "objects/"+reservation.MediaID+"/"+reservation.ID,
		reservation.MediaID, member.CredentialRevision, now+store.S3AbsoluteSeconds, now, now)
	return err
}

func scanS3Part(row rowScanner) (v store.S3Part, err error) {
	err = row.Scan(&v.Number, &v.Bytes, &v.SHA256, &v.ETag, &v.Confirmed, &v.GrantUntil)
	return
}

func (r *Repository) s3Upload(ctx context.Context, q queryer, id, lock string) (v store.S3Upload, err error) {
	if !nodeIDPattern.MatchString(id) {
		return v, nodeConflict("invalid S3 upload identity")
	}
	var memberID, raw string
	var created, updated int64
	err = q.QueryRowContext(ctx, "SELECT "+s3UploadColumns+" FROM s3_uploads WHERE upload_id=?"+lock, id).Scan(
		&v.Reservation.ID, &memberID, &v.Key, &v.ObjectID, &v.ProviderUploadID, &v.State, &v.Revision, &v.CredentialRevision,
		&v.CreateUncertain, &v.GrantUntil, &v.AbsoluteExpiresAt, &v.ConfirmedBytes, &raw, &v.ErrorCode, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		err = s3Missing("upload")
	}
	if err != nil {
		return
	}
	v.Reservation, err = scanUpload(q.QueryRowContext(ctx, "SELECT "+uploadColumns+" FROM cluster_upload_sessions WHERE upload_id=?"+lock, id))
	if err != nil {
		return
	}
	if v.Reservation.MemberID != memberID || v.Reservation.MediaID != v.ObjectID || v.Reservation.ExpectedBytes < 1 ||
		v.Reservation.ExpectedBytes > store.S3MaxObjectBytes || len(raw) > 16384 || json.Unmarshal([]byte(raw), &v.Proof) != nil {
		return v, nodeConflict("S3 upload journal binding is inconsistent")
	}
	member, err := r.s3Member(ctx, q, memberID, lock)
	if err != nil {
		return v, err
	}
	v.Reservation.Member = member.StorageMember
	v.Reservation.Encryption, err = readEncryption(ctx, q, v.Reservation.MediaID, lock)
	if err != nil {
		return v, err
	}
	rows, err := q.QueryContext(ctx, "SELECT "+s3PartColumns+" FROM s3_upload_parts WHERE upload_id=? ORDER BY part_number"+lock, id)
	if err != nil {
		return v, err
	}
	defer rows.Close()
	v.Parts = []store.S3Part{}
	for rows.Next() {
		part, err := scanS3Part(rows)
		if err != nil {
			return v, err
		}
		if len(v.Parts) >= int(store.S3MaxObjectBytes/store.S3PartBytes) {
			return v, nodeConflict("S3 upload has too many parts")
		}
		v.Parts = append(v.Parts, part)
	}
	return v, rows.Err()
}

func (r *Repository) S3Upload(ctx context.Context, id string) (store.S3Upload, error) {
	if err := s3Master(ctx, r.db, ""); err != nil {
		return store.S3Upload{}, err
	}
	return r.s3Upload(ctx, r.db, id, "")
}

func (r *Repository) s3Uploads(ctx context.Context, limit int, recovery bool) ([]store.S3Upload, error) {
	if err := s3Master(ctx, r.db, ""); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 500 {
		limit = 50
	}
	query := "SELECT u.upload_id FROM s3_uploads u JOIN cluster_upload_sessions g ON g.upload_id=u.upload_id WHERE u.state NOT IN ('published','aborted')"
	args := []any{}
	if recovery {
		query += " AND (u.state IN ('creating','create_unknown','completing','aborting') OR g.expires_at<=? OR u.absolute_expires_at<=?)"
		now := time.Now().Unix()
		args = append(args, now, now)
	}
	query += " ORDER BY u.updated_at,u.upload_id LIMIT ?"
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, query, args...)
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
	result := []store.S3Upload{}
	for _, id := range ids {
		v, err := r.s3Upload(ctx, r.db, id, "")
		if err != nil {
			return nil, err
		}
		result = append(result, v)
	}
	return result, nil
}

func (r *Repository) S3PendingUploads(ctx context.Context, limit int) ([]store.S3Upload, error) {
	return r.s3Uploads(ctx, limit, false)
}
func (r *Repository) S3RecoveryUploads(ctx context.Context, limit int) ([]store.S3Upload, error) {
	return r.s3Uploads(ctx, limit, true)
}

func s3Live(v store.S3Upload, now int64) bool {
	return v.Reservation.State == "reserved" && v.Reservation.ExpiresAt > now && v.AbsoluteExpiresAt > now
}

func (r *Repository) s3WritableUpload(ctx context.Context, q queryer, v store.S3Upload) (store.S3Member, error) {
	member, err := r.s3Member(ctx, q, v.Reservation.MemberID, r.lock())
	if err != nil {
		return member, err
	}
	if member.CleanupOnly || member.Enabled == 0 || member.SealedCredentials == "" || member.CredentialRevision != v.CredentialRevision ||
		member.ProbeState != "ready" || member.ProbeRevision != member.Revision || member.CredentialExpiresAt != 0 && member.CredentialExpiresAt <= time.Now().Unix() {
		return member, nodeConflict("S3 upload credentials or admission changed")
	}
	return member, nil
}

func (r *Repository) S3StartCreate(ctx context.Context, id string, revision int64) (result store.S3Upload, err error) {
	err = r.write(ctx, func(q queryer) error {
		if err := s3Master(ctx, q, r.lock()); err != nil {
			return err
		}
		v, err := r.s3Upload(ctx, q, id, r.lock())
		if err != nil {
			return err
		}
		if err = s3Revision(v.Revision, revision); err != nil {
			return err
		}
		if (v.State != "reserved" && v.State != "create_rejected") || !s3Live(v, time.Now().Unix()) || v.CreateUncertain {
			return nodeConflict("S3 creation requires a fresh unambiguous reservation")
		}
		if _, err = r.s3WritableUpload(ctx, q, v); err != nil {
			return err
		}
		if _, err = q.ExecContext(ctx, "UPDATE s3_uploads SET state='creating',create_uncertain=1,revision=revision+1,error_code='',updated_at=? WHERE upload_id=?", time.Now().Unix(), id); err != nil {
			return err
		}
		result, err = r.s3Upload(ctx, q, id, "")
		return err
	})
	return
}

func (r *Repository) S3FinishCreate(ctx context.Context, id string, revision int64, providerID, outcome, code string) (result store.S3Upload, err error) {
	if !s3Opaque(providerID, 2048) || !s3Code(code) || outcome != "created" && outcome != "rejected" && outcome != "unknown" || outcome == "created" && providerID == "" || outcome == "rejected" && providerID != "" {
		return result, nodeConflict("invalid S3 creation outcome")
	}
	err = r.write(ctx, func(q queryer) error {
		if err := s3Master(ctx, q, r.lock()); err != nil {
			return err
		}
		v, err := r.s3Upload(ctx, q, id, r.lock())
		if err != nil {
			return err
		}
		if err = s3Revision(v.Revision, revision); err != nil {
			return err
		}
		if v.State != "creating" && v.State != "create_unknown" && v.State != "aborting" {
			return nodeConflict("S3 creation outcome has no matching intent")
		}
		if v.State == "aborting" && !v.CreateUncertain && v.ProviderUploadID == "" {
			return nodeConflict("S3 cancellation has no preceding creation intent")
		}
		if (v.State == "create_unknown" || v.State == "aborting") && outcome == "rejected" {
			return nodeConflict("an empty provider observation cannot settle unknown creation")
		}
		if v.ProviderUploadID != "" && providerID != "" && providerID != v.ProviderUploadID {
			return nodeConflict("S3 provider upload identity changed")
		}
		state, uncertain := "created", false
		switch outcome {
		case "rejected":
			state = "create_rejected"
		case "unknown":
			state, uncertain = "create_unknown", true
		}
		// Recovery may discover the exact upload after cancellation won the CAS.
		// Bind that identity for cleanup without reopening write admission.
		if v.State == "aborting" {
			state = "aborting"
		}
		if providerID == "" {
			providerID = v.ProviderUploadID
		}
		if _, err = q.ExecContext(ctx, "UPDATE s3_uploads SET provider_upload_id=?,state=?,create_uncertain=?,revision=revision+1,error_code=?,updated_at=? WHERE upload_id=?",
			providerID, state, uncertain, code, time.Now().Unix(), id); err != nil {
			return err
		}
		result, err = r.s3Upload(ctx, q, id, "")
		return err
	})
	return
}

func s3PartSize(total int64, number int) int64 {
	count := (total + store.S3PartBytes - 1) / store.S3PartBytes
	if number < 1 || int64(number) > count {
		return 0
	}
	return min(store.S3PartBytes, total-int64(number-1)*store.S3PartBytes)
}

func s3SHA(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && base64.StdEncoding.EncodeToString(decoded) == value
}

func (r *Repository) touchS3(ctx context.Context, q queryer, v store.S3Upload, now int64) error {
	until := min(now+store.S3IdleSeconds, v.AbsoluteExpiresAt)
	_, err := q.ExecContext(ctx, "UPDATE cluster_upload_sessions SET expires_at=?,updated_at=? WHERE upload_id=? AND state='reserved'", until, now, v.Reservation.ID)
	return err
}

func (r *Repository) S3IssuePart(ctx context.Context, id string, number int, checksum string, size int64) (result store.S3Part, err error) {
	if !s3SHA(checksum) {
		return result, nodeConflict("S3 part requires canonical SHA256")
	}
	err = r.write(ctx, func(q queryer) error {
		if err := s3Master(ctx, q, r.lock()); err != nil {
			return err
		}
		v, err := r.s3Upload(ctx, q, id, r.lock())
		if err != nil {
			return err
		}
		now := time.Now().Unix()
		if v.State != "created" || !s3Live(v, now) || s3PartSize(v.Reservation.ExpectedBytes, number) != size || size < 1 {
			return nodeConflict("S3 part does not match the live reservation")
		}
		member, err := r.s3WritableUpload(ctx, q, v)
		if err != nil {
			return err
		}
		result = store.S3Part{Number: number, Bytes: size, SHA256: checksum}
		found, live := false, 0
		for _, part := range v.Parts {
			if part.Number == number {
				if part.Bytes != size || part.SHA256 != checksum {
					return nodeConflict("S3 part size and checksum are immutable")
				}
				result, found = part, true
			} else if !part.Confirmed && part.GrantUntil > now {
				live++
			}
		}
		if !result.Confirmed && live >= 2 {
			return nodeConflict("S3 upload already has two unconfirmed live grants")
		}
		until := min(now+store.S3GrantSeconds, v.AbsoluteExpiresAt)
		if member.CredentialExpiresAt != 0 {
			until = min(until, member.CredentialExpiresAt)
		}
		if until <= now {
			return nodeConflict("S3 credentials expired before signing")
		}
		result.GrantUntil = max(result.GrantUntil, until)
		if found {
			_, err = q.ExecContext(ctx, "UPDATE s3_upload_parts SET grant_until=?,updated_at=? WHERE upload_id=? AND part_number=?", result.GrantUntil, now, id, number)
		} else {
			_, err = q.ExecContext(ctx, "INSERT INTO s3_upload_parts(upload_id,part_number,size_bytes,checksum_sha256,etag,confirmed,grant_until,created_at,updated_at) VALUES (?,?,?,?,'',0,?,?,?)", id, number, size, checksum, result.GrantUntil, now, now)
		}
		if err != nil {
			return err
		}
		if err = r.touchS3(ctx, q, v, now); err != nil {
			return err
		}
		_, err = q.ExecContext(ctx, "UPDATE s3_uploads SET grant_until=?,revision=revision+1,updated_at=? WHERE upload_id=?", max(v.GrantUntil, result.GrantUntil), now, id)
		return err
	})
	return
}

func (r *Repository) S3ConfirmPart(ctx context.Context, id string, proof store.S3Part) (result store.S3Upload, err error) {
	if !s3SHA(proof.SHA256) || proof.ETag == "" || !s3Opaque(proof.ETag, 128) {
		return result, nodeConflict("invalid S3 confirmed part proof")
	}
	err = r.write(ctx, func(q queryer) error {
		if err := s3Master(ctx, q, r.lock()); err != nil {
			return err
		}
		v, err := r.s3Upload(ctx, q, id, r.lock())
		if err != nil {
			return err
		}
		if v.State != "created" || !s3Live(v, time.Now().Unix()) {
			return nodeConflict("S3 confirmation requires a live multipart upload")
		}
		found := false
		for _, part := range v.Parts {
			if part.Number != proof.Number {
				continue
			}
			found = true
			if part.Bytes != proof.Bytes || part.SHA256 != proof.SHA256 || part.Confirmed && part.ETag != proof.ETag {
				return nodeConflict("S3 confirmation disagrees with the immutable part grant")
			}
			if part.Confirmed {
				result = v
				return nil
			}
		}
		if !found {
			return nodeConflict("S3 part has no durable grant")
		}
		now := time.Now().Unix()
		if _, err = q.ExecContext(ctx, "UPDATE s3_upload_parts SET etag=?,confirmed=1,updated_at=? WHERE upload_id=? AND part_number=?", proof.ETag, now, id, proof.Number); err != nil {
			return err
		}
		if _, err = q.ExecContext(ctx, "UPDATE s3_uploads SET confirmed_bytes=confirmed_bytes+?,revision=revision+1,updated_at=? WHERE upload_id=?", proof.Bytes, now, id); err != nil {
			return err
		}
		if err = r.touchS3(ctx, q, v, now); err != nil {
			return err
		}
		result, err = r.s3Upload(ctx, q, id, "")
		return err
	})
	return
}

func (r *Repository) S3TouchUpload(ctx context.Context, id string) (result store.S3Upload, err error) {
	err = r.write(ctx, func(q queryer) error {
		if err := s3Master(ctx, q, r.lock()); err != nil {
			return err
		}
		v, err := r.s3Upload(ctx, q, id, r.lock())
		if err != nil {
			return err
		}
		now := time.Now().Unix()
		if !s3Live(v, now) || v.State == "aborting" || v.State == "aborted" || v.State == "published" {
			return nodeConflict("S3 upload cannot extend its deadline")
		}
		if err = r.touchS3(ctx, q, v, now); err != nil {
			return err
		}
		result, err = r.s3Upload(ctx, q, id, "")
		return err
	})
	return
}

func s3Composite(v store.S3Upload) (string, error) {
	count := (v.Reservation.ExpectedBytes + store.S3PartBytes - 1) / store.S3PartBytes
	if len(v.Parts) != int(count) || count < 1 || count > store.S3MaxObjectBytes/store.S3PartBytes {
		return "", nodeConflict("S3 upload does not contain every part")
	}
	hash := sha256.New()
	var size int64
	for index, part := range v.Parts {
		if !part.Confirmed || part.Number != index+1 || part.Bytes != s3PartSize(v.Reservation.ExpectedBytes, index+1) || !s3SHA(part.SHA256) || part.ETag == "" {
			return "", nodeConflict("S3 confirmed parts are incomplete or inconsistent")
		}
		digest, _ := base64.StdEncoding.DecodeString(part.SHA256)
		_, _ = hash.Write(digest)
		size += part.Bytes
	}
	if size != v.Reservation.ExpectedBytes || size != v.ConfirmedBytes {
		return "", nodeConflict("S3 confirmed-byte accounting differs from its reservation")
	}
	return base64.StdEncoding.EncodeToString(hash.Sum(nil)) + "-" + strconv.Itoa(len(v.Parts)), nil
}

func (r *Repository) S3StartComplete(ctx context.Context, id string, revision int64) (result store.S3Upload, err error) {
	err = r.write(ctx, func(q queryer) error {
		if err := s3Master(ctx, q, r.lock()); err != nil {
			return err
		}
		v, err := r.s3Upload(ctx, q, id, r.lock())
		if err != nil {
			return err
		}
		if err = s3Revision(v.Revision, revision); err != nil {
			return err
		}
		if v.State != "completing" && (v.State != "created" || !s3Live(v, time.Now().Unix())) {
			return nodeConflict("S3 completion has no live multipart intent")
		}
		if _, err = s3Composite(v); err != nil {
			return err
		}
		if v.State == "completing" {
			result = v
			return nil
		}
		if _, err = q.ExecContext(ctx, "UPDATE s3_uploads SET state='completing',revision=revision+1,error_code='',updated_at=? WHERE upload_id=?", time.Now().Unix(), id); err != nil {
			return err
		}
		result, err = r.s3Upload(ctx, q, id, "")
		return err
	})
	return
}

func (r *Repository) S3FinalizeUpload(ctx context.Context, id string, revision int64, proof store.S3ObjectProof, a store.AdminAudit) (result store.GlobalMedia, err error) {
	err = r.write(ctx, func(q queryer) error {
		if err := s3Master(ctx, q, r.lock()); err != nil {
			return err
		}
		v, err := r.s3Upload(ctx, q, id, r.lock())
		if err != nil {
			return err
		}
		if v.State == "published" {
			if proof != v.Proof || revision != v.Revision && revision != v.Revision-1 {
				return nodeConflict("published S3 completion cannot be replaced")
			}
			result, err = scanGlobal(q.QueryRowContext(ctx, "SELECT "+globalColumns+globalTables+" WHERE g.media_id=? AND g.state='active'", v.Reservation.MediaID))
			return err
		}
		if err = s3Revision(v.Revision, revision); err != nil {
			return err
		}
		if v.State != "completing" || v.CreateUncertain || v.ProviderUploadID == "" {
			return nodeConflict("S3 object has no exact completion intent")
		}
		composite, err := s3Composite(v)
		if err != nil {
			return err
		}
		if proof.Key != v.Key || proof.SessionID != id || proof.ObjectID != v.ObjectID || proof.MemberID != v.Reservation.MemberID ||
			proof.MediaID != v.Reservation.MediaID || proof.Bytes != v.Reservation.ExpectedBytes || proof.CompositeSHA256 != composite ||
			proof.ETag == "" || !s3Opaque(proof.ETag, 128) || !s3Opaque(proof.VersionID, 1024) {
			return nodeConflict("S3 object proof does not match its durable session and part proofs")
		}
		if err = r.finalizeUpload(ctx, q, id, v.ObjectID, proof.Bytes, proof.ETag, a, true, true, &result); err != nil {
			return err
		}
		raw, err := json.Marshal(proof)
		if err != nil {
			return err
		}
		now := time.Now().Unix()
		if _, err = q.ExecContext(ctx, "INSERT INTO s3_objects(media_id,member_id,object_key,object_id,proof_json,state,revision,grant_until,error_code,created_at,updated_at) VALUES (?,?,?,?,?,'active',1,?,'',?,?)",
			v.Reservation.MediaID, v.Reservation.MemberID, v.Key, v.ObjectID, string(raw), v.GrantUntil, now, now); err != nil {
			return err
		}
		_, err = q.ExecContext(ctx, "UPDATE s3_uploads SET state='published',proof_json=?,revision=revision+1,error_code='',updated_at=? WHERE upload_id=?", string(raw), now, id)
		return err
	})
	return
}

func (r *Repository) S3RecordUploadError(ctx context.Context, id string, revision int64, code string) error {
	if !s3Code(code) {
		return nodeConflict("invalid S3 recovery error code")
	}
	return r.write(ctx, func(q queryer) error {
		if err := s3Master(ctx, q, r.lock()); err != nil {
			return err
		}
		v, err := r.s3Upload(ctx, q, id, r.lock())
		if err != nil {
			return err
		}
		if err = s3Revision(v.Revision, revision); err != nil {
			return err
		}
		_, err = q.ExecContext(ctx, "UPDATE s3_uploads SET error_code=?,revision=revision+1,updated_at=? WHERE upload_id=?", code, time.Now().Unix(), id)
		return err
	})
}
