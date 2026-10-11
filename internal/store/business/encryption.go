package business

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

func (r *Repository) Encryption(ctx context.Context, id string) (*mediacrypto.Metadata, error) {
	return readEncryption(ctx, r.db, id, "")
}

func (r *Repository) RecordingEncryption(ctx context.Context, id string) (*mediacrypto.Metadata, error) {
	return readEncryptionFor(ctx, r.db, "recording_lyric", id, "")
}

func readEncryption(ctx context.Context, q queryer, id, lock string) (*mediacrypto.Metadata, error) {
	return readEncryptionFor(ctx, q, "media", id, lock)
}

func readEncryptionFor(ctx context.Context, q queryer, kind, id, lock string) (*mediacrypto.Metadata, error) {
	if kind != "media" && kind != "recording_lyric" {
		return nil, mediacrypto.ErrMetadata
	}
	var raw sql.NullString
	err := q.QueryRowContext(ctx, "SELECT descriptor_json FROM media_encryption WHERE object_kind=? AND object_id=?"+lock, kind, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) || err == nil && !raw.Valid {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var meta mediacrypto.Metadata
	if json.Unmarshal([]byte(raw.String), &meta) != nil || meta.Validate() != nil {
		return nil, mediacrypto.ErrMetadata
	}
	return &meta, nil
}
func (r *Repository) EncryptionUsed(ctx context.Context, fileID string) (bool, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM media_encryption WHERE file_id=?", fileID).Scan(&count)
	return count != 0, err
}

func (r *Repository) HasEncryption(ctx context.Context) (bool, error) {
	var exists bool
	err := r.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM media_encryption WHERE descriptor_json IS NOT NULL)").Scan(&exists)
	return exists, err
}

func (r *Repository) EncryptionKeyID(ctx context.Context) (string, error) {
	return readEncryptionKeyID(ctx, r.db, "")
}

func readEncryptionKeyID(ctx context.Context, q queryer, lock string) (string, error) {
	var id string
	err := q.QueryRowContext(ctx, "SELECT key_id FROM media_crypto_keys WHERE singleton=1"+lock).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err == nil && !nodeHashPattern.MatchString(id) {
		return "", mediacrypto.ErrPremaster
	}
	return id, err
}

// CheckEncryptionKey is startup-only and never rotates a durable key identity.
// A restored database with encrypted objects must already contain its verifier.
func (r *Repository) CheckEncryptionKey(ctx context.Context, id string) error {
	if !nodeHashPattern.MatchString(id) {
		return mediacrypto.ErrPremaster
	}
	return r.write(ctx, func(q queryer) error {
		old, err := readEncryptionKeyID(ctx, q, r.lock())
		if err != nil {
			return err
		}
		if old != "" {
			if !hmac.Equal([]byte(old), []byte(id)) {
				return mediacrypto.ErrPremaster
			}
			return nil
		}
		var encrypted bool
		if err = q.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM media_encryption WHERE descriptor_json IS NOT NULL)").Scan(&encrypted); err != nil {
			return err
		}
		if encrypted {
			return mediacrypto.ErrPremaster
		}
		_, err = q.ExecContext(ctx, "INSERT INTO media_crypto_keys(singleton,key_id,created_at) VALUES (1,?,?)", id, time.Now().Unix())
		return err
	})
}
func (r *Repository) putEncryption(ctx context.Context, q queryer, id string, meta *mediacrypto.Metadata) error {
	return r.putEncryptionFor(ctx, q, "media", id, meta)
}

func (r *Repository) putEncryptionFor(ctx context.Context, q queryer, kind, id string, meta *mediacrypto.Metadata) error {
	if meta == nil {
		return nil
	}
	if kind == "media" && !nodeHashPattern.MatchString(id) || kind == "recording_lyric" && !nodeIDPattern.MatchString(id) || kind != "media" && kind != "recording_lyric" {
		return mediacrypto.ErrMetadata
	}
	if err := meta.Validate(); err != nil {
		return err
	}
	var raw sql.NullString
	var fileID string
	err := q.QueryRowContext(ctx, "SELECT file_id,descriptor_json FROM media_encryption WHERE object_kind=? AND object_id=?"+r.lock(), kind, id).Scan(&fileID, &raw)
	if err == nil {
		// A storage appliance may retry the same signed Master object after its
		// private stage was interrupted. It does not consume a second object ID
		// or descriptor. New business reservations always allocate a new ID, and
		// the unique file ID still prevents reuse for any different object.
		if kind == "media" && !raw.Valid && fileID == meta.FileID {
			encoded, err := json.Marshal(meta)
			if err != nil {
				return err
			}
			_, err = q.ExecContext(ctx, "UPDATE media_encryption SET descriptor_json=? WHERE object_kind=? AND object_id=? AND descriptor_json IS NULL", string(encoded), kind, id)
			return err
		}
		var old mediacrypto.Metadata
		if !raw.Valid || json.Unmarshal([]byte(raw.String), &old) != nil || old != *meta {
			return mediacrypto.ErrMetadata
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var used string
	err = q.QueryRowContext(ctx, "SELECT file_id FROM media_encryption WHERE file_id=?"+r.lock(), meta.FileID).Scan(&used)
	if err == nil {
		return mediacrypto.ErrMetadata
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	encoded, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, "INSERT INTO media_encryption(object_kind,object_id,file_id,descriptor_json,created_at) VALUES (?,?,?,?,?)", kind, id, meta.FileID, string(encoded), time.Now().Unix())
	return err
}
func (r *Repository) checkEncryption(ctx context.Context, q queryer, id string, meta *mediacrypto.Metadata, size int64) error {
	actual, err := readEncryption(ctx, q, id, r.lock())
	if err != nil {
		return err
	}
	if (actual == nil) != (meta == nil) || actual != nil && (*actual != *meta || actual.CiphertextSize != size) {
		return mediacrypto.ErrMetadata
	}
	return nil
}

// Retain a small random-ID tombstone so cleanup never permits nonce reuse.
func retireEncryption(ctx context.Context, q queryer, id string) error {
	return retireEncryptionFor(ctx, q, "media", id)
}

func retireEncryptionFor(ctx context.Context, q queryer, kind, id string) error {
	if kind != "media" && kind != "recording_lyric" {
		return mediacrypto.ErrMetadata
	}
	_, err := q.ExecContext(ctx, "UPDATE media_encryption SET descriptor_json=NULL WHERE object_kind=? AND object_id=?", kind, id)
	return err
}
