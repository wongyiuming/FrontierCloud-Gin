package business

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"time"
)

// The private volume job proves actual bytes and footer before this short SQL
// transaction. Master business metadata/user quota are not modified here.
func (r *Repository) CompletePeerRecordingPublication(ctx context.Context, relationship string, l store.MigrationLease, id string, receipt store.RecordingReceipt, free int64, a store.NodeAudit) error {
	if !validRecordingReceipt(receipt) || receipt.ID != id || free < 0 {
		return store.ErrMigrationState
	}
	return r.write(ctx, func(q queryer) error {
		h, n, state, e := r.checkPeerLease(ctx, q, relationship, l)
		if e != nil {
			return e
		}
		if n.ID != h.TargetID || state == "cancelling" {
			return store.ErrMigrationState
		}
		o, e := r.peerObjectBinding(ctx, q, l.TaskID, id)
		if e != nil {
			return e
		}
		p := o.Recording
		if o.Resource != "recording" || p == nil || p.ID != id || p.UserID != o.Parent || p.Bytes != receipt.Bytes || p.SHA256 != receipt.SHA256 || !store.RecordingProofSnapshotMatches(*p, receipt.Metadata) {
			return store.ErrMigrationState
		}
		var phase, hash, name string
		var size int64
		if e = q.QueryRowContext(ctx, "SELECT state,sha256,expected_bytes,physical_path FROM migration_storage_journal WHERE task_id=? AND logical_id=?"+r.lock(), l.TaskID, id).Scan(&phase, &hash, &size, &name); e != nil {
			return e
		}
		if (phase != "verified" && phase != "published") || hash != receipt.SHA256 || size != receipt.Bytes || name != o.TargetPath {
			return store.ErrMigrationState
		}
		var blocked int
		if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM karaoke_users WHERE user_id=? AND status IN ('deleting','deleted')", p.UserID).Scan(&blocked); e != nil {
			return e
		}
		if blocked != 0 {
			return store.ErrMigrationState
		}
		old, e := recordingLookup(q.QueryRowContext(ctx, "SELECT "+recordingColumns+" FROM karaoke_recordings WHERE recording_id=?"+r.lock(), id))
		if e != nil {
			return e
		}
		if phase == "published" {
			if old == nil || old.State != "ready" || old.MemberID != n.ID || old.UserID != p.UserID || old.Bytes != p.Bytes || old.SHA256 == nil || *old.SHA256 != p.SHA256 || old.Filename != p.Filename || old.ContentType != p.ContentType || !store.RecordingProofSnapshotMatches(*p, ptrMetadata(store.RecordingMetadataFor(*old))) {
				return store.ErrMigrationState
			}
			return nil
		}
		if old != nil && (old.State != "deleted" || old.MemberID != n.ID || old.UserID != p.UserID || old.Bytes != p.Bytes || old.SHA256 == nil || *old.SHA256 != p.SHA256 || old.Filename != p.Filename || old.ContentType != p.ContentType) {
			return store.ErrMigrationState
		}
		member, e := scanMember(q.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?"+r.lock(), n.ID))
		if e != nil {
			return e
		}
		var reserved int64
		if e = q.QueryRowContext(ctx, "SELECT reserved_bytes FROM migration_capacity WHERE task_id=? AND member_id=?"+r.lock(), l.TaskID, n.ID).Scan(&reserved); e != nil {
			return e
		}
		if reserved < p.Bytes || member.Reserved < p.Bytes {
			return store.ErrMigrationState
		}
		v := store.Recording{ID: id, UserID: p.UserID, MemberID: n.ID, Filename: p.Filename, ContentType: p.ContentType, Bytes: p.Bytes, CreatedAt: p.CreatedAt, UpdatedAt: time.Now().Unix(), Lyrics: []store.RecordingLyric{}}
		if receipt.Metadata != nil {
			v.Title = receipt.Metadata.Title
			v.Lyrics = receipt.Metadata.Lyrics
			v.EncryptedLyrics = receipt.Metadata.EncryptedLyrics
		}
		if !validRecording(v) {
			return store.ErrMigrationState
		}
		if v.EncryptedLyrics != nil {
			// A reverse migration reuses the original opaque ciphertext for this exact
			// logical recording. It cannot assign the file ID to any other recording.
			var fileID string
			var raw sql.NullString
			e = q.QueryRowContext(ctx, "SELECT file_id,descriptor_json FROM media_encryption WHERE object_kind='recording_lyric' AND object_id=?"+r.lock(), id).Scan(&fileID, &raw)
			if e != nil && !errors.Is(e, sql.ErrNoRows) {
				return e
			}
			if e == nil && !raw.Valid && fileID == v.EncryptedLyrics.Encryption.FileID {
				if old == nil || old.State != "deleted" {
					return store.ErrMigrationState
				}
				encoded, e := json.Marshal(v.EncryptedLyrics.Encryption)
				if e != nil {
					return e
				}
				if _, e = q.ExecContext(ctx, "UPDATE media_encryption SET descriptor_json=? WHERE object_kind='recording_lyric' AND object_id=? AND file_id=? AND descriptor_json IS NULL", string(encoded), id, fileID); e != nil {
					return e
				}
			} else if e = r.putEncryptionFor(ctx, q, "recording_lyric", id, &v.EncryptedLyrics.Encryption); e != nil {
				return e
			}
		}
		lyrics, e := store.EncodeRecordingReservation(v)
		if e != nil {
			return e
		}
		if old == nil {
			if e = insertRecording(ctx, q, v); e != nil {
				return e
			}
		}
		if _, e = q.ExecContext(ctx, "UPDATE karaoke_recordings SET state='ready',title=?,lyrics=?,sha256=?,created_at=?,updated_at=? WHERE recording_id=?", v.Title, string(lyrics), p.SHA256, p.CreatedAt, v.UpdatedAt, id); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "UPDATE cluster_storage_members SET used_bytes=used_bytes+?,reserved_bytes=reserved_bytes-?,physical_free_bytes=?,updated_at=? WHERE member_id=?", p.Bytes, p.Bytes, free, v.UpdatedAt, n.ID); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "UPDATE migration_capacity SET reserved_bytes=reserved_bytes-?,updated_at=? WHERE task_id=? AND member_id=?", p.Bytes, v.UpdatedAt, l.TaskID, n.ID); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "UPDATE migration_storage_journal SET state='published',updated_at=? WHERE task_id=? AND logical_id=?", v.UpdatedAt, l.TaskID, id); e != nil {
			return e
		}
		return r.nodeAudit(ctx, q, "peer-migration-recording-published", relationship, map[string]any{"task_id": l.TaskID, "recording_id": id, "bytes": p.Bytes}, a)
	})
}
