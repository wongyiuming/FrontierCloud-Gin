package business

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// CompletePeerMediaPublication is called only after the volume transaction
// has synced a same-inode link from verified private material. Master authority
// is committed separately; this receipt alone cannot change a business owner.
func (r *Repository) CompletePeerMediaPublication(ctx context.Context, relationship string, l store.MigrationLease, logical string, o store.MediaObject, size int64, sha string, free int64, a store.NodeAudit) error {
	if !poolPath(store.LocalMedia{MediaObject: o, Bytes: size}) || !nodeHashPattern.MatchString(o.ID) || !nodeHashPattern.MatchString(sha) {
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
		var id, kind, name, hash, phase string
		var expected int64
		if e = q.QueryRowContext(ctx, "SELECT object_id,resource_kind,physical_path,expected_bytes,sha256,state FROM migration_storage_journal WHERE task_id=? AND logical_id=?"+r.lock(), l.TaskID, logical).Scan(&id, &kind, &name, &expected, &hash, &phase); e != nil {
			return e
		}
		if kind != "media" || id != o.ID || name != o.Path || expected != size || hash != sha || (phase != "verified" && phase != "published") {
			return store.ErrMigrationState
		}
		var actualID, actualName, actualKind string
		e = q.QueryRowContext(ctx, "SELECT media_id,media_path,object_kind FROM media_objects WHERE media_id=? OR path_locator=?"+r.lock(), o.ID, locator(o.Path)).Scan(&actualID, &actualName, &actualKind)
		if phase == "published" {
			if e != nil {
				return e
			}
			if actualID != o.ID || actualName != o.Path || actualKind != o.Kind {
				return store.ErrMigrationState
			}
			encryption, e := readEncryption(ctx, q, o.ID, r.lock())
			if e != nil {
				return e
			}
			if (encryption == nil) != (o.Encryption == nil) || encryption != nil && *encryption != *o.Encryption {
				return store.ErrMigrationState
			}
			return nil
		}
		if e == nil {
			return store.ErrMigrationState
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		member, e := scanMember(q.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?"+r.lock(), n.ID))
		if e != nil {
			return e
		}
		var reserved int64
		if e = q.QueryRowContext(ctx, "SELECT reserved_bytes FROM migration_capacity WHERE task_id=? AND member_id=?"+r.lock(), l.TaskID, n.ID).Scan(&reserved); e != nil {
			return e
		}
		if reserved < size || member.Reserved < size {
			return store.ErrMigrationState
		}
		if o.Encryption != nil && o.Encryption.CiphertextSize != size {
			return store.ErrMigrationState
		}
		if e = r.putEncryption(ctx, q, o.ID, o.Encryption); e != nil {
			return e
		}
		if e = r.checkEncryption(ctx, q, o.ID, o.Encryption, size); e != nil {
			return e
		}
		now := time.Now()
		stamp := timestamp(now)
		if _, e = q.ExecContext(ctx, "INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES (?,?,?,?,?,?)", o.ID, o.Kind, o.Path, locator(o.Path), stamp, stamp); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "UPDATE cluster_storage_members SET used_bytes=used_bytes+?,reserved_bytes=reserved_bytes-?,physical_free_bytes=?,updated_at=? WHERE member_id=?", size, size, max(0, free), now.Unix(), n.ID); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "UPDATE migration_capacity SET reserved_bytes=reserved_bytes-?,updated_at=? WHERE task_id=? AND member_id=?", size, now.Unix(), l.TaskID, n.ID); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "UPDATE migration_storage_journal SET state='published',updated_at=? WHERE task_id=? AND logical_id=?", now.Unix(), l.TaskID, logical); e != nil {
			return e
		}
		return r.nodeAudit(ctx, q, "peer-migration-media-published", relationship, map[string]any{"task_id": l.TaskID, "logical_id": logical, "object_id": o.ID, "bytes": size}, a)
	})
}
