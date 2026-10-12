package business

import (
	"context"
	"database/sql"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"time"
)

// This admission persists an exact target cancellation deletion fence. It does
// not delete bytes, change business ownership or refund used/reserved capacity.
func (r *Repository) PreparePeerMigrationShadowDeletion(ctx context.Context, rel string, l store.MigrationLease, g store.MigrationShadowGrant, a store.NodeAudit) error {
	return r.write(ctx, func(q queryer) error {
		h, n, state, e := r.checkPeerLease(ctx, q, rel, l)
		if e != nil {
			return e
		}
		expected, _ := store.MigrationDigest(h)
		actual, _ := store.MigrationDigest(g.Unit.Header)
		u := g.Unit.Unit
		o := g.Object
		proof := g.SourceProof
		if state != "cancelling" || n.ID != h.TargetID || expected != actual || u.State != "cancelled" || u.CommittedAt != 0 || u.CleanupAfter != 0 || !nodeHashPattern.MatchString(g.Unit.UnitVersion) || o.Resource != "media" || u.ID != migrationUnit(o) || u.Resource != o.Resource || u.Parent != o.Parent || !validPeerObject(h, store.MigrationPeerObject{Object: o, Proof: proof.MigrationDiskProof}) {
			return store.ErrMigrationState
		}
		bound, e := r.peerObjectBinding(ctx, q, l.TaskID, o.ID)
		if e != nil {
			return e
		}
		expected, e = store.MigrationDigest(bound)
		if e != nil {
			return e
		}
		actual, e = store.MigrationDigest(o)
		if e != nil || expected != actual {
			return store.ErrMigrationState
		}
		var rosterCount, rosterBytes int64
		if e = q.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(expected_bytes),0) FROM migration_storage_journal WHERE task_id=?", l.TaskID).Scan(&rosterCount, &rosterBytes); e != nil {
			return e
		}
		if rosterCount != h.ObjectCount || rosterBytes != h.Bytes {
			return store.ErrMigrationState
		}
		rows, e := q.QueryContext(ctx, "SELECT logical_id,sha256 FROM migration_storage_journal WHERE task_id=? AND unit_id=? ORDER BY logical_id", l.TaskID, u.ID)
		if e != nil {
			return e
		}
		type entry struct{ id, sha string }
		entries := []entry{}
		for rows.Next() {
			var row entry
			if e = rows.Scan(&row.id, &row.sha); e != nil {
				rows.Close()
				return e
			}
			entries = append(entries, row)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		objects := []store.MigrationPeerObject{}
		var total int64
		for _, entry := range entries {
			object, e := r.peerObjectBinding(ctx, q, l.TaskID, entry.id)
			if e != nil {
				return e
			}
			if migrationUnit(object) != u.ID || object.Parent != u.Parent || object.Resource != u.Resource {
				return store.ErrMigrationState
			}
			total += object.Bytes
			objects = append(objects, store.MigrationPeerObject{Object: object, Proof: store.MigrationDiskProof{ID: object.ID, Version: object.Version, Bytes: object.Bytes, SHA256: entry.sha}})
		}
		sha, e := store.MigrationUnitObjectsSHA(objects)
		if e != nil {
			return e
		}
		if int64(len(objects)) != u.ObjectCount || total != u.Bytes || sha != g.Unit.ObjectsSHA {
			return store.ErrMigrationState
		}
		var phase, hash, version string
		var size int64
		if e = q.QueryRowContext(ctx, "SELECT state,sha256,source_version,expected_bytes FROM migration_storage_journal WHERE task_id=? AND logical_id=?"+r.lock(), l.TaskID, o.ID).Scan(&phase, &hash, &version, &size); e != nil {
			return e
		}
		if hash != proof.SHA256 || version != proof.Version || size != proof.Bytes || proof.ID != o.ID || phase != "published" && phase != "deleting" && phase != "deleted" {
			return store.ErrMigrationState
		}
		now := time.Now().Unix()
		if phase == "published" && (proof.VerifiedAt < now-30 || proof.VerifiedAt > now+30) {
			return store.ErrMigrationState
		}
		var unitState, unitVersion string
		var count, bytes, committed, after int64
		e = q.QueryRowContext(ctx, "SELECT state,source_version,object_count,total_bytes,committed_at,cleanup_after FROM migration_units WHERE task_id=? AND unit_id=?"+r.lock(), l.TaskID, u.ID).Scan(&unitState, &unitVersion, &count, &bytes, &committed, &after)
		if e == nil {
			if unitState != "pending" || unitVersion != g.Unit.UnitVersion || count != u.ObjectCount || bytes != u.Bytes || committed != 0 || after != 0 {
				return store.ErrMigrationState
			}
		} else if !errors.Is(e, sql.ErrNoRows) {
			return e
		} else {
			if phase != "published" {
				return store.ErrMigrationState
			}
			if _, e = q.ExecContext(ctx, "INSERT INTO migration_units(task_id,unit_id,resource_kind,parent_path,source_version,state,object_count,total_bytes) VALUES (?,?,?,?,?,'pending',?,?)", l.TaskID, u.ID, u.Resource, u.Parent, g.Unit.UnitVersion, u.ObjectCount, u.Bytes); e != nil {
				return e
			}
		}
		if phase == "deleting" || phase == "deleted" {
			var failed int
			if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_objects WHERE task_id=? AND logical_id=? AND state='pending'", l.TaskID, o.ID).Scan(&failed); e != nil {
				return e
			}
			if failed != 0 {
				if proof.VerifiedAt < now-30 || proof.VerifiedAt > now+30 {
					return store.ErrMigrationState
				}
				if _, e = q.ExecContext(ctx, "DELETE FROM migration_objects WHERE task_id=? AND logical_id=? AND state='pending'", l.TaskID, o.ID); e != nil {
					return e
				}
			}
			return nil
		}
		var reads int
		if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_read_leases WHERE member_id=? AND (logical_id=? OR object_id=?) AND expires_at>?", n.ID, o.ID, o.ObjectID, now).Scan(&reads); e != nil {
			return e
		}
		if reads != 0 {
			return store.ErrMigrationState
		}
		if _, e = q.ExecContext(ctx, "UPDATE migration_storage_journal SET state='deleting',updated_at=? WHERE task_id=? AND logical_id=?", now, l.TaskID, o.ID); e != nil {
			return e
		}
		return r.nodeAudit(ctx, q, "peer-migration-shadow-delete-authorized", rel, map[string]any{"task_id": l.TaskID, "logical_id": o.ID, "unit_id": u.ID, "source_verified_at": proof.VerifiedAt, "source_sha256": proof.SHA256}, a)
	})
}
