package business

import (
	"context"
	"database/sql"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"time"
)

// PreparePeerMigrationCleanup records a deletion authorization from the active
// Master. It does not remove bytes, refund capacity or release an owned drain.
func (r *Repository) PreparePeerMigrationCleanup(ctx context.Context, relationship string, l store.MigrationLease, g store.MigrationCleanupGrant, a store.NodeAudit) error {
	now := time.Now().Unix()
	if !nodeHashPattern.MatchString(g.UnitVersion) || g.TaskID != l.TaskID || g.CommittedAt <= 0 || g.CleanupAfter < g.CommittedAt+3600 || g.CleanupAfter > now || g.TargetVerifiedAt < g.CommittedAt || g.TargetVerifiedAt < now-30 || g.TargetVerifiedAt > now+30 {
		return store.ErrMigrationState
	}
	return r.write(ctx, func(q queryer) error {
		h, n, state, e := r.checkPeerLease(ctx, q, relationship, l)
		if e != nil {
			return e
		}
		if state == "cancelling" || n.ID != h.SourceID || g.MasterID != h.MasterID || g.SourceID != h.SourceID || g.TargetID != h.TargetID || g.PlanSHA != h.PlanSHA {
			return store.ErrMigrationState
		}
		var rosterCount, rosterBytes int64
		if e = q.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(expected_bytes),0) FROM migration_storage_journal WHERE task_id=?", l.TaskID).Scan(&rosterCount, &rosterBytes); e != nil {
			return e
		}
		if rosterCount != h.ObjectCount || rosterBytes != h.Bytes {
			return store.ErrMigrationState
		}
		bound, e := r.peerObjectBinding(ctx, q, l.TaskID, g.Object.ID)
		if e != nil {
			return e
		}
		expected, e := store.MigrationDigest(bound)
		if e != nil {
			return e
		}
		actual, e := store.MigrationDigest(g.Object)
		if e != nil || actual != expected || g.UnitID != migrationUnit(bound) {
			return store.ErrMigrationState
		}
		var unit, version, hash, phase string
		var size int64
		if e = q.QueryRowContext(ctx, "SELECT unit_id,source_version,expected_bytes,sha256,state FROM migration_storage_journal WHERE task_id=? AND logical_id=?"+r.lock(), l.TaskID, bound.ID).Scan(&unit, &version, &size, &hash, &phase); e != nil {
			return e
		}
		if unit != g.UnitID || version != bound.Version || size != bound.Bytes || hash != g.SHA256 || (phase != "receiving" && phase != "deleting" && phase != "deleted") {
			return store.ErrMigrationState
		}
		var count int
		if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_read_leases WHERE member_id=? AND (logical_id=? OR object_id=?) AND expires_at>?", n.ID, bound.ID, bound.ObjectID, now).Scan(&count); e != nil {
			return e
		}
		if count != 0 {
			return store.ErrMigrationState
		}
		var committed, after int64
		var unitVersion string
		e = q.QueryRowContext(ctx, "SELECT committed_at,cleanup_after,source_version FROM migration_units WHERE task_id=? AND unit_id=?"+r.lock(), l.TaskID, g.UnitID).Scan(&committed, &after, &unitVersion)
		if e == nil {
			if committed != g.CommittedAt || after != g.CleanupAfter || unitVersion != g.UnitVersion {
				return store.ErrMigrationState
			}
		} else {
			if !errors.Is(e, sql.ErrNoRows) {
				return e
			}
			var objects, bytes int64
			if e = q.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(expected_bytes),0) FROM migration_storage_journal WHERE task_id=? AND unit_id=?", l.TaskID, g.UnitID).Scan(&objects, &bytes); e != nil {
				return e
			}
			if _, e = q.ExecContext(ctx, "INSERT INTO migration_units(task_id,unit_id,resource_kind,parent_path,source_version,state,object_count,total_bytes,committed_at,cleanup_after) VALUES (?,?,?,?,?,'cleanup_pending',?,?,?,?)", l.TaskID, g.UnitID, bound.Resource, bound.Parent, g.UnitVersion, objects, bytes, g.CommittedAt, g.CleanupAfter); e != nil {
				return e
			}
		}
		if phase == "deleted" {
			return nil
		}
		if _, e = q.ExecContext(ctx, "UPDATE migration_storage_journal SET state='deleting',updated_at=? WHERE task_id=? AND logical_id=?", now, l.TaskID, bound.ID); e != nil {
			return e
		}
		return r.nodeAudit(ctx, q, "peer-migration-cleanup-authorized", relationship, map[string]any{"task_id": l.TaskID, "unit_id": g.UnitID, "object_id": bound.ID, "sha256": g.SHA256}, a)
	})
}
