package business

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"math"
	"time"
)

// A cancellation grant never authorizes deleting the source or undoing a
// committed owner. The distinct endpoint requires target staging-abort facts.
func (r *Repository) migrationUnitCancelGrant(ctx context.Context, q queryer, l store.MigrationLease, id string) (g store.MigrationUnitFinishGrant, e error) {
	t, e := r.checkMigrationLease(ctx, q, l)
	if e != nil {
		return g, e
	}
	if t.State != "cancelling" {
		return g, store.ErrMigrationState
	}
	w, e := r.migrationWork(ctx, q, l.TaskID)
	if e != nil {
		return g, e
	}
	if w.Plan.Catalog.Source.RelationshipID == nil || w.Plan.Catalog.Target.RelationshipID == nil {
		return g, store.ErrMigrationState
	}
	found := false
	for _, u := range w.Units {
		if u.ID == id {
			g.Unit = u
			found = true
		}
	}
	if !found || g.Unit.CommittedAt != 0 || g.Unit.CleanupAfter != 0 || g.Unit.State == "committed" || g.Unit.State == "cleanup_pending" || g.Unit.State == "cleaned" {
		return g, store.ErrMigrationState
	}
	replay := g.Unit.State == "cancelled"
	g.Unit.State = "cancelled"
	objects := []store.MigrationPeerObject{}
	var total int64
	for _, cp := range w.Objects {
		if cp.UnitID != id {
			continue
		}
		if cp.State == "cleanup_pending" || cp.State == "cleaned" || cp.Object.Resource != g.Unit.Resource || cp.Object.Parent != g.Unit.Parent {
			return g, store.ErrMigrationState
		}
		if !replay {
			table, key := "global_media_objects", "media_id"
			if cp.Object.Resource == "recording" {
				table, key = "karaoke_recordings", "recording_id"
			}
			var owner string
			if e = q.QueryRowContext(ctx, "SELECT storage_member_id FROM "+table+" WHERE "+key+"=?"+r.lock(), cp.Object.ID).Scan(&owner); e != nil {
				return g, e
			}
			if owner != t.SourceID {
				return g, store.ErrMigrationState
			}
		}
		total += cp.Object.Bytes
		objects = append(objects, store.MigrationPeerObject{Object: cp.Object, Proof: store.MigrationDiskProof{ID: cp.Object.ID, Version: cp.Object.Version, Bytes: cp.Object.Bytes, SHA256: cp.SourceSHA}})
	}
	if int64(len(objects)) != g.Unit.ObjectCount || total != g.Unit.Bytes || len(objects) == 0 {
		return g, store.ErrMigrationState
	}
	g.ObjectsSHA, e = store.MigrationUnitObjectsSHA(objects)
	if e != nil {
		return g, e
	}
	if e = q.QueryRowContext(ctx, "SELECT source_version FROM migration_units WHERE task_id=? AND unit_id=?", l.TaskID, id).Scan(&g.UnitVersion); e != nil {
		return g, e
	}
	g.Header = store.MigrationPeerHeader{Format: "frontiercloud-peer-migration", Version: 1, TaskID: l.TaskID, MasterID: t.MasterID, SourceID: t.SourceID, TargetID: t.TargetID, SourceRelationship: *w.Plan.Catalog.Source.RelationshipID, TargetRelationship: *w.Plan.Catalog.Target.RelationshipID, PlanSHA: t.PlanSHA, ObjectCount: t.ObjectCount, Bytes: t.TotalBytes}
	return g, nil
}
func (r *Repository) MigrationUnitCancelGrant(ctx context.Context, l store.MigrationLease, id string) (g store.MigrationUnitFinishGrant, e error) {
	e = r.write(ctx, func(q queryer) error { var err error; g, err = r.migrationUnitCancelGrant(ctx, q, l, id); return err })
	return
}
func (r *Repository) CompleteMigrationUnitCancellation(ctx context.Context, l store.MigrationLease, source, target store.MigrationUnitFinishReceipt, a store.NodeAudit) error {
	return r.write(ctx, func(q queryer) error {
		g, e := r.migrationUnitCancelGrant(ctx, q, l, source.Grant.Unit.ID)
		if e != nil {
			return e
		}
		if !source.Complete || !target.Complete || source.MemberID != g.Header.SourceID || target.MemberID != g.Header.TargetID {
			return store.ErrMigrationState
		}
		expected, e := store.MigrationDigest(g)
		if e != nil {
			return e
		}
		for _, receipt := range []store.MigrationUnitFinishReceipt{source, target} {
			actual, e := store.MigrationDigest(receipt.Grant)
			if e != nil || actual != expected {
				return store.ErrMigrationState
			}
		}
		var phase string
		if e = q.QueryRowContext(ctx, "SELECT state FROM migration_units WHERE task_id=? AND unit_id=?"+r.lock(), l.TaskID, g.Unit.ID).Scan(&phase); e != nil {
			return e
		}
		if phase == "cancelled" {
			return nil
		}
		t, e := r.checkMigrationLease(ctx, q, l)
		if e != nil {
			return e
		}
		if t.Revision == math.MaxInt64 {
			return store.ErrMigrationState
		}
		var reserved, memberReserved int64
		if e = q.QueryRowContext(ctx, "SELECT reserved_bytes FROM migration_capacity WHERE task_id=? AND member_id=?"+r.lock(), l.TaskID, t.TargetID).Scan(&reserved); e != nil {
			return e
		}
		if e = q.QueryRowContext(ctx, "SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?"+r.lock(), t.TargetID).Scan(&memberReserved); e != nil {
			return e
		}
		if reserved < g.Unit.Bytes || memberReserved < g.Unit.Bytes {
			return store.ErrMigrationState
		}
		now := time.Now().Unix()
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{"UPDATE migration_capacity SET reserved_bytes=reserved_bytes-?,updated_at=? WHERE task_id=?", []any{g.Unit.Bytes, now, l.TaskID}},
			{"UPDATE cluster_storage_members SET reserved_bytes=reserved_bytes-?,updated_at=? WHERE member_id=?", []any{g.Unit.Bytes, now, t.TargetID}},
			{"UPDATE migration_units SET state='cancelled' WHERE task_id=? AND unit_id=?", []any{l.TaskID, g.Unit.ID}},
			{"UPDATE migration_objects SET state='cancelled',updated_at=? WHERE task_id=? AND unit_id=?", []any{now, l.TaskID, g.Unit.ID}},
			{"DELETE FROM migration_scopes WHERE task_id=? AND resource_kind=? AND parent_path=?", []any{l.TaskID, g.Unit.Resource, g.Unit.Parent}},
			{"UPDATE migration_tasks SET revision=revision+1,updated_at=? WHERE task_id=?", []any{now, l.TaskID}},
		} {
			if _, e = q.ExecContext(ctx, statement.sql, statement.args...); e != nil {
				return e
			}
		}
		return r.nodeAudit(ctx, q, "resource-migration-unit-cancelled", "", map[string]any{"task_id": l.TaskID, "unit_id": g.Unit.ID, "objects_sha256": g.ObjectsSHA}, a)
	})
}
