package business

import (
	"context"
	"math"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (r *Repository) migrationTaskFinishGrant(ctx context.Context, q queryer, l store.MigrationLease) (g store.MigrationTaskFinishGrant, e error) {
	t, e := r.checkMigrationLease(ctx, q, l)
	if e != nil {
		return g, e
	}
	if t.State != "cleanup_pending" || t.CommittedBytes != t.TotalBytes {
		return g, store.ErrMigrationState
	}
	w, e := r.migrationWork(ctx, q, l.TaskID)
	if e != nil {
		return g, e
	}
	if w.Plan.Catalog.Source.RelationshipID == nil || w.Plan.Catalog.Target.RelationshipID == nil {
		return g, store.ErrMigrationState
	}
	g.Header = store.MigrationPeerHeader{Format: "frontiercloud-peer-migration", Version: 1, TaskID: l.TaskID, MasterID: t.MasterID, SourceID: t.SourceID, TargetID: t.TargetID, SourceRelationship: *w.Plan.Catalog.Source.RelationshipID, TargetRelationship: *w.Plan.Catalog.Target.RelationshipID, PlanSHA: t.PlanSHA, ObjectCount: t.ObjectCount, Bytes: t.TotalBytes}
	units := []store.MigrationUnitFinishGrant{}
	for _, u := range w.Units {
		if u.State != "cleaned" {
			return g, store.ErrMigrationState
		}
		u.State = "cleanup_pending"
		unit := store.MigrationUnitFinishGrant{Header: g.Header, Unit: u}
		if e = q.QueryRowContext(ctx, "SELECT source_version FROM migration_units WHERE task_id=? AND unit_id=?", l.TaskID, u.ID).Scan(&unit.UnitVersion); e != nil {
			return g, e
		}
		objects := []store.MigrationPeerObject{}
		for _, cp := range w.Objects {
			if cp.UnitID == u.ID {
				if cp.State != "cleaned" {
					return g, store.ErrMigrationState
				}
				objects = append(objects, store.MigrationPeerObject{Object: cp.Object, Proof: store.MigrationDiskProof{ID: cp.Object.ID, Version: cp.Object.Version, Bytes: cp.Object.Bytes, SHA256: cp.SourceSHA}})
			}
		}
		unit.ObjectsSHA, e = store.MigrationUnitObjectsSHA(objects)
		if e != nil {
			return g, e
		}
		units = append(units, unit)
	}
	var scopes int
	if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_scopes WHERE task_id=?", l.TaskID).Scan(&scopes); e != nil {
		return g, e
	}
	if scopes != 0 {
		return g, store.ErrMigrationState
	}
	var reserved int64
	if e = q.QueryRowContext(ctx, "SELECT reserved_bytes FROM migration_capacity WHERE task_id=?"+r.lock(), l.TaskID).Scan(&reserved); e != nil {
		return g, e
	}
	if reserved != 0 {
		return g, store.ErrMigrationState
	}
	g.UnitCount = int64(len(units))
	g.UnitsSHA, e = store.MigrationTaskUnitsSHA(units)
	return
}
func (r *Repository) MigrationTaskFinishGrant(ctx context.Context, l store.MigrationLease) (g store.MigrationTaskFinishGrant, e error) {
	e = r.write(ctx, func(q queryer) error { var err error; g, err = r.migrationTaskFinishGrant(ctx, q, l); return err })
	return
}
func (r *Repository) CompleteMigrationTask(ctx context.Context, l store.MigrationLease, source, target store.MigrationTaskFinishReceipt, a store.NodeAudit) error {
	return r.write(ctx, func(q queryer) error {
		g, e := r.migrationTaskFinishGrant(ctx, q, l)
		if e != nil {
			return e
		}
		if !source.Complete || !target.Complete || source.MemberID != g.Header.SourceID || target.MemberID != g.Header.TargetID {
			return store.ErrMigrationState
		}
		expected, _ := store.MigrationDigest(g)
		for _, receipt := range []store.MigrationTaskFinishReceipt{source, target} {
			actual, e := store.MigrationDigest(receipt.Grant)
			if e != nil || actual != expected {
				return store.ErrMigrationState
			}
		}
		t, e := r.checkMigrationLease(ctx, q, l)
		if e != nil {
			return e
		}
		if t.Revision == math.MaxInt64 {
			return store.ErrMigrationState
		}
		if _, e = q.ExecContext(ctx, "DELETE FROM migration_capacity WHERE task_id=? AND reserved_bytes=0", l.TaskID); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "UPDATE migration_tasks SET state='completed',error_code='',revision=revision+1,updated_at=? WHERE task_id=?", time.Now().Unix(), l.TaskID); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "UPDATE migration_runners SET expires_at=0 WHERE task_id=?", l.TaskID); e != nil {
			return e
		}
		return r.nodeAudit(ctx, q, "resource-migration-completed", "", map[string]any{"task_id": l.TaskID, "units_sha256": g.UnitsSHA}, a)
	})
}
