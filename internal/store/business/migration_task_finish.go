package business

import (
	"context"
	"math"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (r *Repository) migrationTaskFinishGrant(ctx context.Context, q queryer, l store.MigrationLease, cancelling bool) (g store.MigrationTaskFinishGrant, e error) {
	t, e := r.checkMigrationLease(ctx, q, l)
	if e != nil {
		return g, e
	}
	g.Outcome = "completed"
	if cancelling {
		g.Outcome = "cancelled"
		if t.State != "cancelling" {
			return g, store.ErrMigrationState
		}
	} else if t.State != "cleanup_pending" || t.CommittedBytes != t.TotalBytes {
		return g, store.ErrMigrationState
	}
	w, e := r.migrationHeader(ctx, q, l.TaskID)
	if e != nil {
		return g, e
	}
	if w.Plan.Catalog.Source.RelationshipID == nil || w.Plan.Catalog.Target.RelationshipID == nil {
		return g, store.ErrMigrationState
	}
	g.Header = store.MigrationPeerHeader{Format: "frontiercloud-peer-migration", Version: 1, TaskID: l.TaskID, MasterID: t.MasterID, SourceID: t.SourceID, TargetID: t.TargetID, SourceRelationship: *w.Plan.Catalog.Source.RelationshipID, TargetRelationship: *w.Plan.Catalog.Target.RelationshipID, PlanSHA: t.PlanSHA, ObjectCount: t.ObjectCount, Bytes: t.TotalBytes}
	var units store.MigrationSequence
	var committedBytes, objectCount, totalBytes int64
	for u, err := range r.migrationUnits(ctx, q, l.TaskID) {
		if err != nil {
			return g, err
		}
		if u.State != "cleaned" && !(cancelling && u.State == "cancelled") {
			return g, store.ErrMigrationState
		}
		objectState := u.State
		if u.State == "cleaned" {
			if u.CommittedAt <= 0 || u.CleanupAfter < u.CommittedAt+3600 {
				return g, store.ErrMigrationState
			}
			committedBytes += u.Bytes
			u.State = "cleanup_pending"
		} else if u.CommittedAt != 0 || u.CleanupAfter != 0 {
			return g, store.ErrMigrationState
		}
		objectCount += u.ObjectCount
		totalBytes += u.Bytes
		unit := store.MigrationUnitFinishGrant{Header: g.Header, Unit: u}
		if e = q.QueryRowContext(ctx, "SELECT source_version FROM migration_units WHERE task_id=? AND unit_id=?", l.TaskID, u.ID).Scan(&unit.UnitVersion); e != nil {
			return g, e
		}
		var objects store.MigrationSequence
		var unitBytes int64
		for cp, err := range r.migrationObjects(ctx, q, l.TaskID, u.ID) {
			if err != nil {
				return g, err
			}
			if cp.UnitID == u.ID {
				if cp.State != objectState {
					return g, store.ErrMigrationState
				}
				if e = objects.Add(cp.Object.ID, store.MigrationPeerObject{Object: cp.Object, Proof: store.MigrationDiskProof{ID: cp.Object.ID, Version: cp.Object.Version, Bytes: cp.Object.Bytes, SHA256: cp.SourceSHA}}); e != nil {
					return g, e
				}
				unitBytes += cp.Object.Bytes
			}
		}
		if objects.Count() != u.ObjectCount || unitBytes != u.Bytes {
			return g, store.ErrMigrationState
		}
		unit.ObjectsSHA = objects.Sum()
		if e != nil {
			return g, e
		}
		if e = units.Add(unit.Unit.ID, unit); e != nil {
			return g, e
		}
	}
	if committedBytes != t.CommittedBytes || objectCount != t.ObjectCount || totalBytes != t.TotalBytes {
		return g, store.ErrMigrationState
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
	g.UnitCount = units.Count()
	g.UnitsSHA = units.Sum()
	return
}
func (r *Repository) MigrationTaskFinishGrant(ctx context.Context, l store.MigrationLease) (g store.MigrationTaskFinishGrant, e error) {
	e = r.write(ctx, func(q queryer) error {
		var err error
		g, err = r.migrationTaskFinishGrant(ctx, q, l, false)
		return err
	})
	return
}
func (r *Repository) CompleteMigrationTask(ctx context.Context, l store.MigrationLease, source, target store.MigrationTaskFinishReceipt, a store.NodeAudit) error {
	return r.completeMigrationTask(ctx, l, source, target, a, false)
}
func (r *Repository) completeMigrationTask(ctx context.Context, l store.MigrationLease, source, target store.MigrationTaskFinishReceipt, a store.NodeAudit, cancelling bool) error {
	return r.write(ctx, func(q queryer) error {
		g, e := r.migrationTaskFinishGrant(ctx, q, l, cancelling)
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
		if _, e = q.ExecContext(ctx, "UPDATE migration_tasks SET state=?,error_code='',revision=revision+1,updated_at=? WHERE task_id=?", g.Outcome, time.Now().Unix(), l.TaskID); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "UPDATE migration_runners SET expires_at=0 WHERE task_id=?", l.TaskID); e != nil {
			return e
		}
		return r.nodeAudit(ctx, q, "resource-migration-"+g.Outcome, "", map[string]any{"task_id": l.TaskID, "units_sha256": g.UnitsSHA}, a)
	})
}

func (r *Repository) MigrationTaskCancelGrant(ctx context.Context, l store.MigrationLease) (g store.MigrationTaskFinishGrant, e error) {
	e = r.write(ctx, func(q queryer) error { var err error; g, err = r.migrationTaskFinishGrant(ctx, q, l, true); return err })
	return
}
func (r *Repository) CompleteMigrationTaskCancellation(ctx context.Context, l store.MigrationLease, source, target store.MigrationTaskFinishReceipt, a store.NodeAudit) error {
	return r.completeMigrationTask(ctx, l, source, target, a, true)
}
