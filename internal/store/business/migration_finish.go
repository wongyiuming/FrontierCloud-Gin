package business

import (
	"context"
	"math"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (r *Repository) migrationUnitFinishGrant(ctx context.Context, q queryer, l store.MigrationLease, id string) (g store.MigrationUnitFinishGrant, e error) {
	t, e := r.checkMigrationLease(ctx, q, l)
	if e != nil {
		return g, e
	}
	if t.State != "cleanup_pending" && t.State != "cancelling" {
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
	if !found || g.Unit.State != "cleanup_pending" && g.Unit.State != "cleaned" || g.Unit.CommittedAt <= 0 || g.Unit.CleanupAfter < g.Unit.CommittedAt+3600 || g.Unit.CleanupAfter > time.Now().Unix() {
		return g, store.ErrMigrationState
	}
	// The grant digest remains stable when a unit is already completed.
	g.Unit.State = "cleanup_pending"
	objects := []store.MigrationPeerObject{}
	for _, cp := range w.Objects {
		if cp.UnitID != id {
			continue
		}
		if cp.State != "cleaned" || cp.TargetSHA != cp.SourceSHA || cp.VerifiedBytes != cp.Object.Bytes {
			return g, store.ErrMigrationState
		}
		table, key, state := "global_media_objects", "media_id", "active"
		if cp.Object.Resource == "recording" {
			table, key, state = "karaoke_recordings", "recording_id", "ready"
		}
		var owner, phase string
		if e = q.QueryRowContext(ctx, "SELECT storage_member_id,state FROM "+table+" WHERE "+key+"=?"+r.lock(), cp.Object.ID).Scan(&owner, &phase); e != nil {
			return g, e
		}
		if owner != t.TargetID || phase != state {
			return g, store.ErrMigrationState
		}
		objects = append(objects, store.MigrationPeerObject{Object: cp.Object, Proof: store.MigrationDiskProof{ID: cp.Object.ID, Version: cp.Object.Version, Bytes: cp.Object.Bytes, SHA256: cp.SourceSHA}})
	}
	if int64(len(objects)) != g.Unit.ObjectCount {
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
func (r *Repository) MigrationUnitFinishGrant(ctx context.Context, l store.MigrationLease, id string) (g store.MigrationUnitFinishGrant, e error) {
	e = r.write(ctx, func(q queryer) error { var err error; g, err = r.migrationUnitFinishGrant(ctx, q, l, id); return err })
	return
}
func (r *Repository) CompleteMigrationUnitCleanup(ctx context.Context, l store.MigrationLease, source, target store.MigrationUnitFinishReceipt, a store.NodeAudit) error {
	return r.write(ctx, func(q queryer) error {
		g, e := r.migrationUnitFinishGrant(ctx, q, l, source.Grant.Unit.ID)
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
			if e != nil || expected != actual {
				return store.ErrMigrationState
			}
		}
		var state string
		if e = q.QueryRowContext(ctx, "SELECT state FROM migration_units WHERE task_id=? AND unit_id=?"+r.lock(), l.TaskID, g.Unit.ID).Scan(&state); e != nil {
			return e
		}
		if state == "cleaned" {
			return nil
		}
		t, e := r.checkMigrationLease(ctx, q, l)
		if e != nil {
			return e
		}
		if t.Revision == math.MaxInt64 {
			return store.ErrMigrationState
		}
		if _, e = q.ExecContext(ctx, "UPDATE migration_units SET state='cleaned' WHERE task_id=? AND unit_id=?", l.TaskID, g.Unit.ID); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "DELETE FROM migration_scopes WHERE task_id=? AND resource_kind=? AND parent_path=?", l.TaskID, g.Unit.Resource, g.Unit.Parent); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "UPDATE migration_tasks SET revision=revision+1,updated_at=? WHERE task_id=?", time.Now().Unix(), l.TaskID); e != nil {
			return e
		}
		return r.nodeAudit(ctx, q, "resource-migration-unit-cleaned", "", map[string]any{"task_id": l.TaskID, "unit_id": g.Unit.ID, "objects_sha256": g.ObjectsSHA}, a)
	})
}
