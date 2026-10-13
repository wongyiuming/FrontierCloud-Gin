package business

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Cancellation reads and shadow deletion require the exact current source
// authority before and after hashing. The immutable admitted unit root avoids
// re-reading every sibling for each file; terminal reconciliation still checks
// the full roster. Legacy tasks retain their full-unit validation.
func (r *Repository) migrationCancellationObjectGrant(ctx context.Context, q queryer, l store.MigrationLease, id string) (g store.MigrationUnitFinishGrant, e error) {
	t, e := r.checkMigrationLease(ctx, q, l)
	if e != nil {
		return g, e
	}
	if t.State != "cancelling" {
		return g, store.ErrMigrationState
	}
	w, e := r.migrationObjectWork(ctx, q, l.TaskID, id)
	if e != nil {
		return g, e
	}
	cp, u := w.Objects[0], w.Units[0]
	if cp.State == "cancelled" || cp.State == "cleanup_pending" || cp.State == "cleaned" || u.State == "cancelled" || u.State == "committed" || u.State == "cleanup_pending" || u.State == "cleaned" || u.CommittedAt != 0 || u.CleanupAfter != 0 || cp.UnitID != u.ID || cp.Object.Resource != u.Resource || cp.Object.Parent != u.Parent || w.Plan.Catalog.Source.RelationshipID == nil || w.Plan.Catalog.Target.RelationshipID == nil {
		return g, store.ErrMigrationState
	}
	current, e := r.migrationCatalogSelection(ctx, q, w.Plan.Catalog, "", id)
	if e != nil {
		return g, e
	}
	if len(current) != 1 {
		return g, store.ErrMigrationState
	}
	expected, e := store.MigrationDigest(cp.Object)
	if e != nil {
		return g, e
	}
	actual, e := store.MigrationDigest(current[0])
	if e != nil || actual != expected {
		return g, store.ErrMigrationState
	}
	if w.Plan.Format == "" {
		return r.migrationUnitCancelGrant(ctx, q, l, cp.UnitID)
	}
	if w.Plan.Format != pagedMigrationFormat || u.ObjectCount <= 0 || u.Bytes <= 0 {
		return g, store.ErrMigrationState
	}
	if e = q.QueryRowContext(ctx, "SELECT source_version FROM migration_units WHERE task_id=? AND unit_id=?", l.TaskID, u.ID).Scan(&g.UnitVersion); e != nil {
		return g, e
	}
	if !nodeHashPattern.MatchString(g.UnitVersion) {
		return g, store.ErrMigrationState
	}
	g.Unit = u
	g.Unit.State = "cancelled"
	g.ObjectsSHA = g.UnitVersion
	g.Header = store.MigrationPeerHeader{Format: "frontiercloud-peer-migration", Version: 1, TaskID: l.TaskID, MasterID: t.MasterID, SourceID: t.SourceID, TargetID: t.TargetID, SourceRelationship: *w.Plan.Catalog.Source.RelationshipID, TargetRelationship: *w.Plan.Catalog.Target.RelationshipID, PlanSHA: t.PlanSHA, ObjectCount: t.ObjectCount, Bytes: t.TotalBytes}
	return g, nil
}

func (r *Repository) MigrationCancellationObjectGrant(ctx context.Context, l store.MigrationLease, id string) (g store.MigrationUnitFinishGrant, e error) {
	e = r.write(ctx, func(q queryer) error {
		var err error
		g, err = r.migrationCancellationObjectGrant(ctx, q, l, id)
		return err
	})
	return
}
