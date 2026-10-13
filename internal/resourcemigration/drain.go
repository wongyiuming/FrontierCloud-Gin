package resourcemigration

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Explicit confirmation is required. Neither task completion nor retirement
// calls this automatically. Each side removes only this task-owned restriction.
func (r *Runner) ReleaseDrain(ctx context.Context, task, confirmation string, a store.NodeAudit) error {
	w, e := r.header(ctx, task)
	if e != nil {
		return e
	}
	if confirmation != w.Task.SourceID || w.Task.State != "completed" && w.Task.State != "cancelled" || w.Plan.Catalog.Source.RelationshipID == nil {
		return store.ErrMigrationState
	}
	rel, e := r.Nodes.Relationship(ctx, *w.Plan.Catalog.Source.RelationshipID)
	if e != nil {
		return e
	}
	if rel.State != "active" || rel.Direction != "downstream" || rel.PeerID != w.Task.SourceID {
		return store.ErrMigrationState
	}
	value, e := r.request(ctx, rel, prefix+"release-drain", map[string]any{"task_id": task, "confirmation": confirmation})
	if e != nil {
		return e
	}
	var receipt store.MigrationDrainReceipt
	if e = decode(value, &receipt); e != nil {
		return e
	}
	if !receipt.Released || receipt.TaskID != task || receipt.SourceID != confirmation || receipt.PlanSHA != w.Task.PlanSHA {
		return store.ErrMigrationState
	}
	return r.Repository.ReleaseMigrationDrain(ctx, task, confirmation, a)
}
