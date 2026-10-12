package business

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"time"
)

// Called only after the receiver has durably removed its unpublished staging
// bytes. Capacity and scope reservations remain until whole-task reconciliation.
func (r *Repository) CompletePeerMigrationAbort(ctx context.Context, relationship string, l store.MigrationLease, id string, a store.NodeAudit) error {
	return r.write(ctx, func(q queryer) error {
		h, n, state, e := r.checkPeerLease(ctx, q, relationship, l)
		if e != nil {
			return e
		}
		if state != "cancelling" || n.ID != h.TargetID {
			return store.ErrMigrationState
		}
		var phase string
		if e = q.QueryRowContext(ctx, "SELECT state FROM migration_storage_journal WHERE task_id=? AND logical_id=?"+r.lock(), l.TaskID, id).Scan(&phase); e != nil {
			return e
		}
		if phase == "aborted" {
			return nil
		}
		if phase != "receiving" && phase != "verified" && phase != "aborting" {
			return store.ErrMigrationState
		}
		if _, e = q.ExecContext(ctx, "UPDATE migration_storage_journal SET state='aborted',updated_at=? WHERE task_id=? AND logical_id=?", time.Now().Unix(), l.TaskID, id); e != nil {
			return e
		}
		return r.nodeAudit(ctx, q, "resource-migration-staging-aborted", relationship, map[string]any{"task_id": l.TaskID, "logical_id": id}, a)
	})
}
