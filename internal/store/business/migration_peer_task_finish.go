package business

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Completed peers return the same receipt to a newly fenced Master runner.
// This endpoint never reactivates a completed task or its data permissions.
func (r *Repository) CompletePeerMigrationTask(ctx context.Context, relationship string, l store.MigrationLease, g store.MigrationTaskFinishGrant, a store.NodeAudit) (store.MigrationTaskFinishReceipt, error) {
	return r.completePeerMigrationTask(ctx, relationship, l, g, a, false)
}
func (r *Repository) CompletePeerMigrationTaskCancellation(ctx context.Context, relationship string, l store.MigrationLease, g store.MigrationTaskFinishGrant, a store.NodeAudit) (store.MigrationTaskFinishReceipt, error) {
	return r.completePeerMigrationTask(ctx, relationship, l, g, a, true)
}
func (r *Repository) completePeerMigrationTask(ctx context.Context, relationship string, l store.MigrationLease, g store.MigrationTaskFinishGrant, a store.NodeAudit, cancelling bool) (receipt store.MigrationTaskFinishReceipt, e error) {
	outcome := "completed"
	if cancelling {
		outcome = "cancelled"
	}
	if g.Outcome != outcome {
		return receipt, store.ErrMigrationState
	}
	if !peerLeaseValid(l, g.Header.TaskID) {
		return receipt, store.ErrMigrationLease
	}
	e = r.write(ctx, func(q queryer) error {
		if _, e := readNode(ctx, q, r.lock()); e != nil {
			return e
		}
		h, state, e := r.peerHeader(ctx, q, l.TaskID)
		if e != nil {
			return e
		}
		expected, _ := store.MigrationDigest(h)
		actual, _ := store.MigrationDigest(g.Header)
		if expected != actual {
			return store.ErrMigrationState
		}
		if cancelling {
			if state != "cancelling" && state != "cancelled" {
				return store.ErrMigrationState
			}
		} else if state != "completed" && state != "queued" && state != "cleanup_pending" {
			return store.ErrMigrationState
		}
		n, e := r.peerIdentity(ctx, q, relationship, h)
		if e != nil {
			return e
		}
		var runner string
		var epoch int64
		if e = q.QueryRowContext(ctx, "SELECT runner_id,epoch FROM migration_runners WHERE task_id=?"+r.lock(), l.TaskID).Scan(&runner, &epoch); e != nil {
			return e
		}
		if l.Epoch < epoch || l.Epoch == epoch && l.RunnerID != runner {
			return store.ErrMigrationLease
		}
		var count, total int64
		if e = q.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(expected_bytes),0) FROM migration_storage_journal WHERE task_id=?", l.TaskID).Scan(&count, &total); e != nil {
			return e
		}
		if count != h.ObjectCount || total != h.Bytes {
			return store.ErrMigrationState
		}

		var units store.MigrationSequence
		var objects, bytes int64
		for u, err := range r.migrationUnits(ctx, q, l.TaskID) {
			if err != nil {
				return err
			}
			unit := store.MigrationUnitFinishGrant{Header: h, Unit: u}
			if u.State != "cleaned" && !(cancelling && u.State == "cancelled") {
				return store.ErrMigrationState
			}
			if u.State == "cleaned" {
				if u.CommittedAt <= 0 || u.CleanupAfter < u.CommittedAt+3600 {
					return store.ErrMigrationState
				}
				unit.Unit.State = "cleanup_pending"
			} else if u.CommittedAt != 0 || u.CleanupAfter != 0 {
				return store.ErrMigrationState
			}
			if e = q.QueryRowContext(ctx, "SELECT source_version FROM migration_units WHERE task_id=? AND unit_id=?", l.TaskID, u.ID).Scan(&unit.UnitVersion); e != nil {
				return e
			}
			var bindings store.MigrationSequence
			var actualBytes int64
			for binding, err := range r.peerObjects(ctx, q, l.TaskID, u.ID) {
				if err != nil {
					return err
				}
				actualBytes += binding.Object.Bytes
				binding.State = ""
				binding.Header = store.MigrationPeerHeader{}
				if e = bindings.Add(binding.Object.ID, binding); e != nil {
					return e
				}
			}
			if bindings.Count() != u.ObjectCount || actualBytes != u.Bytes {
				return store.ErrMigrationState
			}
			unit.ObjectsSHA = bindings.Sum()
			if e = units.Add(u.ID, unit); e != nil {
				return e
			}
			objects += u.ObjectCount
			bytes += u.Bytes
		}
		sha := units.Sum()
		if g.UnitCount != units.Count() || objects != h.ObjectCount || bytes != h.Bytes || sha != g.UnitsSHA {
			return store.ErrMigrationState
		}

		var scopes int
		if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_scopes WHERE task_id=?", l.TaskID).Scan(&scopes); e != nil {
			return e
		}
		if scopes != 0 {
			return store.ErrMigrationState
		}
		var reserved int64
		e = q.QueryRowContext(ctx, "SELECT reserved_bytes FROM migration_capacity WHERE task_id=?"+r.lock(), l.TaskID).Scan(&reserved)
		if e != nil && !((state == outcome || n.ID == h.SourceID) && errors.Is(e, sql.ErrNoRows)) {
			return e
		}
		if reserved != 0 {
			return store.ErrMigrationState
		}
		receipt = store.MigrationTaskFinishReceipt{Grant: g, MemberID: n.ID, Complete: true}
		if state == outcome {
			return nil
		}
		if _, e = q.ExecContext(ctx, "DELETE FROM migration_capacity WHERE task_id=? AND reserved_bytes=0", l.TaskID); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "UPDATE migration_tasks SET state=?,updated_at=? WHERE task_id=?", outcome, time.Now().Unix(), l.TaskID); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "UPDATE migration_runners SET runner_id=?,epoch=?,expires_at=0 WHERE task_id=?", l.RunnerID, l.Epoch, l.TaskID); e != nil {
			return e
		}
		return r.nodeAudit(ctx, q, "peer-migration-"+outcome, relationship, map[string]any{"task_id": l.TaskID, "units_sha256": sha}, a)
	})
	return
}

func (r *Repository) ReleasePeerMigrationDrain(ctx context.Context, relationship, task, confirmation string, a store.NodeAudit) (receipt store.MigrationDrainReceipt, e error) {
	e = r.write(ctx, func(q queryer) error {
		if _, e := readNode(ctx, q, r.lock()); e != nil {
			return e
		}
		h, state, e := r.peerHeader(ctx, q, task)
		if e != nil {
			return e
		}
		n, e := r.peerIdentity(ctx, q, relationship, h)
		if e != nil {
			return e
		}
		if n.ID != h.SourceID || confirmation != n.ID || state != "completed" && state != "cancelled" {
			return store.ErrMigrationState
		}
		for _, query := range []string{"SELECT COUNT(*) FROM migration_capacity WHERE task_id=? AND reserved_bytes<>0", "SELECT COUNT(*) FROM migration_scopes WHERE task_id=?", "SELECT COUNT(*) FROM migration_units WHERE task_id=? AND state NOT IN ('cleaned','cancelled')"} {
			var count int
			if e = q.QueryRowContext(ctx, query, task).Scan(&count); e != nil {
				return e
			}
			if count != 0 {
				return store.ErrMigrationState
			}
		}
		var reads int
		if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_read_leases WHERE member_id=? AND expires_at>?", n.ID, time.Now().Unix()).Scan(&reads); e != nil {
			return e
		}
		if reads != 0 {
			return store.ErrMigrationState
		}
		result, e := q.ExecContext(ctx, "DELETE FROM migration_drains WHERE member_id=? AND owner_id=? AND reason='migration'", n.ID, task)
		if e != nil {
			return e
		}
		changed, e := result.RowsAffected()
		if e != nil {
			return e
		}
		receipt = store.MigrationDrainReceipt{TaskID: task, SourceID: n.ID, PlanSHA: h.PlanSHA, Released: true}
		if changed == 0 {
			return nil
		}
		return r.nodeAudit(ctx, q, "peer-migration-drain-released", relationship, map[string]any{"task_id": task, "source_id": n.ID}, a)
	})
	return
}
