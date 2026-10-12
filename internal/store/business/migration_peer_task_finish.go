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
func (r *Repository) CompletePeerMigrationTask(ctx context.Context, relationship string, l store.MigrationLease, g store.MigrationTaskFinishGrant, a store.NodeAudit) (receipt store.MigrationTaskFinishReceipt, e error) {
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
		if expected != actual || state != "completed" && state != "queued" && state != "cleanup_pending" {
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
		rows, e := q.QueryContext(ctx, "SELECT unit_id,resource_kind,parent_path,source_version,state,object_count,total_bytes,committed_at,cleanup_after FROM migration_units WHERE task_id=? ORDER BY unit_id", l.TaskID)
		if e != nil {
			return e
		}
		units := []store.MigrationUnitFinishGrant{}
		for rows.Next() {
			unit := store.MigrationUnitFinishGrant{Header: h}
			var phase string
			if e = rows.Scan(&unit.Unit.ID, &unit.Unit.Resource, &unit.Unit.Parent, &unit.UnitVersion, &phase, &unit.Unit.ObjectCount, &unit.Unit.Bytes, &unit.Unit.CommittedAt, &unit.Unit.CleanupAfter); e != nil {
				rows.Close()
				return e
			}
			if phase != "cleaned" {
				rows.Close()
				return store.ErrMigrationState
			}
			unit.Unit.State = "cleanup_pending"
			units = append(units, unit)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		var objects int64
		var bytes int64
		for i := range units {
			unit := &units[i]
			entries, e := q.QueryContext(ctx, "SELECT logical_id,sha256 FROM migration_storage_journal WHERE task_id=? AND unit_id=? ORDER BY logical_id", l.TaskID, unit.Unit.ID)
			if e != nil {
				return e
			}
			type item struct{ id, sha string }
			items := []item{}
			for entries.Next() {
				var value item
				if e = entries.Scan(&value.id, &value.sha); e != nil {
					entries.Close()
					return e
				}
				items = append(items, value)
			}
			e = entries.Err()
			entries.Close()
			if e != nil {
				return e
			}
			bindings := []store.MigrationPeerObject{}
			for _, entry := range items {
				o, e := r.peerObjectBinding(ctx, q, l.TaskID, entry.id)
				if e != nil {
					return e
				}
				bindings = append(bindings, store.MigrationPeerObject{Object: o, Proof: store.MigrationDiskProof{ID: o.ID, Version: o.Version, Bytes: o.Bytes, SHA256: entry.sha}})
			}
			unit.ObjectsSHA, e = store.MigrationUnitObjectsSHA(bindings)
			if e != nil {
				return e
			}
			objects += unit.Unit.ObjectCount
			bytes += unit.Unit.Bytes
		}
		sha, e := store.MigrationTaskUnitsSHA(units)
		if e != nil {
			return e
		}
		if g.UnitCount != int64(len(units)) || objects != h.ObjectCount || bytes != h.Bytes || sha != g.UnitsSHA {
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
		if e != nil && !((state == "completed" || n.ID == h.SourceID) && errors.Is(e, sql.ErrNoRows)) {
			return e
		}
		if reserved != 0 {
			return store.ErrMigrationState
		}
		receipt = store.MigrationTaskFinishReceipt{Grant: g, MemberID: n.ID, Complete: true}
		if state == "completed" {
			return nil
		}
		if _, e = q.ExecContext(ctx, "DELETE FROM migration_capacity WHERE task_id=? AND reserved_bytes=0", l.TaskID); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "UPDATE migration_tasks SET state='completed',updated_at=? WHERE task_id=?", time.Now().Unix(), l.TaskID); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "UPDATE migration_runners SET runner_id=?,epoch=?,expires_at=0 WHERE task_id=?", l.RunnerID, l.Epoch, l.TaskID); e != nil {
			return e
		}
		return r.nodeAudit(ctx, q, "peer-migration-completed", relationship, map[string]any{"task_id": l.TaskID, "units_sha256": sha}, a)
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
