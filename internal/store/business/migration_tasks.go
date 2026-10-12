package business

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"sort"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const migrationTaskColumns = "task_id,master_id,source_id,target_id,plan_sha256,state,revision,object_count,total_bytes,committed_bytes,error_code,created_at,updated_at"

func scanMigrationTask(q rowScanner) (t store.MigrationTask, e error) {
	e = q.Scan(&t.ID, &t.MasterID, &t.SourceID, &t.TargetID, &t.PlanSHA, &t.State, &t.Revision, &t.ObjectCount, &t.TotalBytes, &t.CommittedBytes, &t.ErrorCode, &t.CreatedAt, &t.UpdatedAt)
	return
}
func (r *Repository) MigrationTask(ctx context.Context, id string) (store.MigrationTask, error) {
	if !nodeIDPattern.MatchString(id) {
		return store.MigrationTask{}, store.ErrMigrationState
	}
	return scanMigrationTask(r.db.QueryRowContext(ctx, "SELECT "+migrationTaskColumns+" FROM migration_tasks WHERE task_id=?", id))
}
func (r *Repository) MigrationTasks(ctx context.Context, limit int) ([]store.MigrationTask, error) {
	n, e := r.ReadIdentity(ctx)
	if e != nil || n.Role != "Master" {
		return nil, store.ErrMigrationState
	}
	limit = min(100, max(1, limit))
	rows, e := r.db.QueryContext(ctx, "SELECT "+migrationTaskColumns+" FROM migration_tasks ORDER BY created_at DESC,task_id LIMIT ?", limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	tasks := []store.MigrationTask{}
	for rows.Next() {
		t, e := scanMigrationTask(rows)
		if e != nil {
			return nil, e
		}
		tasks = append(tasks, t)
	}
	return tasks, rows.Err()
}
func (r *Repository) StartMigration(ctx context.Context, p store.MigrationPlan, a store.NodeAudit) (task store.MigrationTask, e error) {
	now := time.Now().Unix()
	if !nodeIDPattern.MatchString(p.ID) || !nodeIDPattern.MatchString(p.Catalog.Source.ID) || !nodeIDPattern.MatchString(p.Catalog.Target.ID) || p.Catalog.Source.ID == p.Catalog.Target.ID || !nodeHashPattern.MatchString(p.Catalog.Version) || !p.TargetAbsent || p.TargetFree < store.PhysicalReserve || len(p.Catalog.Blockers) != 0 || len(p.Proofs) != len(p.Catalog.Objects) || len(p.Proofs) > store.MaxMigrationObjects {
		return task, store.ErrMigrationState
	}
	raw, e := migrationPlanBytes(p)
	if e != nil {
		return task, e
	}
	digest, e := store.MigrationDigest(p)
	if e != nil {
		return task, e
	}
	proofs := map[string]store.MigrationDiskProof{}
	for _, proof := range p.Proofs {
		if _, ok := proofs[proof.ID]; ok || !nodeHashPattern.MatchString(proof.SHA256) || !nodeHashPattern.MatchString(proof.Version) || proof.Bytes <= 0 {
			return task, store.ErrMigrationState
		}
		proofs[proof.ID] = proof
	}
	e = r.write(ctx, func(q queryer) error {
		n, e := readNode(ctx, q, r.lock())
		if e != nil {
			return e
		}
		if n.Role != "Master" || n.ID != p.Catalog.MasterID {
			return store.ErrMigrationState
		}
		old, e := scanMigrationTask(q.QueryRowContext(ctx, "SELECT "+migrationTaskColumns+" FROM migration_tasks WHERE task_id=?"+r.lock(), p.ID))
		if e == nil {
			if old.PlanSHA != digest || old.MasterID != n.ID {
				return store.ErrMigrationState
			}
			task = old
			return nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		now = time.Now().Unix()
		if p.CreatedAt > now+30 || p.CreatedAt < now-300 || p.ExpiresAt <= now || p.ExpiresAt > p.CreatedAt+300 {
			return store.ErrMigrationState
		}
		// Ordinary allocations take the same member rows, in deterministic order.
		ids := []string{p.Catalog.Source.ID, p.Catalog.Target.ID}
		sort.Strings(ids)
		for _, id := range ids {
			if _, e = scanMember(q.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?"+r.lock(), id)); e != nil {
				return e
			}
		}
		current, e := r.migrationCatalog(ctx, q, p.Catalog.Source.ID, p.Catalog.Target.ID)
		if e != nil {
			return e
		}
		if current.Version != p.Catalog.Version || len(current.Blockers) != 0 || current.TotalBytes != p.Catalog.TotalBytes || capacity(current.Target) < current.TotalBytes || p.TargetFree-store.PhysicalReserve-current.Target.Reserved < current.TotalBytes {
			return store.ErrMigrationState
		}
		for _, o := range current.Objects {
			proof, ok := proofs[o.ID]
			if !ok || proof.Version != o.Version || proof.Bytes != o.Bytes {
				return store.ErrMigrationState
			}
			if o.Resource == "media" {
				if e = r.checkMigrationScopes(ctx, q, o.Resource, []store.DeleteItem{{Path: o.Path}}); e != nil {
					return e
				}
			} else {
				for _, member := range ids {
					if e = r.checkMigrationRecording(ctx, q, member, o.Parent); e != nil {
						return e
					}
				}
			}
		}
		for _, id := range ids {
			var count int
			if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_scopes WHERE member_id=?", id).Scan(&count); e != nil {
				return e
			}
			if id == current.Source.ID && count != 0 {
				return store.ErrMigrationState
			}
		}
		if _, e = q.ExecContext(ctx, "INSERT INTO migration_tasks(task_id,master_id,source_id,target_id,source_relationship,target_relationship,plan_sha256,plan,state,object_count,total_bytes,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,'queued',?,?,?,?)", p.ID, n.ID, current.Source.ID, current.Target.ID, *current.Source.RelationshipID, *current.Target.RelationshipID, digest, string(raw), len(current.Objects), current.TotalBytes, now, now); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "INSERT INTO migration_capacity(task_id,member_id,reserved_bytes,updated_at) VALUES (?,?,?,?)", p.ID, current.Target.ID, current.TotalBytes, now); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "UPDATE cluster_storage_members SET reserved_bytes=reserved_bytes+?,updated_at=? WHERE member_id=?", current.TotalBytes, now, current.Target.ID); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "INSERT INTO migration_drains(member_id,owner_id,reason,created_at) VALUES (?,?,'migration',?)", current.Source.ID, p.ID, now); e != nil {
			return e
		}
		type unit struct {
			object       store.MigrationObject
			count, bytes int64
		}
		units := map[string]unit{}
		for _, o := range current.Objects {
			key := migrationUnit(o)
			u := units[key]
			u.object = o
			u.count++
			u.bytes += o.Bytes
			units[key] = u
			if _, e = q.ExecContext(ctx, "INSERT INTO migration_objects(task_id,unit_id,logical_id,resource_kind,source_object,target_object,source_version,physical_path,expected_bytes,source_sha256,state,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,'pending',?)", p.ID, key, o.ID, o.Resource, o.ObjectID, o.ObjectID, o.Version, o.Path, o.Bytes, proofs[o.ID].SHA256, now); e != nil {
				return e
			}
		}
		keys := make([]string, 0, len(units))
		for key := range units {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			u := units[key]
			version, e := store.MigrationDigest(struct{ Catalog, Unit string }{current.Version, key})
			if e != nil {
				return e
			}
			if _, e = q.ExecContext(ctx, "INSERT INTO migration_units(task_id,unit_id,resource_kind,parent_path,source_version,state,object_count,total_bytes) VALUES (?,?,?,?,?,'pending',?,?)", p.ID, key, u.object.Resource, u.object.Parent, version, u.count, u.bytes); e != nil {
				return e
			}
			for _, member := range ids {
				if _, e = q.ExecContext(ctx, "INSERT INTO migration_scopes(scope_id,task_id,member_id,resource_kind,parent_path,created_at) VALUES (?,?,?,?,?,?)", migrationScope(u.object, member), p.ID, member, u.object.Resource, u.object.Parent, now); e != nil {
					return e
				}
			}
		}
		if e = r.nodeAudit(ctx, q, "resource-migration-started", *current.Source.RelationshipID, map[string]any{"task_id": p.ID, "source_id": current.Source.ID, "target_id": current.Target.ID, "objects": len(current.Objects), "bytes": current.TotalBytes, "plan_sha256": digest}, a); e != nil {
			return e
		}
		task = store.MigrationTask{ID: p.ID, MasterID: n.ID, SourceID: current.Source.ID, TargetID: current.Target.ID, PlanSHA: digest, State: "queued", Revision: 1, ObjectCount: int64(len(current.Objects)), TotalBytes: current.TotalBytes, CreatedAt: now, UpdatedAt: now}
		return nil
	})
	return
}

var _ store.MigrationRepository = (*Repository)(nil)

func (r *Repository) ControlMigration(ctx context.Context, id, action string, a store.NodeAudit) (task store.MigrationTask, e error) {
	if !nodeIDPattern.MatchString(id) {
		return task, store.ErrMigrationState
	}
	e = r.write(ctx, func(q queryer) error {
		n, e := readNode(ctx, q, r.lock())
		if e != nil {
			return e
		}
		if n.Role != "Master" {
			return store.ErrMigrationState
		}
		task, e = scanMigrationTask(q.QueryRowContext(ctx, "SELECT "+migrationTaskColumns+" FROM migration_tasks WHERE task_id=?"+r.lock(), id))
		if e != nil {
			return e
		}
		if task.MasterID != n.ID {
			return store.ErrMigrationState
		}
		state := task.State
		switch action {
		case "pause":
			if state == "paused" {
				return nil
			}
			if !migrationRunnable(state) {
				return store.ErrMigrationState
			}
			state = "paused"
		case "resume":
			if migrationRunnable(state) {
				return nil
			}
			if state != "paused" {
				return store.ErrMigrationState
			}
			state = "queued"
		case "retry":
			if state == "cleanup_pending" && task.ErrorCode != "" {
				break
			}
			if state != "failed" {
				return store.ErrMigrationState
			}
			state = "queued"
		case "cancel":
			if state == "cancelling" || state == "cancelled" {
				return nil
			}
			if state == "completed" {
				return store.ErrMigrationState
			}
			state = "cancelling"
		default:
			return store.ErrMigrationState
		}
		if task.Revision >= math.MaxInt64 {
			return store.ErrMigrationState
		}
		task.State = state
		task.ErrorCode = ""
		task.Revision++
		task.UpdatedAt = time.Now().Unix()
		if _, e = q.ExecContext(ctx, "UPDATE migration_tasks SET state=?,revision=?,error_code='',updated_at=? WHERE task_id=?", state, task.Revision, task.UpdatedAt, id); e != nil {
			return e
		}
		// Keep runner tombstones/epochs: an expired or paused actor cannot commit
		// after another worker resumes this task (including the same process ID).
		if _, e = q.ExecContext(ctx, "UPDATE migration_runners SET expires_at=0 WHERE task_id=?", id); e != nil {
			return e
		}
		return r.nodeAudit(ctx, q, "resource-migration-"+action, "", map[string]any{"task_id": id, "state": state, "committed_bytes": task.CommittedBytes}, a)
	})
	return
}
func migrationRunnable(state string) bool {
	return state == "queued" || state == "copying" || state == "verifying" || state == "committing" || state == "cleanup_pending"
}

func (r *Repository) ClaimMigration(ctx context.Context, task, runner string, ttl time.Duration) (lease store.MigrationLease, e error) {
	if !nodeIDPattern.MatchString(task) || !nodeIDPattern.MatchString(runner) || ttl < 5*time.Second || ttl > time.Minute {
		return lease, store.ErrMigrationLease
	}
	e = r.write(ctx, func(q queryer) error {
		n, e := readNode(ctx, q, r.lock())
		if e != nil {
			return e
		}
		t, e := scanMigrationTask(q.QueryRowContext(ctx, "SELECT "+migrationTaskColumns+" FROM migration_tasks WHERE task_id=?"+r.lock(), task))
		if e != nil {
			return e
		}
		if n.Role != "Master" || n.ID != t.MasterID || !migrationRunnable(t.State) && t.State != "cancelling" {
			return store.ErrMigrationLease
		}
		now := time.Now().Unix()
		var old store.MigrationLease
		e = q.QueryRowContext(ctx, "SELECT task_id,runner_id,epoch,expires_at FROM migration_runners WHERE task_id=?"+r.lock(), task).Scan(&old.TaskID, &old.RunnerID, &old.Epoch, &old.ExpiresAt)
		if e == nil {
			if old.ExpiresAt > now {
				return store.ErrMigrationLease
			}
			if old.Epoch >= math.MaxInt64 {
				return store.ErrMigrationLease
			}
			lease = store.MigrationLease{TaskID: task, RunnerID: runner, Epoch: old.Epoch + 1, ExpiresAt: now + int64(ttl/time.Second)}
			_, e = q.ExecContext(ctx, "UPDATE migration_runners SET runner_id=?,epoch=?,expires_at=? WHERE task_id=?", runner, lease.Epoch, lease.ExpiresAt, task)
			return e
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		lease = store.MigrationLease{TaskID: task, RunnerID: runner, Epoch: 1, ExpiresAt: now + int64(ttl/time.Second)}
		_, e = q.ExecContext(ctx, "INSERT INTO migration_runners(task_id,runner_id,epoch,expires_at) VALUES (?,?,?,?)", task, runner, lease.Epoch, lease.ExpiresAt)
		return e
	})
	return
}
func (r *Repository) checkMigrationLease(ctx context.Context, q queryer, l store.MigrationLease) (store.MigrationTask, error) {
	if !nodeIDPattern.MatchString(l.TaskID) || !nodeIDPattern.MatchString(l.RunnerID) || l.Epoch <= 0 {
		return store.MigrationTask{}, store.ErrMigrationLease
	}
	n, e := readNode(ctx, q, r.lock())
	if e != nil {
		return store.MigrationTask{}, e
	}
	t, e := scanMigrationTask(q.QueryRowContext(ctx, "SELECT "+migrationTaskColumns+" FROM migration_tasks WHERE task_id=?"+r.lock(), l.TaskID))
	if e != nil {
		return t, e
	}
	if n.Role != "Master" || n.ID != t.MasterID || !migrationRunnable(t.State) && t.State != "cancelling" {
		return t, store.ErrMigrationLease
	}
	var runner string
	var epoch, expires int64
	if e = q.QueryRowContext(ctx, "SELECT runner_id,epoch,expires_at FROM migration_runners WHERE task_id=?"+r.lock(), l.TaskID).Scan(&runner, &epoch, &expires); e != nil {
		return t, e
	}
	if runner != l.RunnerID || epoch != l.Epoch || expires <= time.Now().Unix() {
		return t, store.ErrMigrationLease
	}
	return t, nil
}
func (r *Repository) RenewMigration(ctx context.Context, l store.MigrationLease, ttl time.Duration) (store.MigrationLease, error) {
	if ttl < 5*time.Second || ttl > time.Minute {
		return l, store.ErrMigrationLease
	}
	e := r.write(ctx, func(q queryer) error {
		if _, e := r.checkMigrationLease(ctx, q, l); e != nil {
			return e
		}
		l.ExpiresAt = time.Now().Unix() + int64(ttl/time.Second)
		_, e := q.ExecContext(ctx, "UPDATE migration_runners SET expires_at=? WHERE task_id=? AND runner_id=? AND epoch=?", l.ExpiresAt, l.TaskID, l.RunnerID, l.Epoch)
		return e
	})
	return l, e
}
func (r *Repository) ReleaseMigration(ctx context.Context, l store.MigrationLease) error {
	return r.write(ctx, func(q queryer) error {
		if _, e := r.checkMigrationLease(ctx, q, l); e != nil {
			return e
		}
		_, e := q.ExecContext(ctx, "UPDATE migration_runners SET expires_at=0 WHERE task_id=? AND runner_id=? AND epoch=?", l.TaskID, l.RunnerID, l.Epoch)
		return e
	})
}
func (r *Repository) ReleaseMigrationDrain(ctx context.Context, id, confirmation string, a store.NodeAudit) error {
	if !nodeIDPattern.MatchString(id) {
		return store.ErrMigrationState
	}
	return r.write(ctx, func(q queryer) error {
		n, e := readNode(ctx, q, r.lock())
		if e != nil {
			return e
		}
		t, e := scanMigrationTask(q.QueryRowContext(ctx, "SELECT "+migrationTaskColumns+" FROM migration_tasks WHERE task_id=?"+r.lock(), id))
		if e != nil {
			return e
		}
		if n.Role != "Master" || n.ID != t.MasterID || confirmation != t.SourceID || t.State != "completed" && t.State != "cancelled" {
			return store.ErrMigrationState
		}
		for _, query := range []string{"SELECT COUNT(*) FROM migration_capacity WHERE task_id=? AND reserved_bytes<>0", "SELECT COUNT(*) FROM migration_scopes WHERE task_id=?", "SELECT COUNT(*) FROM migration_units WHERE task_id=? AND state NOT IN ('cleaned','cancelled')"} {
			var count int
			if e = q.QueryRowContext(ctx, query, id).Scan(&count); e != nil {
				return e
			}
			if count != 0 {
				return store.ErrMigrationState
			}
		}
		if _, e = q.ExecContext(ctx, "DELETE FROM migration_drains WHERE member_id=? AND owner_id=? AND reason='migration'", confirmation, id); e != nil {
			return e
		}
		return r.nodeAudit(ctx, q, "resource-migration-drain-released", "", map[string]any{"task_id": id, "source_id": confirmation}, a)
	})
}
