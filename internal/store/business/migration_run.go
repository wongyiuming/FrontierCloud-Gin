package business

import (
	"context"
	"database/sql"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"math"
	"time"
)

// Runnable lookup does not acquire a lease or alter a task. Historical tasks
// cannot hide an older runnable task behind the GUI's bounded history list.
func (r *Repository) NextMigrationRun(ctx context.Context) (string, error) {
	n, e := r.ReadIdentity(ctx)
	if e != nil {
		return "", e
	}
	if n.Role != "Master" {
		return "", nil
	}
	var id string
	e = r.db.QueryRowContext(ctx, "SELECT t.task_id FROM migration_tasks t LEFT JOIN migration_runners r ON r.task_id=t.task_id WHERE t.master_id=? AND (t.state IN ('queued','copying','verifying','committing') OR (t.state='cancelling' AND t.error_code='' AND (EXISTS (SELECT 1 FROM migration_units cu WHERE cu.task_id=t.task_id AND cu.committed_at=0 AND cu.state NOT IN ('cleaned','cancelled')) OR EXISTS (SELECT 1 FROM migration_units cu WHERE cu.task_id=t.task_id AND cu.state='cleanup_pending' AND cu.committed_at>0 AND cu.cleanup_after>=cu.committed_at+3600 AND cu.cleanup_after<=?) OR NOT EXISTS (SELECT 1 FROM migration_units cu WHERE cu.task_id=t.task_id AND cu.state NOT IN ('cleaned','cancelled')))) OR (t.state='cleanup_pending' AND t.error_code='' AND (EXISTS (SELECT 1 FROM migration_units u JOIN migration_objects o ON o.task_id=u.task_id AND o.unit_id=u.unit_id WHERE u.task_id=t.task_id AND u.state='cleanup_pending' AND u.committed_at>0 AND u.cleanup_after>=u.committed_at+3600 AND u.cleanup_after<=? AND o.state IN ('cleanup_pending','cleaned')) OR NOT EXISTS (SELECT 1 FROM migration_units pending_unit WHERE pending_unit.task_id=t.task_id AND pending_unit.state<>'cleaned')))) AND (r.task_id IS NULL OR r.expires_at<=?) ORDER BY t.created_at,t.task_id LIMIT 1", n.ID, time.Now().Unix(), time.Now().Unix(), time.Now().Unix()).Scan(&id)
	if errors.Is(e, sql.ErrNoRows) {
		return "", nil
	}
	return id, e
}

func (r *Repository) ValidateMigrationLease(ctx context.Context, l store.MigrationLease) error {
	return r.write(ctx, func(q queryer) error { _, e := r.checkMigrationLease(ctx, q, l); return e })
}

// Only a currently fenced runner records execution phases/failures. Error codes
// are stable, bounded identifiers; peer text, credentials and URLs are excluded.
func (r *Repository) MigrationRunState(ctx context.Context, l store.MigrationLease, state, object, code string, a store.NodeAudit) error {
	if state != "copying" && state != "verifying" && state != "committing" && state != "cleanup_pending" && state != "failed" && state != "cancelling" {
		return store.ErrMigrationState
	}
	if object != "" && !nodeHashPattern.MatchString(object) && !nodeIDPattern.MatchString(object) {
		return store.ErrMigrationState
	}
	if code != "" && code != "peer_transport" && code != "peer_conflict" && code != "target_verification" && code != "target_publication" && code != "unit_commit" && code != "source_cleanup" && code != "cancel_cleanup" {
		return store.ErrMigrationState
	}
	return r.write(ctx, func(q queryer) error {
		t, e := r.checkMigrationLease(ctx, q, l)
		if e != nil {
			return e
		}
		if !migrationRunnable(t.State) && t.State != "cancelling" || t.Revision == math.MaxInt64 {
			return store.ErrMigrationState
		}
		if (t.State == "cancelling") != (state == "cancelling") {
			return store.ErrMigrationState
		}
		if t.State == "cleanup_pending" && state != "cleanup_pending" && state != "failed" {
			return store.ErrMigrationState
		}
		if state == "cleanup_pending" {
			var unfinished int
			if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_units WHERE task_id=? AND state NOT IN ('cleanup_pending','cleaned')", l.TaskID).Scan(&unfinished); e != nil {
				return e
			}
			if unfinished != 0 {
				return store.ErrMigrationState
			}
		}
		errorCode := code
		if _, e = q.ExecContext(ctx, "UPDATE migration_tasks SET state=?,error_code=?,revision=revision+1,updated_at=? WHERE task_id=?", state, errorCode, time.Now().Unix(), l.TaskID); e != nil {
			return e
		}
		if state == "failed" {
			if _, e = q.ExecContext(ctx, "UPDATE migration_runners SET expires_at=0 WHERE task_id=? AND runner_id=? AND epoch=?", l.TaskID, l.RunnerID, l.Epoch); e != nil {
				return e
			}
		}
		return r.nodeAudit(ctx, q, "resource-migration-run-"+state, "", map[string]any{"task_id": l.TaskID, "object_id": object, "code": code}, a)
	})
}
