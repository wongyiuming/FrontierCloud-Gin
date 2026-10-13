package business

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (r *Repository) MigrationTasksPage(ctx context.Context, afterTime int64, afterID string) (page store.MigrationTaskPage, e error) {
	page = store.MigrationTaskPage{Tasks: []store.MigrationTask{}, AfterTime: afterTime, AfterID: afterID, NextTime: afterTime, NextID: afterID}
	if afterTime < 0 || (afterID == "" && afterTime != 0) || (afterID != "" && !nodeIDPattern.MatchString(afterID)) {
		return page, store.ErrMigrationState
	}
	n, e := r.ReadIdentity(ctx)
	if e != nil || n.Role != "Master" {
		return page, store.ErrMigrationState
	}
	query := "SELECT " + migrationTaskColumns + " FROM migration_tasks WHERE master_id=?"
	args := []any{n.ID}
	if afterID != "" {
		query += " AND (created_at<? OR (created_at=? AND task_id<?))"
		args = append(args, afterTime, afterTime, afterID)
	}
	query += " ORDER BY created_at DESC,task_id DESC LIMIT 17"
	rows, e := r.db.QueryContext(ctx, query, args...)
	if e != nil {
		return page, e
	}
	defer rows.Close()
	page.Complete = true
	for rows.Next() {
		if len(page.Tasks) == 16 {
			page.Complete = false
			break
		}
		task, e := scanMigrationTask(rows)
		if e != nil {
			return page, e
		}
		page.Tasks = append(page.Tasks, task)
		page.NextID = task.ID
		page.NextTime = task.CreatedAt
	}
	return page, rows.Err()
}
func (r *Repository) MigrationStatus(ctx context.Context, id, after string) (result store.MigrationStatus, e error) {
	result = store.MigrationStatus{After: after, Next: after, Objects: []store.MigrationObjectStatus{}, ObjectStages: []store.MigrationStage{}, UnitStages: []store.MigrationStage{}}
	if !nodeIDPattern.MatchString(id) || after != "" && !nodeHashPattern.MatchString(after) {
		return result, store.ErrMigrationState
	}
	tx, e := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return result, e
	}
	defer tx.Rollback()
	n, e := readNode(ctx, tx, "")
	if e != nil || n.Role != "Master" {
		return result, store.ErrMigrationState
	}
	result.Task, e = scanMigrationTask(tx.QueryRowContext(ctx, "SELECT "+migrationTaskColumns+" FROM migration_tasks WHERE task_id=?", id))
	if e != nil {
		return result, e
	}
	if result.Task.MasterID != n.ID {
		return result, store.ErrMigrationState
	}
	stages := func(query string) ([]store.MigrationStage, error) {
		rows, e := tx.QueryContext(ctx, query, id)
		if e != nil {
			return nil, e
		}
		defer rows.Close()
		values := []store.MigrationStage{}
		for rows.Next() {
			var value store.MigrationStage
			if e = rows.Scan(&value.State, &value.Count, &value.Bytes, &value.VerifiedBytes); e != nil {
				return nil, e
			}
			if len(values) >= 16 || len(value.State) > 32 || value.Count < 1 || value.Bytes < 0 || value.VerifiedBytes < 0 || value.VerifiedBytes > value.Bytes {
				return nil, store.ErrMigrationState
			}
			values = append(values, value)
		}
		return values, rows.Err()
	}
	result.ObjectStages, e = stages("SELECT state,COUNT(*),COALESCE(SUM(expected_bytes),0),COALESCE(SUM(verified_bytes),0) FROM migration_objects WHERE task_id=? GROUP BY state ORDER BY state")
	if e != nil {
		return result, e
	}
	result.UnitStages, e = stages("SELECT state,COUNT(*),COALESCE(SUM(total_bytes),0),0 FROM migration_units WHERE task_id=? GROUP BY state ORDER BY state")
	if e != nil {
		return result, e
	}
	rows, e := tx.QueryContext(ctx, "SELECT logical_id,unit_id,resource_kind,physical_path,state,expected_bytes,verified_bytes,updated_at FROM migration_objects WHERE task_id=? AND logical_id>? ORDER BY logical_id LIMIT 17", id, after)
	if e != nil {
		return result, e
	}
	result.Complete = true
	encodedBytes := 0
	for rows.Next() {
		var value store.MigrationObjectStatus
		if e = rows.Scan(&value.ID, &value.UnitID, &value.Resource, &value.Path, &value.State, &value.Bytes, &value.VerifiedBytes, &value.UpdatedAt); e != nil {
			rows.Close()
			return result, e
		}
		raw, e := json.Marshal(value)
		if e != nil || len(raw) > 48<<10 {
			rows.Close()
			return result, store.ErrMigrationInventoryLimit
		}
		if len(result.Objects) == 16 || encodedBytes+len(raw) > 48<<10 {
			result.Complete = false
			break
		}
		encodedBytes += len(raw)
		result.Objects = append(result.Objects, value)
		result.Next = value.ID
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return result, e
	}
	if e = tx.Commit(); e != nil {
		return result, e
	}
	return result, nil
}
