package business

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// DeleteEmptySealedUser retires an account after every recording has completed
// its own cleanup. The recording tombstones and audit references keep the old
// account ID, while its original name and credentials are released.
func (r *Repository) DeleteEmptySealedUser(ctx context.Context, tree *sealedtree.SQLStore, id string, expected *store.KaraokeUser, audit store.KaraokeAudit) (bool, error) {
	if !nodeIDPattern.MatchString(id) || expected != nil && expected.ID != id {
		return false, store.ErrUserMissing
	}
	var removed bool
	err := r.withSelectedMutation(ctx, tree, func(c context.Context, q queryer, _ *sealedtree.CoordinatedMutation) error {
		if err := r.accountMaster(c, q); err != nil {
			return err
		}
		current, err := userLookup(q.QueryRowContext(c, "SELECT "+userColumns+" FROM karaoke_users WHERE user_id=?"+r.lock(), id))
		if err != nil {
			return err
		}
		if current == nil || current.Status == "deleted" {
			return nil
		}
		if current.Status != "active" && current.Status != "banned" && current.Status != "deleting" ||
			expected != nil && (current.Status != "active" || current.CreatedAt != expected.CreatedAt || current.PasswordHash != expected.PasswordHash) {
			return store.ErrAccountConflict
		}
		var hasRecordings, migrating bool
		if err = q.QueryRowContext(c, `SELECT EXISTS(SELECT 1 FROM karaoke_recordings WHERE user_id=? AND state<>'deleted'),
			EXISTS(SELECT 1 FROM migration_scopes WHERE resource_kind='recording' AND parent_path=?)`, id, id).Scan(&hasRecordings, &migrating); err != nil {
			return err
		}
		if current.Used != 0 || hasRecordings || migrating {
			return store.ErrUserHasRecordings
		}
		result, err := q.ExecContext(c, `UPDATE karaoke_users SET username='已注销',username_key=?,password_hash='!',status='deleted',quota_bytes=0,updated_at=? WHERE user_id=? AND used_bytes=0`, "deleted:"+id, time.Now().Unix(), id)
		if err != nil {
			return err
		}
		if n, e := result.RowsAffected(); e != nil || n != 1 {
			return store.ErrAccountConflict
		}
		audit.UserID, audit.Result = id, "success"
		if err = r.karaokeAudit(c, q, audit); err != nil {
			return err
		}
		removed = true
		return nil
	})
	return removed && err == nil, err
}

func (r *Repository) StageUserDeletion(ctx context.Context, id string, a store.KaraokeAudit) (found bool, err error) {
	if !nodeIDPattern.MatchString(id) {
		return false, store.ErrUserMissing
	}
	err = r.legacyWrite(ctx, func(q queryer) error {
		if err := r.accountMaster(ctx, q); err != nil {
			return err
		}
		v, err := scanUser(q.QueryRowContext(ctx, "SELECT "+userColumns+" FROM karaoke_users WHERE user_id=?"+r.lock(), id))
		if errors.Is(err, sql.ErrNoRows) {
			found = false
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		if v.Status == "deleting" {
			return nil
		}
		var migrating int
		if err = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_scopes WHERE resource_kind='recording' AND parent_path=?", id).Scan(&migrating); err != nil {
			return err
		}
		if migrating != 0 {
			return store.ErrMigrationState
		}
		now := time.Now().Unix()
		if _, err := q.ExecContext(ctx, "UPDATE karaoke_users SET status='deleting',updated_at=? WHERE user_id=?", now, id); err != nil {
			return err
		}
		if _, err := q.ExecContext(ctx, "UPDATE karaoke_recordings SET state='deleting',updated_at=? WHERE user_id=? AND state IN ('pending','ready')", now, id); err != nil {
			return err
		}
		a.UserID, a.Result = id, "pending"
		return r.karaokeAudit(ctx, q, a)
	})
	return
}
func (r *Repository) FinishUserDeletion(ctx context.Context, id string, a store.KaraokeAudit) (complete bool, err error) {
	err = r.legacyWrite(ctx, func(q queryer) error {
		complete = false
		if err := r.accountMaster(ctx, q); err != nil {
			return err
		}
		v, err := scanUser(q.QueryRowContext(ctx, "SELECT "+userColumns+" FROM karaoke_users WHERE user_id=?"+r.lock(), id))
		if errors.Is(err, sql.ErrNoRows) {
			complete = true
			return nil
		}
		if err != nil {
			return err
		}
		if v.Status != "deleting" {
			return store.ErrAccountConflict
		}
		var count int
		if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM karaoke_recordings WHERE user_id=?", id).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			_, err = q.ExecContext(ctx, "UPDATE karaoke_users SET updated_at=? WHERE user_id=?", time.Now().Unix(), id)
			return err
		}
		if v.Used != 0 {
			return store.ErrAccountConflict
		}
		a.UserID, a.Result = id, "success"
		if err := r.karaokeAudit(ctx, q, a); err != nil {
			return err
		}
		if _, err := q.ExecContext(ctx, "DELETE FROM karaoke_users WHERE user_id=?", id); err != nil {
			return err
		}
		complete = true
		return nil
	})
	return
}
func (r *Repository) DeletingUsers(ctx context.Context, limit int) ([]string, error) {
	n, err := r.ReadIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if n.Role != "Master" {
		return nil, nil
	}
	if limit < 1 || limit > 500 {
		limit = 20
	}
	rows, err := r.db.QueryContext(ctx, "SELECT user_id FROM karaoke_users WHERE status='deleting' ORDER BY updated_at,user_id LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
