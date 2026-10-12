package business

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const migrationReadSeconds = 300

func (r *Repository) migrationReadAllowed(ctx context.Context, q queryer, member, physical string) error {
	var count int
	if e := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_storage_journal j JOIN migration_tasks t ON t.task_id=j.task_id WHERE (j.source_id=? OR j.target_id=?) AND j.object_id=? AND j.state IN ('deleting','deleted') AND t.state NOT IN ('completed','cancelled')", member, member, physical).Scan(&count); e != nil {
		return e
	}
	if count != 0 {
		return store.ErrMigrationState
	}
	return nil
}

func (r *Repository) AcquireMigrationRead(ctx context.Context, relationship, logical, physical, resource string) (id string, e error) {
	if !nodeIDPattern.MatchString(relationship) {
		return "", store.ErrMigrationState
	}
	valid := nodeHashPattern.MatchString
	if resource == "recording" {
		valid = nodeIDPattern.MatchString
	} else if resource != "media" {
		return "", store.ErrMigrationState
	}
	if !valid(logical) || !valid(physical) {
		return "", store.ErrMigrationState
	}
	raw := make([]byte, 16)
	if _, e = rand.Read(raw); e != nil {
		return "", e
	}
	id = hex.EncodeToString(raw)
	e = r.write(ctx, func(q queryer) error {
		n, e := r.ownedStorageNode(ctx, q, relationship)
		if e != nil {
			return e
		}
		if e = r.migrationReadAllowed(ctx, q, n.ID, physical); e != nil {
			return e
		}
		now := time.Now().Unix()
		if _, e = q.ExecContext(ctx, "DELETE FROM migration_read_leases WHERE member_id=? AND expires_at<=?", n.ID, now); e != nil {
			return e
		}
		var count int
		if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_read_leases WHERE member_id=?", n.ID).Scan(&count); e != nil {
			return e
		}
		if count >= 1024 {
			return store.ErrMigrationState
		}
		// Before registration there is no migration content version. This binding
		// still fences physical identity; registration never discards live reads.
		sum := sha256.Sum256([]byte(resource + ":" + physical))
		version := hex.EncodeToString(sum[:])
		e = q.QueryRowContext(ctx, "SELECT source_version FROM migration_storage_journal WHERE source_id=? AND object_id=? ORDER BY updated_at DESC,task_id DESC LIMIT 1", n.ID, physical).Scan(&version)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		_, e = q.ExecContext(ctx, "INSERT INTO migration_read_leases(lease_id,member_id,logical_id,object_id,source_version,expires_at) VALUES (?,?,?,?,?,?)", id, n.ID, logical, physical, version, now+migrationReadSeconds)
		return e
	})
	if e != nil {
		return "", e
	}
	return id, nil
}

func (r *Repository) RenewMigrationRead(ctx context.Context, relationship, id string) error {
	if !nodeIDPattern.MatchString(id) || !nodeIDPattern.MatchString(relationship) {
		return store.ErrMigrationState
	}
	return r.write(ctx, func(q queryer) error {
		n, e := r.ownedStorageNode(ctx, q, relationship)
		if e != nil {
			return e
		}
		var physical string
		var expires int64
		if e = q.QueryRowContext(ctx, "SELECT object_id,expires_at FROM migration_read_leases WHERE lease_id=? AND member_id=?"+r.lock(), id, n.ID).Scan(&physical, &expires); e != nil {
			return e
		}
		if expires <= time.Now().Unix() {
			return store.ErrMigrationState
		}
		if e = r.migrationReadAllowed(ctx, q, n.ID, physical); e != nil {
			return e
		}
		_, e = q.ExecContext(ctx, "UPDATE migration_read_leases SET expires_at=? WHERE lease_id=?", time.Now().Unix()+migrationReadSeconds, id)
		return e
	})
}

func (r *Repository) ReleaseMigrationRead(ctx context.Context, id string) error {
	if !nodeIDPattern.MatchString(id) {
		return store.ErrMigrationState
	}
	return r.write(ctx, func(q queryer) error {
		n, e := readNode(ctx, q, r.lock())
		if e != nil {
			return e
		}
		_, e = q.ExecContext(ctx, "DELETE FROM migration_read_leases WHERE lease_id=? AND member_id=?", id, n.ID)
		return e
	})
}
