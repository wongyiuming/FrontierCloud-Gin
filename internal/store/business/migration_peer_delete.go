package business

import (
	"context"
	"encoding/json"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// checkPeerMediaDelete checks the already-persisted cleanup grant. Commit does
// not invent permission from a path or from a missing file; the pending managed
// delete operation and the source journal must name the same immutable object.
func (r *Repository) checkPeerMediaDelete(ctx context.Context, q queryer, member string, item store.DeleteItem) error {
	if !nodeIDPattern.MatchString(item.MigrationTask) || !nodeHashPattern.MatchString(item.MigrationLogical) || item.Absent || item.GlobalID != "" {
		return store.ErrMigrationState
	}
	h, _, e := r.peerHeader(ctx, q, item.MigrationTask)
	if e != nil {
		return e
	}
	if h.SourceID != member {
		return store.ErrMigrationState
	}
	o, e := r.peerObjectBinding(ctx, q, item.MigrationTask, item.MigrationLogical)
	if e != nil {
		return e
	}
	if o.Resource != "media" || o.ObjectID != item.OwnedID || o.Path != item.Path || o.Bytes != item.Bytes {
		return store.ErrMigrationState
	}
	var phase, version, hash string
	var size int64
	if e = q.QueryRowContext(ctx, "SELECT state,source_version,sha256,expected_bytes FROM migration_storage_journal WHERE task_id=? AND logical_id=?"+r.lock(), item.MigrationTask, item.MigrationLogical).Scan(&phase, &version, &hash, &size); e != nil {
		return e
	}
	if phase != "deleting" || version != o.Version || size != o.Bytes || !nodeHashPattern.MatchString(hash) {
		return store.ErrMigrationState
	}
	var committed, after int64
	var unitState string
	if e = q.QueryRowContext(ctx, "SELECT state,committed_at,cleanup_after FROM migration_units WHERE task_id=? AND unit_id=?"+r.lock(), item.MigrationTask, migrationUnit(o)).Scan(&unitState, &committed, &after); e != nil {
		return e
	}
	if unitState != "cleanup_pending" || committed <= 0 || after < committed+3600 || after > time.Now().Unix() {
		return store.ErrMigrationState
	}
	var name, kind string
	if e = q.QueryRowContext(ctx, "SELECT media_path,object_kind FROM media_objects WHERE media_id=?"+r.lock(), o.ObjectID).Scan(&name, &kind); e != nil {
		return e
	}
	if name != o.Path || kind != o.Kind {
		return store.ErrMigrationState
	}
	enc, e := readEncryption(ctx, q, o.ObjectID, r.lock())
	if e != nil {
		return e
	}
	if (enc == nil) != (o.Encryption == nil) || enc != nil && *enc != *o.Encryption {
		return store.ErrMigrationState
	}
	var reads int
	if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_read_leases WHERE member_id=? AND (logical_id=? OR object_id=?) AND expires_at>?", member, o.ID, o.ObjectID, time.Now().Unix()).Scan(&reads); e != nil {
		return e
	}
	if reads != 0 {
		return store.ErrMigrationState
	}
	return nil
}

func (r *Repository) PreparePeerMediaDelete(ctx context.Context, relationship string, l store.MigrationLease, operation store.DeleteOperation, a store.NodeAudit) error {
	item, e := ownedDeleteItem(operation)
	if e != nil {
		return e
	}
	if item.MigrationTask != l.TaskID {
		return store.ErrMigrationState
	}
	manifest, e := json.Marshal(operation.Items)
	if e != nil {
		return e
	}
	return r.write(ctx, func(q queryer) error {
		h, n, _, e := r.checkPeerLease(ctx, q, relationship, l)
		if e != nil {
			return e
		}
		if n.ID != h.SourceID {
			return store.ErrMigrationState
		}
		if e = r.checkPeerMediaDelete(ctx, q, n.ID, item); e != nil {
			return e
		}
		if e = r.ownedDeleteAccounting(ctx, q, n.ID, item); e != nil {
			return e
		}
		var used int64
		if e = q.QueryRowContext(ctx, "SELECT used_bytes FROM cluster_storage_members WHERE member_id=?"+r.lock(), n.ID).Scan(&used); e != nil {
			return e
		}
		if used < item.Bytes {
			return store.ErrMigrationState
		}
		if _, e = q.ExecContext(ctx, "INSERT INTO media_delete_operations(operation_id,state,manifest,created_at) VALUES (?,'pending',?,?)", operation.ID, string(manifest), timestamp(time.Now())); e != nil {
			return e
		}
		return r.nodeAudit(ctx, q, "peer-migration-delete-prepared", relationship, map[string]any{"task_id": l.TaskID, "logical_id": item.MigrationLogical, "operation": operation.ID}, a)
	})
}
