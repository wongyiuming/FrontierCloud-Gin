package business

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (r *Repository) peerUnitFinishWork(ctx context.Context, q queryer, rel string, l store.MigrationLease, g store.MigrationUnitFinishGrant) (objects []store.MigrationPeerObject, e error) {
	h, n, state, e := r.checkPeerLease(ctx, q, rel, l)
	if e != nil {
		return nil, e
	}
	expected, _ := store.MigrationDigest(h)
	actual, _ := store.MigrationDigest(g.Header)
	if state == "cancelling" || expected != actual || g.Unit.State != "cleanup_pending" || !nodeHashPattern.MatchString(g.UnitVersion) || g.Unit.CommittedAt <= 0 || g.Unit.CleanupAfter < g.Unit.CommittedAt+3600 || g.Unit.CleanupAfter > time.Now().Unix() {
		return nil, store.ErrMigrationState
	}
	var count, total int64
	if e = q.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(expected_bytes),0) FROM migration_storage_journal WHERE task_id=?", l.TaskID).Scan(&count, &total); e != nil {
		return nil, e
	}
	if count != h.ObjectCount || total != h.Bytes {
		return nil, store.ErrMigrationState
	}
	rows, e := q.QueryContext(ctx, "SELECT logical_id,state,sha256 FROM migration_storage_journal WHERE task_id=? AND unit_id=? ORDER BY logical_id", l.TaskID, g.Unit.ID)
	if e != nil {
		return nil, e
	}
	type row struct{ id, state, sha string }
	entries := []row{}
	for rows.Next() {
		var entry row
		if e = rows.Scan(&entry.id, &entry.state, &entry.sha); e != nil {
			rows.Close()
			return nil, e
		}
		entries = append(entries, entry)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	objects = []store.MigrationPeerObject{}
	var bytes int64
	for _, entry := range entries {
		phase := "published"
		if n.ID == h.SourceID {
			phase = "deleted"
		}
		if entry.state != phase {
			return nil, store.ErrMigrationState
		}
		o, e := r.peerObjectBinding(ctx, q, l.TaskID, entry.id)
		if e != nil {
			return nil, e
		}
		if migrationUnit(o) != g.Unit.ID || o.Parent != g.Unit.Parent || o.Resource != g.Unit.Resource {
			return nil, store.ErrMigrationState
		}
		bytes += o.Bytes
		objects = append(objects, store.MigrationPeerObject{Object: o, Proof: store.MigrationDiskProof{ID: o.ID, Version: o.Version, Bytes: o.Bytes, SHA256: entry.sha}})
		if n.ID == h.SourceID {
			var reads int
			if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_read_leases WHERE member_id=? AND (logical_id=? OR object_id=?) AND expires_at>?", n.ID, o.ID, o.ObjectID, time.Now().Unix()).Scan(&reads); e != nil {
				return nil, e
			}
			if reads != 0 {
				return nil, store.ErrMigrationState
			}
		}
	}
	sha, e := store.MigrationUnitObjectsSHA(objects)
	if e != nil {
		return nil, e
	}
	if int64(len(objects)) != g.Unit.ObjectCount || bytes != g.Unit.Bytes || sha != g.ObjectsSHA {
		return nil, store.ErrMigrationState
	}
	return objects, nil
}
func (r *Repository) PeerMigrationUnitFinishWork(ctx context.Context, rel string, l store.MigrationLease, g store.MigrationUnitFinishGrant) (objects []store.MigrationPeerObject, e error) {
	e = r.write(ctx, func(q queryer) error {
		var err error
		objects, err = r.peerUnitFinishWork(ctx, q, rel, l, g)
		return err
	})
	return
}
func (r *Repository) CompletePeerMigrationUnit(ctx context.Context, rel string, l store.MigrationLease, g store.MigrationUnitFinishGrant, a store.NodeAudit) (receipt store.MigrationUnitFinishReceipt, e error) {
	e = r.write(ctx, func(q queryer) error {
		if _, e := r.peerUnitFinishWork(ctx, q, rel, l, g); e != nil {
			return e
		}
		n, e := r.ownedStorageNode(ctx, q, rel)
		if e != nil {
			return e
		}
		var state, version string
		var count, bytes, committed, after int64
		e = q.QueryRowContext(ctx, "SELECT state,source_version,object_count,total_bytes,committed_at,cleanup_after FROM migration_units WHERE task_id=? AND unit_id=?"+r.lock(), l.TaskID, g.Unit.ID).Scan(&state, &version, &count, &bytes, &committed, &after)
		if e == nil {
			if version != g.UnitVersion || count != g.Unit.ObjectCount || bytes != g.Unit.Bytes || committed != g.Unit.CommittedAt || after != g.Unit.CleanupAfter || state != "cleanup_pending" && state != "cleaned" {
				return store.ErrMigrationState
			}
			if state == "cleaned" {
				receipt = store.MigrationUnitFinishReceipt{Grant: g, MemberID: n.ID, Complete: true}
				return nil
			}
		} else if !errors.Is(e, sql.ErrNoRows) {
			return e
		} else {
			if _, e = q.ExecContext(ctx, "INSERT INTO migration_units(task_id,unit_id,resource_kind,parent_path,source_version,state,object_count,total_bytes,committed_at,cleanup_after) VALUES (?,?,?,?,?,'cleanup_pending',?,?,?,?)", l.TaskID, g.Unit.ID, g.Unit.Resource, g.Unit.Parent, g.UnitVersion, g.Unit.ObjectCount, g.Unit.Bytes, g.Unit.CommittedAt, g.Unit.CleanupAfter); e != nil {
				return e
			}
		}
		if _, e = q.ExecContext(ctx, "UPDATE migration_units SET state='cleaned' WHERE task_id=? AND unit_id=?", l.TaskID, g.Unit.ID); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "DELETE FROM migration_scopes WHERE task_id=? AND member_id=? AND resource_kind=? AND parent_path=?", l.TaskID, n.ID, g.Unit.Resource, g.Unit.Parent); e != nil {
			return e
		}
		if e = r.nodeAudit(ctx, q, "peer-migration-unit-cleaned", rel, map[string]any{"task_id": l.TaskID, "unit_id": g.Unit.ID, "objects_sha256": g.ObjectsSHA}, a); e != nil {
			return e
		}
		receipt = store.MigrationUnitFinishReceipt{Grant: g, MemberID: n.ID, Complete: true}
		return nil
	})
	return
}
