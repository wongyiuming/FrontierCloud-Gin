package business

import (
	"context"
	"database/sql"
	"errors"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (r *Repository) peerUnitFinishWork(ctx context.Context, q queryer, rel string, l store.MigrationLease, g store.MigrationUnitFinishGrant, cancelling bool) (objects []store.MigrationPeerObject, e error) {
	e = r.validatePeerUnit(ctx, q, rel, l, g, cancelling, func(o store.MigrationPeerObject) error {
		if len(objects) >= store.MaxMigrationObjects {
			return store.ErrMigrationInventoryLimit
		}
		objects = append(objects, o)
		return nil
	})
	return
}

func (r *Repository) PeerMigrationUnitFinishWork(ctx context.Context, rel string, l store.MigrationLease, g store.MigrationUnitFinishGrant) (objects []store.MigrationPeerObject, e error) {
	e = r.write(ctx, func(q queryer) error {
		var err error
		objects, err = r.peerUnitFinishWork(ctx, q, rel, l, g, false)
		return err
	})
	return
}
func (r *Repository) CompletePeerMigrationUnit(ctx context.Context, rel string, l store.MigrationLease, g store.MigrationUnitFinishGrant, a store.NodeAudit) (receipt store.MigrationUnitFinishReceipt, e error) {
	e = r.write(ctx, func(q queryer) error {
		if e := r.validatePeerUnit(ctx, q, rel, l, g, false, nil); e != nil {
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
