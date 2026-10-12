package business

import (
	"context"
	"database/sql"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"time"
)

func (r *Repository) PeerMigrationUnitCancelWork(ctx context.Context, rel string, l store.MigrationLease, g store.MigrationUnitFinishGrant) (objects []store.MigrationPeerObject, e error) {
	e = r.write(ctx, func(q queryer) error {
		var err error
		objects, err = r.peerUnitFinishWork(ctx, q, rel, l, g, true)
		return err
	})
	return
}
func (r *Repository) CompletePeerMigrationUnitCancellation(ctx context.Context, rel string, l store.MigrationLease, g store.MigrationUnitFinishGrant, a store.NodeAudit) (receipt store.MigrationUnitFinishReceipt, e error) {
	e = r.write(ctx, func(q queryer) error {
		if _, e := r.peerUnitFinishWork(ctx, q, rel, l, g, true); e != nil {
			return e
		}
		n, e := r.ownedStorageNode(ctx, q, rel)
		if e != nil {
			return e
		}
		var phase, version string
		var count, bytes, committed, after int64
		e = q.QueryRowContext(ctx, "SELECT state,source_version,object_count,total_bytes,committed_at,cleanup_after FROM migration_units WHERE task_id=? AND unit_id=?"+r.lock(), l.TaskID, g.Unit.ID).Scan(&phase, &version, &count, &bytes, &committed, &after)
		if e == nil {
			if phase != "cancelled" || version != g.UnitVersion || count != g.Unit.ObjectCount || bytes != g.Unit.Bytes || committed != 0 || after != 0 {
				return store.ErrMigrationState
			}
			receipt = store.MigrationUnitFinishReceipt{Grant: g, MemberID: n.ID, Complete: true}
			return nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		// Publication already converts target reservation into used capacity. Only
		// unpublished aborts may refund this reservation; published units are blocked.
		if n.ID == g.Header.TargetID {
			var reserved, memberReserved int64
			if e = q.QueryRowContext(ctx, "SELECT reserved_bytes FROM migration_capacity WHERE task_id=? AND member_id=?"+r.lock(), l.TaskID, n.ID).Scan(&reserved); e != nil {
				return e
			}
			if e = q.QueryRowContext(ctx, "SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?"+r.lock(), n.ID).Scan(&memberReserved); e != nil {
				return e
			}
			if reserved < g.Unit.Bytes || memberReserved < g.Unit.Bytes {
				return store.ErrMigrationState
			}
			now := time.Now().Unix()
			if _, e = q.ExecContext(ctx, "UPDATE migration_capacity SET reserved_bytes=reserved_bytes-?,updated_at=? WHERE task_id=?", g.Unit.Bytes, now, l.TaskID); e != nil {
				return e
			}
			if _, e = q.ExecContext(ctx, "UPDATE cluster_storage_members SET reserved_bytes=reserved_bytes-?,updated_at=? WHERE member_id=?", g.Unit.Bytes, now, n.ID); e != nil {
				return e
			}
		}
		if _, e = q.ExecContext(ctx, "INSERT INTO migration_units(task_id,unit_id,resource_kind,parent_path,source_version,state,object_count,total_bytes) VALUES (?,?,?,?,?,'cancelled',?,?)", l.TaskID, g.Unit.ID, g.Unit.Resource, g.Unit.Parent, g.UnitVersion, g.Unit.ObjectCount, g.Unit.Bytes); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "DELETE FROM migration_scopes WHERE task_id=? AND member_id=? AND resource_kind=? AND parent_path=?", l.TaskID, n.ID, g.Unit.Resource, g.Unit.Parent); e != nil {
			return e
		}
		if e = r.nodeAudit(ctx, q, "peer-migration-unit-cancelled", rel, map[string]any{"task_id": l.TaskID, "unit_id": g.Unit.ID, "objects_sha256": g.ObjectsSHA}, a); e != nil {
			return e
		}
		receipt = store.MigrationUnitFinishReceipt{Grant: g, MemberID: n.ID, Complete: true}
		return nil
	})
	return
}
