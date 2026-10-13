package business

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"iter"
	"time"
)

func (r *Repository) peerObjectPage(ctx context.Context, q queryer, task, unit, after string) (out []store.MigrationPeerObject, e error) {
	rows, e := q.QueryContext(ctx, "SELECT logical_id,state,sha256 FROM migration_storage_journal WHERE task_id=? AND unit_id=? AND logical_id>? ORDER BY logical_id LIMIT ?", task, unit, after, store.MigrationPageObjects)
	if e != nil {
		return nil, e
	}
	type entry struct{ id, state, sha string }
	entries := []entry{}
	for rows.Next() {
		var v entry
		if e = rows.Scan(&v.id, &v.state, &v.sha); e != nil {
			rows.Close()
			return nil, e
		}
		entries = append(entries, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	for _, v := range entries {
		o, e := r.peerObjectBinding(ctx, q, task, v.id)
		if e != nil {
			return nil, e
		}
		if migrationUnit(o) != unit || !nodeHashPattern.MatchString(v.sha) {
			return nil, store.ErrMigrationState
		}
		out = append(out, store.MigrationPeerObject{State: v.state, Object: o, Proof: store.MigrationDiskProof{ID: o.ID, Version: o.Version, Bytes: o.Bytes, SHA256: v.sha}})
	}
	return out, nil
}
func (r *Repository) peerObjects(ctx context.Context, q queryer, task, unit string) iter.Seq2[store.MigrationPeerObject, error] {
	return func(yield func(store.MigrationPeerObject, error) bool) {
		after := ""
		for {
			page, e := r.peerObjectPage(ctx, q, task, unit, after)
			if e != nil {
				yield(store.MigrationPeerObject{}, e)
				return
			}
			for _, o := range page {
				if !yield(o, nil) {
					return
				}
				after = o.Object.ID
			}
			if len(page) < store.MigrationPageObjects {
				return
			}
		}
	}
}
func (r *Repository) peerUnitAdmission(ctx context.Context, q queryer, rel string, l store.MigrationLease, g store.MigrationUnitFinishGrant, cancelling bool) (h store.MigrationPeerHeader, member string, e error) {
	h, n, state, e := r.checkPeerLease(ctx, q, rel, l)
	if e != nil {
		return h, "", e
	}
	expected, e := store.MigrationDigest(h)
	if e != nil {
		return h, "", e
	}
	actual, e := store.MigrationDigest(g.Header)
	if e != nil || expected != actual || !nodeHashPattern.MatchString(g.UnitVersion) || !nodeHashPattern.MatchString(g.ObjectsSHA) || g.Unit.ObjectCount <= 0 || g.Unit.Bytes < 0 {
		return h, "", store.ErrMigrationState
	}
	if cancelling {
		if state != "cancelling" || g.Unit.State != "cancelled" || g.Unit.CommittedAt != 0 || g.Unit.CleanupAfter != 0 {
			return h, "", store.ErrMigrationState
		}
	} else if g.Unit.State != "cleanup_pending" || g.Unit.CommittedAt <= 0 || g.Unit.CleanupAfter < g.Unit.CommittedAt+3600 || g.Unit.CleanupAfter > time.Now().Unix() {
		return h, "", store.ErrMigrationState
	}
	return h, n.ID, nil
}
func peerUnitPhase(member string, h store.MigrationPeerHeader, g store.MigrationUnitFinishGrant, o store.MigrationPeerObject, cancelling bool) error {
	phase := "published"
	if member == h.SourceID {
		phase = "deleted"
	}
	if cancelling {
		phase = "aborted"
		if member == h.SourceID {
			phase = "receiving"
		}
	}
	if o.State != phase && !(cancelling && member == h.TargetID && o.State == "deleted") || migrationUnit(o.Object) != g.Unit.ID || o.Object.Parent != g.Unit.Parent || o.Object.Resource != g.Unit.Resource {
		return store.ErrMigrationState
	}
	return nil
}
func (r *Repository) PeerMigrationUnitWorkPage(ctx context.Context, rel string, l store.MigrationLease, g store.MigrationUnitFinishGrant, cancelling bool, after string) (out []store.MigrationPeerObject, err error) {
	err = r.write(ctx, func(q queryer) error {
		h, member, e := r.peerUnitAdmission(ctx, q, rel, l, g, cancelling)
		if e != nil {
			return e
		}
		out, e = r.peerObjectPage(ctx, q, l.TaskID, g.Unit.ID, after)
		if e != nil {
			return e
		}
		for _, o := range out {
			if e = peerUnitPhase(member, h, g, o, cancelling); e != nil {
				return e
			}
		}
		return nil
	})
	return
}

func (r *Repository) validatePeerUnit(ctx context.Context, q queryer, rel string, l store.MigrationLease, g store.MigrationUnitFinishGrant, cancelling bool, visit func(store.MigrationPeerObject) error) error {
	h, member, e := r.peerUnitAdmission(ctx, q, rel, l, g, cancelling)
	if e != nil {
		return e
	}
	var count, total int64
	if e = q.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(expected_bytes),0) FROM migration_storage_journal WHERE task_id=?", l.TaskID).Scan(&count, &total); e != nil {
		return e
	}
	if count != h.ObjectCount || total != h.Bytes {
		return store.ErrMigrationState
	}
	var sequence store.MigrationSequence
	var bytes int64
	for object, err := range r.peerObjects(ctx, q, l.TaskID, g.Unit.ID) {
		if err != nil {
			return err
		}
		if e = peerUnitPhase(member, h, g, object, cancelling); e != nil {
			return e
		}
		if !cancelling && member == h.SourceID {
			var reads int
			if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_read_leases WHERE member_id=? AND (logical_id=? OR object_id=?) AND expires_at>?", member, object.Object.ID, object.Object.ObjectID, time.Now().Unix()).Scan(&reads); e != nil {
				return e
			}
			if reads != 0 {
				return store.ErrMigrationState
			}
		}
		if visit != nil {
			if e = visit(object); e != nil {
				return e
			}
		}
		object.State = ""
		object.Header = store.MigrationPeerHeader{}
		if e = sequence.Add(object.Object.ID, object); e != nil {
			return e
		}
		bytes += object.Object.Bytes
	}
	if sequence.Count() != g.Unit.ObjectCount || bytes != g.Unit.Bytes || sequence.Sum() != g.ObjectsSHA {
		return store.ErrMigrationState
	}
	return nil
}
