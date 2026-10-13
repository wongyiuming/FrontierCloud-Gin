package business

import (
	"context"
	"encoding/json"
	"iter"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (r *Repository) migrationHeader(ctx context.Context, q queryer, id string) (w store.MigrationWork, e error) {
	w.Task, e = scanMigrationTask(q.QueryRowContext(ctx, "SELECT "+migrationTaskColumns+" FROM migration_tasks WHERE task_id=?", id))
	if e != nil {
		return w, e
	}
	var raw []byte
	if e = q.QueryRowContext(ctx, "SELECT SUBSTR(plan,1,?) FROM migration_tasks WHERE task_id=?", store.MaxMigrationPlanBytes+1, id).Scan(&raw); e != nil {
		return w, e
	}
	if len(raw) > store.MaxMigrationPlanBytes {
		return w, store.ErrMigrationState
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(&w.Plan); e != nil {
		return w, e
	}
	sha, e := store.MigrationDigest(w.Plan)
	if e != nil || sha != w.Task.PlanSHA || w.Plan.ID != id {
		return w, store.ErrMigrationState
	}
	if w.Plan.Format != "" {
		var state, digest, catalog, proofs string
		var count, bytes, units int64
		if e = q.QueryRowContext(ctx, "SELECT state,plan_sha256,catalog_sha256,proofs_sha256,object_count,total_bytes,unit_count FROM migration_plan_headers WHERE plan_id=?", id).Scan(&state, &digest, &catalog, &proofs, &count, &bytes, &units); e != nil {
			return w, e
		}
		if w.Plan.Format != pagedMigrationFormat || state != "admitted" || digest != sha || catalog != w.Plan.Catalog.Version || proofs != w.Plan.ProofsSHA || count != w.Task.ObjectCount || count != w.Plan.ObjectCount || bytes != w.Task.TotalBytes || units != w.Plan.UnitCount || len(w.Plan.Catalog.Objects) != 0 || len(w.Plan.Proofs) != 0 {
			return w, store.ErrMigrationState
		}
	}
	return w, nil
}
func (r *Repository) MigrationHeader(ctx context.Context, id string) (store.MigrationWork, error) {
	if !nodeIDPattern.MatchString(id) {
		return store.MigrationWork{}, store.ErrMigrationState
	}
	n, e := r.ReadIdentity(ctx)
	if e != nil || n.Role != "Master" {
		return store.MigrationWork{}, store.ErrMigrationState
	}
	w, e := r.migrationHeader(ctx, r.db, id)
	if e == nil && w.Task.MasterID != n.ID {
		return w, store.ErrMigrationState
	}
	return w, e
}

const migrationUnitColumns = "unit_id,resource_kind,parent_path,state,object_count,total_bytes,committed_at,cleanup_after"

func scanMigrationUnit(row rowScanner) (u store.MigrationUnit, e error) {
	e = row.Scan(&u.ID, &u.Resource, &u.Parent, &u.State, &u.ObjectCount, &u.Bytes, &u.CommittedAt, &u.CleanupAfter)
	return
}
func (r *Repository) migrationUnitPage(ctx context.Context, q queryer, id, after string) (out []store.MigrationUnit, e error) {
	rows, e := q.QueryContext(ctx, "SELECT "+migrationUnitColumns+" FROM migration_units WHERE task_id=? AND unit_id>? ORDER BY unit_id LIMIT ?", id, after, store.MigrationPageObjects)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		u, e := scanMigrationUnit(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
func (r *Repository) MigrationUnitPage(ctx context.Context, id, after string) ([]store.MigrationUnit, error) {
	return r.migrationUnitPage(ctx, r.db, id, after)
}
func (r *Repository) MigrationUnit(ctx context.Context, id, unit string) (store.MigrationUnit, error) {
	return scanMigrationUnit(r.db.QueryRowContext(ctx, "SELECT "+migrationUnitColumns+" FROM migration_units WHERE task_id=? AND unit_id=?", id, unit))
}

func (r *Repository) migrationObjectPage(ctx context.Context, q queryer, id, unit, after, exact string) (out []store.MigrationCheckpoint, e error) {
	w, e := r.migrationHeader(ctx, q, id)
	if e != nil {
		return nil, e
	}
	if w.Plan.Format == "" {
		legacy, e := r.migrationWork(ctx, q, id)
		if e != nil {
			return nil, e
		}
		for _, cp := range legacy.Objects {
			if cp.Object.ID > after && (unit == "" || cp.UnitID == unit) && (exact == "" || cp.Object.ID == exact) {
				out = append(out, cp)
				if len(out) == store.MigrationPageObjects {
					break
				}
			}
		}
		return out, nil
	}
	query := "SELECT b.object_json,b.object_sha256,b.source_sha256,b.unit_id,o.logical_id,o.unit_id,o.state,o.source_sha256,o.target_sha256,o.verified_bytes,o.source_version,o.expected_bytes,o.physical_path,o.source_object,o.target_object,o.resource_kind FROM migration_objects o JOIN migration_plan_bindings b ON b.plan_id=o.task_id AND b.logical_id=o.logical_id WHERE o.task_id=? AND o.logical_id>?"
	args := []any{id, after}
	if unit != "" {
		query += " AND o.unit_id=?"
		args = append(args, unit)
	}
	if exact != "" {
		query += " AND o.logical_id=?"
		args = append(args, exact)
	}
	query += " ORDER BY o.logical_id LIMIT ?"
	args = append(args, store.MigrationPageObjects)
	rows, e := q.QueryContext(ctx, query, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var cp store.MigrationCheckpoint
		var raw []byte
		var sha, proof, unitBinding, logical, version, physical, sourceObject, targetObject, kind string
		var expected int64
		if e = rows.Scan(&raw, &sha, &proof, &unitBinding, &logical, &cp.UnitID, &cp.State, &cp.SourceSHA, &cp.TargetSHA, &cp.VerifiedBytes, &version, &expected, &physical, &sourceObject, &targetObject, &kind); e != nil {
			return nil, e
		}
		o, e := scanPlanObject(raw, sha)
		if e != nil {
			return nil, e
		}
		if logical != o.ID || migrationUnit(o) != unitBinding || unitBinding != cp.UnitID || version != o.Version || expected != o.Bytes || physical != o.Path || sourceObject != o.ObjectID || targetObject != o.ObjectID || kind != o.Resource || proof != cp.SourceSHA || !nodeHashPattern.MatchString(proof) {
			return nil, store.ErrMigrationState
		}
		cp.Object = o
		out = append(out, cp)
	}
	return out, rows.Err()
}
func (r *Repository) MigrationObjectPage(ctx context.Context, id, unit, after string) ([]store.MigrationCheckpoint, error) {
	return r.migrationObjectPage(ctx, r.db, id, unit, after, "")
}
func (r *Repository) MigrationObject(ctx context.Context, id, logical string) (store.MigrationCheckpoint, error) {
	objects, e := r.migrationObjectPage(ctx, r.db, id, "", "", logical)
	if e != nil {
		return store.MigrationCheckpoint{}, e
	}
	if len(objects) != 1 {
		return store.MigrationCheckpoint{}, store.ErrMigrationState
	}
	return objects[0], nil
}
func (r *Repository) migrationObjects(ctx context.Context, q queryer, id, unit string) iter.Seq2[store.MigrationCheckpoint, error] {
	return func(yield func(store.MigrationCheckpoint, error) bool) {
		after := ""
		for {
			page, e := r.migrationObjectPage(ctx, q, id, unit, after, "")
			if e != nil {
				yield(store.MigrationCheckpoint{}, e)
				return
			}
			for _, cp := range page {
				if cp.Object.ID <= after {
					yield(store.MigrationCheckpoint{}, store.ErrMigrationState)
					return
				}
				if !yield(cp, nil) {
					return
				}
				after = cp.Object.ID
			}
			if len(page) < store.MigrationPageObjects {
				return
			}
		}
	}
}
func (r *Repository) migrationUnits(ctx context.Context, q queryer, id string) iter.Seq2[store.MigrationUnit, error] {
	return func(yield func(store.MigrationUnit, error) bool) {
		after := ""
		for {
			page, e := r.migrationUnitPage(ctx, q, id, after)
			if e != nil {
				yield(store.MigrationUnit{}, e)
				return
			}
			for _, u := range page {
				if !yield(u, nil) {
					return
				}
				after = u.ID
			}
			if len(page) < store.MigrationPageObjects {
				return
			}
		}
	}
}

// Single-object authorization obtains the associated unit without reading
// other task objects. Legacy task JSON remains readable during the transition.
func (r *Repository) migrationObjectWork(ctx context.Context, q queryer, id, logical string) (w store.MigrationWork, e error) {
	w, e = r.migrationHeader(ctx, q, id)
	if e != nil {
		return w, e
	}
	w.Objects, e = r.migrationObjectPage(ctx, q, id, "", "", logical)
	if e != nil {
		return w, e
	}
	if len(w.Objects) != 1 {
		return w, store.ErrMigrationState
	}
	u, e := scanMigrationUnit(q.QueryRowContext(ctx, "SELECT "+migrationUnitColumns+" FROM migration_units WHERE task_id=? AND unit_id=?", id, w.Objects[0].UnitID))
	if e != nil {
		return w, e
	}
	w.Units = []store.MigrationUnit{u}
	return w, nil
}
