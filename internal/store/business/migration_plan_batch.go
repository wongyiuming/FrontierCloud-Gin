package business

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"strings"
)

func (r *Repository) migrationPlanBindingPage(ctx context.Context, q queryer, id, after string) (out []store.MigrationPeerObject, e error) {
	return r.migrationPlanUnitBindingPage(ctx, q, id, "", after)
}

func (r *Repository) migrationPlanUnitBindingPage(ctx context.Context, q queryer, id, selectedUnit, after string) (out []store.MigrationPeerObject, e error) {
	query := "SELECT logical_id,unit_id,resource_kind,source_object,object_json,object_sha256,expected_bytes,source_sha256,native_metadata_sha256,native_seen FROM migration_plan_bindings WHERE plan_id=? AND logical_id>?"
	args := []any{id, after}
	if selectedUnit != "" {
		query += " AND unit_id=?"
		args = append(args, selectedUnit)
	}
	query += " ORDER BY logical_id LIMIT ?"
	args = append(args, store.MigrationPageObjects)
	rows, e := q.QueryContext(ctx, query, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var logical, unit, resource, source, sha, proof, metadata string
		var size int64
		var seen int
		if e = rows.Scan(&logical, &unit, &resource, &source, &raw, &sha, &size, &proof, &metadata, &seen); e != nil {
			return nil, e
		}
		o, e := scanPlanObject(raw, sha)
		if e != nil {
			return nil, e
		}
		if o.ID != logical || migrationUnit(o) != unit || o.Resource != resource || o.ObjectID != source || o.Bytes != size || seen != 1 || !nodeHashPattern.MatchString(proof) || !nodeHashPattern.MatchString(metadata) {
			return nil, store.ErrMigrationState
		}
		out = append(out, store.MigrationPeerObject{Object: o, Proof: store.MigrationDiskProof{ID: o.ID, Version: o.Version, Bytes: o.Bytes, SHA256: proof}})
	}
	return out, rows.Err()
}

func (r *Repository) insertMigrationExecutionPage(ctx context.Context, q queryer, p store.MigrationPlan, page []store.MigrationPeerObject, now int64) error {
	if len(page) == 0 || len(page) > store.MigrationPageObjects {
		return store.ErrMigrationState
	}
	values := make([]string, 0, len(page))
	args := make([]any, 0, len(page)*11)
	type unit struct {
		object       store.MigrationObject
		count, bytes int64
	}
	units := map[string]unit{}
	for _, binding := range page {
		o := binding.Object
		key := migrationUnit(o)
		values = append(values, "(?,?,?,?,?,?,?,?,?,?,'pending',?)")
		args = append(args, p.ID, key, o.ID, o.Resource, o.ObjectID, o.ObjectID, o.Version, o.Path, o.Bytes, binding.Proof.SHA256, now)
		u := units[key]
		u.object = o
		u.count++
		u.bytes += o.Bytes
		units[key] = u
	}
	if _, e := q.ExecContext(ctx, "INSERT INTO migration_objects(task_id,unit_id,logical_id,resource_kind,source_object,target_object,source_version,physical_path,expected_bytes,source_sha256,state,updated_at) VALUES "+strings.Join(values, ","), args...); e != nil {
		return e
	}
	values = values[:0]
	args = args[:0]
	for key, u := range units {
		version, e := store.MigrationDigest(struct{ Catalog, Unit string }{p.Catalog.Version, key})
		if e != nil {
			return e
		}
		values = append(values, "(?,?,?,?,?,'pending',?,?)")
		args = append(args, p.ID, key, u.object.Resource, u.object.Parent, version, u.count, u.bytes)
	}
	suffix := " ON CONFLICT(task_id,unit_id) DO UPDATE SET object_count=object_count+excluded.object_count,total_bytes=total_bytes+excluded.total_bytes"
	if r.backend == "mysql" {
		suffix = " ON DUPLICATE KEY UPDATE object_count=object_count+VALUES(object_count),total_bytes=total_bytes+VALUES(total_bytes)"
	}
	_, e := q.ExecContext(ctx, "INSERT INTO migration_units(task_id,unit_id,resource_kind,parent_path,source_version,state,object_count,total_bytes) VALUES "+strings.Join(values, ",")+suffix, args...)
	return e
}

// The admitted unit root binds every sorted object and source proof. It is
// established in the same transaction as admission, before any executor lease
// exists; per-object cancellation can subsequently use this durable fact.
func (r *Repository) sealMigrationUnitRoster(ctx context.Context, q queryer, task string, u store.MigrationUnit) error {
	var sequence store.MigrationSequence
	var bytes int64
	after := ""
	for {
		page, e := r.migrationPlanUnitBindingPage(ctx, q, task, u.ID, after)
		if e != nil {
			return e
		}
		for _, binding := range page {
			if binding.Object.Resource != u.Resource || binding.Object.Parent != u.Parent {
				return store.ErrMigrationState
			}
			if e = sequence.Add(binding.Object.ID, binding); e != nil {
				return e
			}
			bytes += binding.Object.Bytes
			after = binding.Object.ID
		}
		if len(page) < store.MigrationPageObjects {
			break
		}
	}
	if sequence.Count() != u.ObjectCount || bytes != u.Bytes || u.ObjectCount == 0 {
		return store.ErrMigrationState
	}
	_, e := q.ExecContext(ctx, "UPDATE migration_units SET source_version=? WHERE task_id=? AND unit_id=?", sequence.Sum(), task, u.ID)
	return e
}
