package business

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const pagedMigrationFormat = "frontiercloud-paged-migration-v1"

func (r *Repository) BuildMigrationPlan(ctx context.Context, id, source, target string) (p store.MigrationPlan, err error) {
	if !nodeIDPattern.MatchString(id) || !nodeIDPattern.MatchString(source) || !nodeIDPattern.MatchString(target) || source == target {
		return p, store.ErrMigrationState
	}
	c, e := r.migrationCatalogHeader(ctx, r.db, source, target)
	if e != nil {
		return p, e
	}
	p = store.MigrationPlan{ID: id, Format: pagedMigrationFormat, Catalog: c, CreatedAt: time.Now().Unix(), ExpiresAt: time.Now().Unix() + 1800}
	raw, e := json.Marshal(p)
	if e != nil {
		return p, e
	}
	e = r.write(ctx, func(q queryer) error {
		var state string
		e := q.QueryRowContext(ctx, "SELECT state FROM migration_plan_headers WHERE plan_id=?"+r.lock(), id).Scan(&state)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if state == "admitted" {
			return store.ErrMigrationState
		}
		// Only ephemeral observations are replaceable. Admitted bindings are
		// permanent task facts and are never swept by preview expiration.
		for _, table := range []string{"migration_plan_bindings", "migration_plan_paths"} {
			if _, e = q.ExecContext(ctx, "DELETE FROM "+table+" WHERE plan_id IN (SELECT plan_id FROM migration_plan_headers WHERE state<>'admitted' AND (plan_id=? OR expires_at<?))", id, time.Now().Unix()); e != nil {
				return e
			}
		}
		if _, e = q.ExecContext(ctx, "DELETE FROM migration_plan_headers WHERE state<>'admitted' AND (plan_id=? OR expires_at<?)", id, time.Now().Unix()); e != nil {
			return e
		}
		_, e = q.ExecContext(ctx, "INSERT INTO migration_plan_headers(plan_id,master_id,source_id,target_id,state,header_json,created_at,expires_at) VALUES (?,?,?,?,'observing',?,?,?)", id, c.MasterID, source, target, string(raw), p.CreatedAt, p.ExpiresAt)
		return e
	})
	if e != nil {
		return p, e
	}
	c, objectsSHA, count, e := r.scanMigrationCatalog(ctx, r.db, source, target, func(page []store.MigrationObject) error {
		return r.write(ctx, func(q queryer) error {
			var state string
			if e := q.QueryRowContext(ctx, "SELECT state FROM migration_plan_headers WHERE plan_id=?"+r.lock(), id).Scan(&state); e != nil {
				return e
			}
			if state != "observing" {
				return store.ErrMigrationState
			}
			for _, o := range page {
				raw, e := json.Marshal(o)
				if e != nil {
					return e
				}
				sha, e := store.MigrationDigest(o)
				if e != nil {
					return e
				}
				if _, e = q.ExecContext(ctx, "INSERT INTO migration_plan_bindings(plan_id,logical_id,unit_id,resource_kind,source_object,object_sha256,object_json,expected_bytes) VALUES (?,?,?,?,?,?,?,?)", id, o.ID, migrationUnit(o), o.Resource, o.ObjectID, sha, string(raw), o.Bytes); e != nil {
					return e
				}
				paths := map[string][]string{o.TargetPath: {"name"}, path.Dir(o.TargetPath): {"parent"}}
				for ancestor := path.Dir(o.TargetPath); ancestor != "." && ancestor != "/"; ancestor = path.Dir(ancestor) {
					paths[ancestor] = append(paths[ancestor], "ancestor")
				}
				for name, kinds := range paths {
					for _, kind := range kinds {
						statement := "INSERT OR IGNORE INTO migration_plan_paths(plan_id,resource_kind,path_locator,entry_kind) VALUES (?,?,?,?)"
						if r.backend == "mysql" {
							statement = "INSERT IGNORE INTO migration_plan_paths(plan_id,resource_kind,path_locator,entry_kind) VALUES (?,?,?,?)"
						}
						if _, e = q.ExecContext(ctx, statement, id, o.Resource, locator(name), kind); e != nil {
							return e
						}
					}
				}
			}
			return nil
		})
	})
	if e != nil {
		return p, e
	}
	p.Catalog = c
	p.ObjectCount = count
	p.ObjectsSHA = objectsSHA
	if e = r.db.QueryRowContext(ctx, "SELECT COUNT(DISTINCT unit_id) FROM migration_plan_bindings WHERE plan_id=?", id).Scan(&p.UnitCount); e != nil {
		return p, e
	}
	raw, e = json.Marshal(p)
	if e != nil {
		return p, e
	}
	e = r.write(ctx, func(q queryer) error {
		_, e := q.ExecContext(ctx, "UPDATE migration_plan_headers SET header_json=?,object_count=?,unit_count=?,total_bytes=?,catalog_sha256=? WHERE plan_id=? AND state='observing'", string(raw), count, p.UnitCount, c.TotalBytes, c.Version, id)
		return e
	})
	return p, e
}

func scanPlanObject(raw []byte, sha string) (o store.MigrationObject, e error) {
	if len(raw) > 64<<10 {
		return o, store.ErrMigrationState
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(&o); e != nil {
		return o, e
	}
	digest, e := store.MigrationDigest(o)
	if e != nil || digest != sha {
		return o, store.ErrMigrationState
	}
	return o, nil
}
func (r *Repository) MigrationPlanPage(ctx context.Context, id, after string) ([]store.MigrationObject, error) {
	if !nodeIDPattern.MatchString(id) || after != "" && !nodeIDPattern.MatchString(after) && !nodeHashPattern.MatchString(after) {
		return nil, store.ErrMigrationState
	}
	return r.migrationPlanPage(ctx, r.db, id, after)
}
func (r *Repository) migrationPlanPage(ctx context.Context, q queryer, id, after string) (objects []store.MigrationObject, err error) {
	rows, e := q.QueryContext(ctx, "SELECT object_json,object_sha256 FROM migration_plan_bindings WHERE plan_id=? AND logical_id>? ORDER BY logical_id LIMIT ?", id, after, store.MigrationPageObjects)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var sha string
		if e = rows.Scan(&raw, &sha); e != nil {
			return nil, e
		}
		o, e := scanPlanObject(raw, sha)
		if e != nil {
			return nil, e
		}
		objects = append(objects, o)
	}
	return objects, rows.Err()
}
func (r *Repository) ObserveMigrationPlanNative(ctx context.Context, id, resource string, item store.ExpectedPhysicalItem) error {
	if resource != "media" && resource != "recording" {
		return store.ErrMigrationState
	}
	return r.write(ctx, func(q queryer) error {
		var raw []byte
		var sha, state, source string
		var seen int
		if e := q.QueryRowContext(ctx, "SELECT b.object_json,b.object_sha256,b.native_seen,h.state,h.source_id FROM migration_plan_bindings b JOIN migration_plan_headers h ON h.plan_id=b.plan_id WHERE b.plan_id=? AND b.resource_kind=? AND b.source_object=?"+r.lock(), id, resource, item.ObjectID).Scan(&raw, &sha, &seen, &state, &source); e != nil {
			return e
		}
		o, e := scanPlanObject(raw, sha)
		if e != nil {
			return e
		}
		scope := "media"
		if o.Resource == "recording" {
			scope = "recordings"
		}
		if state != "observing" || seen != 0 || item.Path != scope+"/"+o.Path || !nodeHashPattern.MatchString(item.MetadataSHA256) || item.ExpectedBytes != nil && *item.ExpectedBytes != o.Bytes {
			return store.ErrMigrationState
		}
		digest, e := store.MigrationNativeMetadataSHA(o, source)
		if e != nil || digest != item.MetadataSHA256 {
			return store.ErrMigrationState
		}
		_, e = q.ExecContext(ctx, "UPDATE migration_plan_bindings SET native_seen=1,native_metadata_sha256=? WHERE plan_id=? AND logical_id=?", item.MetadataSHA256, id, o.ID)
		return e
	})
}
func (r *Repository) MigrationPlanNative(ctx context.Context, id, logical string) (item store.ExpectedPhysicalItem, e error) {
	var raw []byte
	var sha string
	var seen int
	if e = r.db.QueryRowContext(ctx, "SELECT object_json,object_sha256,native_seen,native_metadata_sha256 FROM migration_plan_bindings WHERE plan_id=? AND logical_id=?", id, logical).Scan(&raw, &sha, &seen, &item.MetadataSHA256); e != nil {
		return item, e
	}
	o, e := scanPlanObject(raw, sha)
	if e != nil || seen != 1 {
		return item, store.ErrMigrationState
	}
	scope := "media"
	if o.Resource == "recording" {
		scope = "recordings"
	}
	item.ObjectID = o.ObjectID
	item.Path = scope + "/" + o.Path
	item.ExpectedBytes = &o.Bytes
	return item, nil
}
func (r *Repository) ObserveMigrationPlanProof(ctx context.Context, id string, proof store.MigrationDiskProof) error {
	if !nodeHashPattern.MatchString(proof.SHA256) {
		return store.ErrMigrationState
	}
	return r.write(ctx, func(q queryer) error {
		var raw []byte
		var sha, state string
		var seen int
		if e := q.QueryRowContext(ctx, "SELECT b.object_json,b.object_sha256,b.native_seen,h.state FROM migration_plan_bindings b JOIN migration_plan_headers h ON h.plan_id=b.plan_id WHERE b.plan_id=? AND b.logical_id=?"+r.lock(), id, proof.ID).Scan(&raw, &sha, &seen, &state); e != nil {
			return e
		}
		o, e := scanPlanObject(raw, sha)
		if e != nil {
			return e
		}
		if seen != 1 || state != "observing" || proof.Version != o.Version || proof.Bytes != o.Bytes {
			return store.ErrMigrationState
		}
		_, e = q.ExecContext(ctx, "UPDATE migration_plan_bindings SET source_sha256=? WHERE plan_id=? AND logical_id=?", proof.SHA256, id, proof.ID)
		return e
	})
}
func (r *Repository) MigrationPlanPathConflict(ctx context.Context, id, resource, name string, directory bool) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM migration_plan_paths WHERE plan_id=? AND resource_kind=? AND path_locator=? AND entry_kind='name'"
	args := []any{id, resource, locator(name)}
	if !directory {
		query = "SELECT COUNT(*) FROM migration_plan_paths WHERE plan_id=? AND resource_kind=? AND ((path_locator=? AND entry_kind IN ('name','ancestor')) OR (path_locator=? AND entry_kind='parent'))"
		args = append(args, locator(path.Dir(name)))
	}
	e := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count > 0, e
}

func (r *Repository) SealMigrationPlan(ctx context.Context, p store.MigrationPlan) (store.MigrationPlan, error) {
	c, objectsSHA, count, e := r.scanMigrationCatalog(ctx, r.db, p.Catalog.Source.ID, p.Catalog.Target.ID, nil)
	if e != nil {
		return p, e
	}
	if c.Version != p.Catalog.Version || count != p.ObjectCount || objectsSHA != p.ObjectsSHA {
		return p, store.ErrMigrationState
	}
	var proofs store.MigrationSequence
	after := ""
	for {
		page, e := r.migrationPlanBindingPage(ctx, r.db, p.ID, after)
		if e != nil {
			return p, e
		}
		for _, binding := range page {
			if e = proofs.Add(binding.Object.ID, binding.Proof); e != nil {
				return p, e
			}
		}
		if len(page) < store.MigrationPageObjects {
			break
		}
		after = page[len(page)-1].Object.ID
	}
	if proofs.Count() != p.ObjectCount {
		return p, store.ErrMigrationState
	}
	p.ProofsSHA = proofs.Sum()
	c.MergeBlockers(p.Catalog)
	p.Catalog = c
	p.CreatedAt = time.Now().Unix()
	p.ExpiresAt = p.CreatedAt + 300
	sha, e := store.MigrationDigest(p)
	if e != nil {
		return p, e
	}
	raw, e := json.Marshal(p)
	if e != nil {
		return p, e
	}
	state := "ready"
	if c.TotalBlockers() > 0 || !p.TargetAbsent {
		state = "blocked"
	}
	e = r.write(ctx, func(q queryer) error {
		result, e := q.ExecContext(ctx, "UPDATE migration_plan_headers SET state=?,header_json=?,proofs_sha256=?,plan_sha256=?,created_at=?,expires_at=? WHERE plan_id=? AND state='observing'", state, string(raw), p.ProofsSHA, sha, p.CreatedAt, p.ExpiresAt, p.ID)
		if e != nil {
			return e
		}
		n, e := result.RowsAffected()
		if e != nil || n != 1 {
			return store.ErrMigrationState
		}
		return nil
	})
	return p, e
}
