package business

import (
	"context"
	"encoding/json"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"io"
	"math"
	"strings"
)

func retirementPlanQueries(member string) []retirementQuery {
	next := "reconcile_terminal_task_unit_and_object_rosters"
	return []retirementQuery{
		{"migration_plan_header_orphans", "migration_plan_headers h LEFT JOIN migration_tasks t ON t.task_id=h.plan_id WHERE (h.source_id=? OR h.target_id=?) AND ((h.state='admitted' AND t.task_id IS NULL) OR (h.state<>'admitted' AND t.task_id IS NOT NULL))", "h.plan_id", next, []any{member, member}},
		{"migration_plan_binding_orphans", "migration_plan_bindings b LEFT JOIN migration_plan_headers h ON h.plan_id=b.plan_id WHERE h.plan_id IS NULL", "b.plan_id", next, nil},
		{"migration_plan_path_orphans", "migration_plan_paths p LEFT JOIN migration_plan_headers h ON h.plan_id=p.plan_id WHERE h.plan_id IS NULL", "p.plan_id", next, nil},
	}
}

// Preview caches have no migration authority and may remain after expiry. Only
// admitted manifests must reconcile with durable tasks. Page cursors and bounded
// SQL projections keep arbitrarily large history out of application memory.
func (r *Repository) retirementPlanHistory(ctx context.Context, q queryer, master, member string) ([]store.RetirementBlocker, error) {
	block := store.RetirementBlocker{Code: "migration_plan_history_mismatch", SampleIDs: []string{}, NextStep: "reconcile_terminal_task_unit_and_object_rosters"}
	after := ""
	for {
		rows, e := q.QueryContext(ctx, "SELECT task_id FROM migration_tasks WHERE (source_id=? OR target_id=?) AND task_id>? ORDER BY task_id LIMIT 64", member, member, after)
		if e != nil {
			return nil, e
		}
		var ids []string
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				rows.Close()
				return nil, e
			}
			ids = append(ids, id)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, e
		}
		for _, id := range ids {
			if id <= after || !nodeIDPattern.MatchString(id) {
				return nil, store.ErrNodeState
			}
			after = id
			var raw []byte
			if e = q.QueryRowContext(ctx, "SELECT SUBSTR(plan,1,?) FROM migration_tasks WHERE task_id=?", store.MaxMigrationPlanBytes+1, id).Scan(&raw); e != nil {
				return nil, e
			}
			var marker struct {
				Format string `json:"format"`
			}
			e = json.Unmarshal(raw, &marker)
			if e == nil && marker.Format == "" {
				continue
			} // Legacy generation-six manifests have no paging header.
			if e == nil {
				e = r.retirementPagedPlan(ctx, q, master, id)
			}
			if e != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				block.Count++
				if len(block.SampleIDs) < 8 {
					block.SampleIDs = append(block.SampleIDs, id)
				}
			}
		}
		if len(ids) < 64 {
			break
		}
	}
	if block.Count == 0 {
		return nil, nil
	}
	return []store.RetirementBlocker{block}, nil
}

func (r *Repository) retirementPagedPlan(ctx context.Context, q queryer, master, id string) error {
	work, e := r.migrationHeader(ctx, q, id)
	if e != nil {
		return e
	}
	p := work.Plan
	if p.Format != pagedMigrationFormat || work.Task.MasterID != master || p.Catalog.MasterID != master || p.Catalog.Source.ID != work.Task.SourceID || p.Catalog.Target.ID != work.Task.TargetID || p.Catalog.TotalBytes != work.Task.TotalBytes {
		return store.ErrMigrationState
	}
	var raw []byte
	var headerMaster, source, target, state string
	if e = q.QueryRowContext(ctx, "SELECT SUBSTR(header_json,1,?),master_id,source_id,target_id,state FROM migration_plan_headers WHERE plan_id=?", store.MaxMigrationPlanBytes+1, id).Scan(&raw, &headerMaster, &source, &target, &state); e != nil {
		return e
	}
	var saved store.MigrationPlan
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if len(raw) > store.MaxMigrationPlanBytes || d.Decode(&saved) != nil || d.Decode(new(any)) != io.EOF {
		return store.ErrMigrationState
	}
	digest, e := store.MigrationDigest(saved)
	if e != nil || digest != work.Task.PlanSHA || headerMaster != master || source != work.Task.SourceID || target != work.Task.TargetID || state != "admitted" {
		return store.ErrMigrationState
	}
	var objects, proofs store.MigrationSequence
	var bytes int64
	after := ""
	for {
		rows, e := q.QueryContext(ctx, "SELECT logical_id,unit_id,resource_kind,source_object,object_sha256,SUBSTR(object_json,1,65537),expected_bytes,source_sha256,native_metadata_sha256,native_seen FROM migration_plan_bindings WHERE plan_id=? AND logical_id>? ORDER BY logical_id LIMIT 64", id, after)
		if e != nil {
			return e
		}
		count := 0
		for rows.Next() {
			var logical, unit, kind, sourceObject, sha, proof, metadata string
			var raw []byte
			var expected int64
			var seen int
			if e = rows.Scan(&logical, &unit, &kind, &sourceObject, &sha, &raw, &expected, &proof, &metadata, &seen); e != nil {
				rows.Close()
				return e
			}
			o, e := scanPlanObject(raw, sha)
			if e != nil || !json.Valid(raw) || logical <= after || logical != o.ID || unit != migrationUnit(o) || kind != o.Resource || sourceObject != o.ObjectID || expected != o.Bytes || seen != 1 || !nodeHashPattern.MatchString(proof) || !nodeHashPattern.MatchString(metadata) || o.Bytes < 0 || bytes > math.MaxInt64-o.Bytes {
				rows.Close()
				return store.ErrMigrationState
			}
			if e = objects.Add(o.ID, o); e == nil {
				e = proofs.Add(o.ID, store.MigrationDiskProof{ID: o.ID, Version: o.Version, Bytes: o.Bytes, SHA256: proof})
			}
			if e != nil {
				rows.Close()
				return e
			}
			bytes += o.Bytes
			after = logical
			count++
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		if count < 64 {
			break
		}
	}
	if objects.Count() != p.ObjectCount || objects.Sum() != p.ObjectsSHA || proofs.Sum() != p.ProofsSHA || bytes != work.Task.TotalBytes {
		return store.ErrMigrationState
	}
	var units, taskObjects int64
	if e = q.QueryRowContext(ctx, "SELECT COUNT(DISTINCT unit_id) FROM migration_plan_bindings WHERE plan_id=?", id).Scan(&units); e != nil {
		return e
	}
	if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_objects WHERE task_id=?", id).Scan(&taskObjects); e != nil {
		return e
	}
	if units != p.UnitCount || taskObjects != p.ObjectCount {
		return store.ErrMigrationState
	}
	var checked int64
	for cp, e := range r.migrationObjects(ctx, q, id, "") {
		if e != nil {
			return e
		}
		if work.Task.State == "completed" && cp.State != "cleaned" || work.Task.State == "cancelled" && cp.State != "cleaned" && cp.State != "cancelled" {
			return store.ErrMigrationState
		}
		checked++
	}
	if checked != p.ObjectCount {
		return store.ErrMigrationState
	}
	var badUnits, taskUnits int64
	if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_units WHERE task_id=?", id).Scan(&taskUnits); e != nil {
		return e
	}
	if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_units u WHERE u.task_id=? AND (u.object_count<>(SELECT COUNT(*) FROM migration_plan_bindings b WHERE b.plan_id=u.task_id AND b.unit_id=u.unit_id) OR u.total_bytes<>(SELECT COALESCE(SUM(b.expected_bytes),0) FROM migration_plan_bindings b WHERE b.plan_id=u.task_id AND b.unit_id=u.unit_id))", id).Scan(&badUnits); e != nil {
		return e
	}
	if taskUnits != p.UnitCount || badUnits != 0 {
		return store.ErrMigrationState
	}
	return nil
}
