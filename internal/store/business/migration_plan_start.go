package business

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (r *Repository) startPagedMigration(ctx context.Context, p store.MigrationPlan, a store.NodeAudit) (task store.MigrationTask, err error) {
	if p.Format != pagedMigrationFormat || !nodeIDPattern.MatchString(p.ID) || p.ObjectCount < 0 || p.UnitCount < 0 || len(p.Catalog.Objects) != 0 || len(p.Proofs) != 0 || p.Catalog.TotalBlockers() != 0 || !p.TargetAbsent || !nodeHashPattern.MatchString(p.ObjectsSHA) || !nodeHashPattern.MatchString(p.ProofsSHA) {
		return task, store.ErrMigrationState
	}
	digest, e := store.MigrationDigest(p)
	if e != nil {
		return task, e
	}
	raw, e := json.Marshal(p)
	if e != nil {
		return task, e
	}
	err = r.write(ctx, func(q queryer) error {
		n, e := readNode(ctx, q, r.lock())
		if e != nil {
			return e
		}
		if n.Role != "Master" || n.ID != p.Catalog.MasterID {
			return store.ErrMigrationState
		}
		old, e := scanMigrationTask(q.QueryRowContext(ctx, "SELECT "+migrationTaskColumns+" FROM migration_tasks WHERE task_id=?"+r.lock(), p.ID))
		if e == nil {
			if old.PlanSHA != digest {
				return store.ErrMigrationState
			}
			task = old
			return nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		var state, sha string
		var expires int64
		if e = q.QueryRowContext(ctx, "SELECT state,plan_sha256,expires_at FROM migration_plan_headers WHERE plan_id=?"+r.lock(), p.ID).Scan(&state, &sha, &expires); e != nil {
			return e
		}
		now := time.Now().Unix()
		if state != "ready" || sha != digest || expires != p.ExpiresAt || expires <= now || p.CreatedAt < now-300 || p.CreatedAt > now+30 || p.ExpiresAt != p.CreatedAt+300 {
			return store.ErrMigrationState
		}
		ids := []string{p.Catalog.Source.ID, p.Catalog.Target.ID}
		sort.Strings(ids)
		for _, id := range ids {
			if _, e = scanMember(q.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?"+r.lock(), id)); e != nil {
				return e
			}
		}
		current, objectsSHA, count, e := r.scanMigrationCatalog(ctx, q, p.Catalog.Source.ID, p.Catalog.Target.ID, nil)
		if e != nil {
			return e
		}
		if current.Version != p.Catalog.Version || objectsSHA != p.ObjectsSHA || count != p.ObjectCount || current.TotalBlockers() != 0 || current.TotalBytes != p.Catalog.TotalBytes || capacity(current.Target) < current.TotalBytes || p.TargetFree < store.PhysicalReserve || p.TargetFree-store.PhysicalReserve-current.Target.Reserved < current.TotalBytes {
			return store.ErrMigrationState
		}
		var scopes int
		if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_scopes WHERE member_id=?", current.Source.ID).Scan(&scopes); e != nil {
			return e
		}
		if scopes != 0 {
			return store.ErrMigrationState
		}
		if _, e = q.ExecContext(ctx, "INSERT INTO migration_tasks(task_id,master_id,source_id,target_id,source_relationship,target_relationship,plan_sha256,plan,state,object_count,total_bytes,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,'queued',?,?,?,?)", p.ID, n.ID, current.Source.ID, current.Target.ID, *current.Source.RelationshipID, *current.Target.RelationshipID, digest, string(raw), count, current.TotalBytes, now, now); e != nil {
			return e
		}
		var objectSequence, proofSequence store.MigrationSequence
		after := ""
		for {
			page, e := r.migrationPlanBindingPage(ctx, q, p.ID, after)
			if e != nil {
				return e
			}

			for _, binding := range page {
				if e = objectSequence.Add(binding.Object.ID, binding.Object); e != nil {
					return e
				}
				if e = proofSequence.Add(binding.Object.ID, binding.Proof); e != nil {
					return e
				}
			}
			if len(page) > 0 {
				if e = r.insertMigrationExecutionPage(ctx, q, p, page, now); e != nil {
					return e
				}
			}

			if len(page) < store.MigrationPageObjects {
				break
			}
			after = page[len(page)-1].Object.ID
		}
		if objectSequence.Count() != count || objectSequence.Sum() != p.ObjectsSHA || proofSequence.Sum() != p.ProofsSHA {
			return store.ErrMigrationState
		}
		// Unit locks are admitted only after the complete immutable roster was
		// checked, so later objects in this task do not conflict with themselves.
		after = ""
		var units int64
		for {
			page, e := r.migrationUnitPage(ctx, q, p.ID, after)
			if e != nil {
				return e
			}

			for _, u := range page {
				if e = r.sealMigrationUnitRoster(ctx, q, p.ID, u); e != nil {
					return e
				}
				if u.Resource == "media" {
					if e = r.checkMigrationScopes(ctx, q, u.Resource, []store.DeleteItem{{Path: u.Parent + "/.migration-unit-check"}}); e != nil {
						return e
					}
				} else {
					if e = r.checkMigrationRecording(ctx, q, current.Target.ID, u.Parent); e != nil {
						return e
					}
				}
				for _, member := range ids {
					if _, e = q.ExecContext(ctx, "INSERT INTO migration_scopes(scope_id,task_id,member_id,resource_kind,parent_path,created_at) VALUES (?,?,?,?,?,?)", locator(member+":"+u.Resource+":"+u.Parent), p.ID, member, u.Resource, u.Parent, now); e != nil {
						return e
					}
				}
				units++
			}
			if len(page) < store.MigrationPageObjects {
				break
			}
			after = page[len(page)-1].ID
		}
		if units != p.UnitCount {
			return store.ErrMigrationState
		}
		for _, s := range []struct {
			sql  string
			args []any
		}{
			{"INSERT INTO migration_capacity(task_id,member_id,reserved_bytes,updated_at) VALUES (?,?,?,?)", []any{p.ID, current.Target.ID, current.TotalBytes, now}},
			{"UPDATE cluster_storage_members SET reserved_bytes=reserved_bytes+?,updated_at=? WHERE member_id=?", []any{current.TotalBytes, now, current.Target.ID}},
			{"INSERT INTO migration_drains(member_id,owner_id,reason,created_at) VALUES (?,?,'migration',?)", []any{current.Source.ID, p.ID, now}},
			{"UPDATE migration_plan_headers SET state='admitted' WHERE plan_id=? AND state='ready'", []any{p.ID}},
		} {
			if _, e = q.ExecContext(ctx, s.sql, s.args...); e != nil {
				return e
			}
		}
		if e = r.nodeAudit(ctx, q, "resource-migration-started", *current.Source.RelationshipID, map[string]any{"task_id": p.ID, "source_id": current.Source.ID, "target_id": current.Target.ID, "objects": count, "bytes": current.TotalBytes, "plan_sha256": digest}, a); e != nil {
			return e
		}
		task = store.MigrationTask{ID: p.ID, MasterID: n.ID, SourceID: current.Source.ID, TargetID: current.Target.ID, PlanSHA: digest, State: "queued", Revision: 1, ObjectCount: count, TotalBytes: current.TotalBytes, CreatedAt: now, UpdatedAt: now}
		return nil
	})
	return
}
