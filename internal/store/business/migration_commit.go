package business

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"sort"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (r *Repository) migrationWork(ctx context.Context, q queryer, id string) (w store.MigrationWork, e error) {
	w.Task, e = scanMigrationTask(q.QueryRowContext(ctx, "SELECT "+migrationTaskColumns+" FROM migration_tasks WHERE task_id=?", id))
	if e != nil {
		return w, e
	}
	var raw []byte
	if e = q.QueryRowContext(ctx, "SELECT plan FROM migration_tasks WHERE task_id=?", id).Scan(&raw); e != nil {
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
	digest, e := store.MigrationDigest(w.Plan)
	if e != nil || digest != w.Task.PlanSHA || w.Plan.ID != id {
		return w, store.ErrMigrationState
	}
	byID := map[string]store.MigrationObject{}
	for _, o := range w.Plan.Catalog.Objects {
		byID[o.ID] = o
	}
	proofs := map[string]store.MigrationDiskProof{}
	for _, proof := range w.Plan.Proofs {
		proofs[proof.ID] = proof
	}
	w.Units = []store.MigrationUnit{}
	w.Objects = []store.MigrationCheckpoint{}
	rows, e := q.QueryContext(ctx, "SELECT unit_id,resource_kind,parent_path,state,object_count,total_bytes,committed_at,cleanup_after FROM migration_units WHERE task_id=? ORDER BY unit_id", id)
	if e != nil {
		return w, e
	}
	for rows.Next() {
		var u store.MigrationUnit
		if e = rows.Scan(&u.ID, &u.Resource, &u.Parent, &u.State, &u.ObjectCount, &u.Bytes, &u.CommittedAt, &u.CleanupAfter); e != nil {
			rows.Close()
			return w, e
		}
		w.Units = append(w.Units, u)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return w, e
	}
	rows, e = q.QueryContext(ctx, "SELECT logical_id,unit_id,state,source_sha256,target_sha256,verified_bytes,source_version,expected_bytes,physical_path,source_object,target_object,resource_kind FROM migration_objects WHERE task_id=? ORDER BY logical_id", id)
	if e != nil {
		return w, e
	}
	for rows.Next() {
		var c store.MigrationCheckpoint
		var logical string
		var version, physical, sourceObject, targetObject, kind string
		var expected int64
		if e = rows.Scan(&logical, &c.UnitID, &c.State, &c.SourceSHA, &c.TargetSHA, &c.VerifiedBytes, &version, &expected, &physical, &sourceObject, &targetObject, &kind); e != nil {
			rows.Close()
			return w, e
		}
		o, ok := byID[logical]
		proof, proven := proofs[logical]
		if !ok || !proven || migrationUnit(o) != c.UnitID || version != o.Version || expected != o.Bytes || physical != o.Path || sourceObject != o.ObjectID || targetObject != o.ObjectID || kind != o.Resource || proof.SHA256 != c.SourceSHA || proof.Version != o.Version || proof.Bytes != o.Bytes {
			rows.Close()
			return w, store.ErrMigrationState
		}
		c.Object = o
		w.Objects = append(w.Objects, c)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return w, e
	}
	if len(w.Objects) != len(byID) || int64(len(w.Objects)) != w.Task.ObjectCount {
		return w, store.ErrMigrationState
	}
	return w, nil
}
func (r *Repository) MigrationWork(ctx context.Context, id string) (store.MigrationWork, error) {
	if !nodeIDPattern.MatchString(id) {
		return store.MigrationWork{}, store.ErrMigrationState
	}
	level := sql.LevelSerializable
	if r.backend == "mysql" {
		level = sql.LevelRepeatableRead
	}
	tx, e := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: level, ReadOnly: true})
	if e != nil {
		return store.MigrationWork{}, e
	}
	defer tx.Rollback()
	n, e := readNode(ctx, tx, "")
	if e != nil || n.Role != "Master" {
		return store.MigrationWork{}, store.ErrMigrationState
	}
	w, e := r.migrationWork(ctx, tx, id)
	if e != nil {
		return w, e
	}
	if w.Task.MasterID != n.ID {
		return w, store.ErrMigrationState
	}
	return w, tx.Commit()
}
func (r *Repository) VerifyMigrationObject(ctx context.Context, l store.MigrationLease, id string, bytes int64, sha string) error {
	if !nodeHashPattern.MatchString(sha) {
		return store.ErrMigrationState
	}
	return r.write(ctx, func(q queryer) error {
		t, e := r.checkMigrationLease(ctx, q, l)
		if e != nil {
			return e
		}
		if !migrationRunnable(t.State) {
			return store.ErrMigrationState
		}
		var expected, verified int64
		var source, target, state string
		if e = q.QueryRowContext(ctx, "SELECT expected_bytes,verified_bytes,source_sha256,target_sha256,state FROM migration_objects WHERE task_id=? AND logical_id=?"+r.lock(), l.TaskID, id).Scan(&expected, &verified, &source, &target, &state); e != nil {
			return e
		}
		if bytes != expected || sha != source {
			return store.ErrMigrationState
		}
		if state != "pending" && state != "copying" {
			if verified == bytes && target == sha && (state == "verified" || state == "publishing" || state == "published" || state == "cleanup_pending" || state == "cleaned") {
				return nil
			}
			return store.ErrMigrationState
		}
		_, e = q.ExecContext(ctx, "UPDATE migration_objects SET state='verified',verified_bytes=?,target_sha256=?,updated_at=? WHERE task_id=? AND logical_id=?", bytes, sha, time.Now().Unix(), l.TaskID, id)
		return e
	})
}
func (r *Repository) PrepareMigrationPublication(ctx context.Context, l store.MigrationLease, unit string) error {
	return r.write(ctx, func(q queryer) error {
		t, e := r.checkMigrationLease(ctx, q, l)
		if e != nil {
			return e
		}
		if !migrationRunnable(t.State) {
			return store.ErrMigrationState
		}
		var state string
		if e = q.QueryRowContext(ctx, "SELECT state FROM migration_units WHERE task_id=? AND unit_id=?"+r.lock(), l.TaskID, unit).Scan(&state); e != nil {
			return e
		}
		if state == "publishing" || state == "committed" || state == "cleanup_pending" || state == "cleaned" {
			return nil
		}
		if state != "pending" && state != "copying" && state != "verified" {
			return store.ErrMigrationState
		}
		var count int
		if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_objects WHERE task_id=? AND unit_id=? AND (state<>'verified' OR target_sha256<>source_sha256 OR verified_bytes<>expected_bytes)", l.TaskID, unit).Scan(&count); e != nil {
			return e
		}
		if count != 0 {
			return store.ErrMigrationState
		}
		if _, e = q.ExecContext(ctx, "UPDATE migration_units SET state='publishing' WHERE task_id=? AND unit_id=?", l.TaskID, unit); e != nil {
			return e
		}
		_, e = q.ExecContext(ctx, "UPDATE migration_objects SET state='publishing',updated_at=? WHERE task_id=? AND unit_id=?", time.Now().Unix(), l.TaskID, unit)
		return e
	})
}

// Called only after the service authenticates the target's durable publication
// receipt. A published physical copy still has no Master business authority.
func (r *Repository) PublishMigrationObject(ctx context.Context, l store.MigrationLease, id string) error {
	return r.write(ctx, func(q queryer) error {
		t, e := r.checkMigrationLease(ctx, q, l)
		if e != nil {
			return e
		}
		if !migrationRunnable(t.State) {
			return store.ErrMigrationState
		}
		var state, source, target string
		var bytes, expected int64
		if e = q.QueryRowContext(ctx, "SELECT state,source_sha256,target_sha256,verified_bytes,expected_bytes FROM migration_objects WHERE task_id=? AND logical_id=?"+r.lock(), l.TaskID, id).Scan(&state, &source, &target, &bytes, &expected); e != nil {
			return e
		}
		if source != target || bytes != expected || !nodeHashPattern.MatchString(target) {
			return store.ErrMigrationState
		}
		if state == "published" || state == "cleanup_pending" || state == "cleaned" {
			return nil
		}
		if state != "publishing" {
			return store.ErrMigrationState
		}
		_, e = q.ExecContext(ctx, "UPDATE migration_objects SET state='published',updated_at=? WHERE task_id=? AND logical_id=?", time.Now().Unix(), l.TaskID, id)
		return e
	})
}

// Only this short transaction changes authoritative ownership. Network/file
// publication happens before it; source cleanup is separately journaled later.
func (r *Repository) CommitMigrationUnit(ctx context.Context, l store.MigrationLease, unit string, a store.NodeAudit) error {
	return r.write(ctx, func(q queryer) error {
		t, e := r.checkMigrationLease(ctx, q, l)
		if e != nil {
			return e
		}
		if !migrationRunnable(t.State) {
			return store.ErrMigrationState
		}
		w, e := r.migrationWork(ctx, q, l.TaskID)
		if e != nil {
			return e
		}
		var selected *store.MigrationUnit
		for i := range w.Units {
			if w.Units[i].ID == unit {
				selected = &w.Units[i]
			}
		}
		if selected == nil {
			return store.ErrMigrationState
		}
		if selected.State == "committed" || selected.State == "cleanup_pending" || selected.State == "cleaned" {
			return nil
		}
		if selected.State != "publishing" {
			return store.ErrMigrationState
		}
		ids := []string{t.SourceID, t.TargetID}
		sort.Strings(ids)
		members := map[string]store.StorageMember{}
		for _, id := range ids {
			m, e := scanMember(q.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?"+r.lock(), id))
			if e != nil {
				return e
			}
			if m.RelationshipID == nil {
				return store.ErrMigrationState
			}
			members[id] = m
			rel, e := scanRelation(q.QueryRowContext(ctx, "SELECT "+relationColumns+" FROM node_relationships WHERE relationship_id=?"+r.lock(), *m.RelationshipID))
			if e != nil {
				return e
			}
			binding, e := migrationBinding(rel)
			if e != nil {
				return e
			}
			expected := w.Plan.Catalog.SourceBinding
			if id == t.TargetID {
				expected = w.Plan.Catalog.TargetBinding
			}
			if binding != expected || rel.Status != "online" || time.Now().Unix()-rel.LastHeartbeat >= 120 {
				return store.ErrMigrationState
			}
		}
		count := int64(0)
		expectedObjects := map[string]store.MigrationObject{}
		bytes := int64(0)
		for _, c := range w.Objects {
			if c.UnitID != unit {
				continue
			}
			if c.Object.Resource != selected.Resource || c.Object.Parent != selected.Parent {
				return store.ErrMigrationState
			}
			if c.State != "published" || c.SourceSHA != c.TargetSHA || c.VerifiedBytes != c.Object.Bytes {
				return store.ErrMigrationState
			}
			expectedObjects[c.Object.ID] = c.Object
			count++
			bytes += c.Object.Bytes
		}
		if count != selected.ObjectCount || bytes != selected.Bytes || count == 0 {
			return store.ErrMigrationState
		}
		// One bounded row stream rechecks versions and the entire parent unit;
		// avoid one database round trip per object while holding writer locks.
		if selected.Resource == "media" {
			where, args := r.pathScope("g.media_path", selected.Parent, true)
			where += " AND LENGTH(g.media_path)-LENGTH(REPLACE(g.media_path,'/',''))=?"
			args = append(args, strings.Count(selected.Parent, "/")+1)
			rows, e := q.QueryContext(ctx, "SELECT g.media_id,g.object_id,g.media_path,g.object_kind,g.etag,g.state,g.size_bytes,g.updated_at,g.storage_member_id,e.descriptor_json FROM global_media_objects g LEFT JOIN media_encryption e ON e.object_kind='media' AND e.object_id=g.media_id WHERE "+where+" ORDER BY g.media_id"+r.lock(), args...)
			if e != nil {
				return e
			}
			actual := int64(0)
			for rows.Next() {
				var id, object, name, kind, etag, state, owner string
				var size, updated int64
				var raw sql.NullString
				if e = rows.Scan(&id, &object, &name, &kind, &etag, &state, &size, &updated, &owner, &raw); e != nil {
					rows.Close()
					return e
				}
				var encryption *mediacrypto.Metadata
				if raw.Valid {
					var value mediacrypto.Metadata
					if json.Unmarshal([]byte(raw.String), &value) != nil || value.Validate() != nil {
						rows.Close()
						return store.ErrMigrationState
					}
					encryption = &value
				}
				version, e := store.MigrationDigest(struct {
					ID, Object, Path, Kind, ETag, State string
					Bytes, Updated                      int64
				}{id, object, name, kind, etag, state, size, updated})
				if e != nil {
					rows.Close()
					return e
				}
				version, e = store.MigrationDigest(struct {
					Version    string
					Encryption any
				}{version, encryption})
				if e != nil {
					rows.Close()
					return e
				}
				expected, ok := expectedObjects[id]
				if !ok || owner != t.SourceID || version != expected.Version {
					rows.Close()
					return store.ErrMigrationState
				}
				actual++
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return e
			}
			if actual != count {
				return store.ErrMigrationState
			}
		} else {
			rows, e := q.QueryContext(ctx, "SELECT "+recordingColumns+" FROM karaoke_recordings WHERE user_id=? AND storage_member_id=? AND state<>'deleted' ORDER BY recording_id"+r.lock(), selected.Parent, t.SourceID)
			if e != nil {
				return e
			}
			actual := int64(0)
			for rows.Next() {
				v, e := scanRecording(rows)
				if e != nil {
					rows.Close()
					return e
				}
				metadata, e := store.EncodeRecordingReservation(v)
				if e != nil {
					rows.Close()
					return e
				}
				version, e := store.MigrationDigest(struct {
					ID, User, Owner, Filename, Type string
					Bytes, Updated                  int64
					SHA                             *string
					Metadata                        json.RawMessage
				}{v.ID, v.UserID, v.MemberID, v.Filename, v.ContentType, v.Bytes, v.UpdatedAt, v.SHA256, json.RawMessage(metadata)})
				if e != nil {
					rows.Close()
					return e
				}
				expected, ok := expectedObjects[v.ID]
				if !ok || v.State != "ready" || version != expected.Version {
					rows.Close()
					return store.ErrMigrationState
				}
				actual++
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return e
			}
			if actual != count {
				return store.ErrMigrationState
			}
		}
		source, target := members[t.SourceID], members[t.TargetID]
		var reserved int64
		if e = q.QueryRowContext(ctx, "SELECT reserved_bytes FROM migration_capacity WHERE task_id=?"+r.lock(), l.TaskID).Scan(&reserved); e != nil {
			return e
		}
		if source.Used < bytes || target.Reserved < bytes || reserved < bytes || target.Used > target.Allocation-target.Reserved || target.Enabled == 0 || target.Writable == 0 || target.Health != "online" {
			return store.ErrMigrationState
		}
		now := time.Now().Unix()
		// Validation of a large unit may consume the lease interval. Recheck
		// the persistent epoch/expiry before the authority-changing statement.
		if _, e = r.checkMigrationLease(ctx, q, l); e != nil {
			return e
		}
		objectIDs := make([]string, 0, len(expectedObjects))
		for id := range expectedObjects {
			objectIDs = append(objectIDs, id)
		}
		sort.Strings(objectIDs)
		args := []any{t.TargetID, now, t.SourceID}
		placeholders := make([]string, len(objectIDs))
		for i, id := range objectIDs {
			placeholders[i] = "?"
			args = append(args, id)
		}
		table, key := "global_media_objects", "media_id"
		if selected.Resource == "recording" {
			table, key = "karaoke_recordings", "recording_id"
		}
		result, e := q.ExecContext(ctx, "UPDATE "+table+" SET storage_member_id=?,updated_at=? WHERE storage_member_id=? AND "+key+" IN ("+strings.Join(placeholders, ",")+")", args...)
		if e != nil {
			return e
		}
		changed, e := result.RowsAffected()
		if e != nil || changed != count {
			return store.ErrMigrationState
		}
		for _, change := range []struct {
			query string
			args  []any
		}{
			{"UPDATE cluster_storage_members SET used_bytes=used_bytes-?,updated_at=? WHERE member_id=?", []any{bytes, now, t.SourceID}},
			{"UPDATE cluster_storage_members SET used_bytes=used_bytes+?,reserved_bytes=reserved_bytes-?,updated_at=? WHERE member_id=?", []any{bytes, bytes, now, t.TargetID}},
			{"UPDATE migration_capacity SET reserved_bytes=reserved_bytes-?,updated_at=? WHERE task_id=?", []any{bytes, now, l.TaskID}},
			{"UPDATE migration_objects SET state='cleanup_pending',updated_at=? WHERE task_id=? AND unit_id=?", []any{now, l.TaskID, unit}},
			// The grace timestamp is a minimum delay, never proof that active
			// read leases or old capabilities have drained. Cleanup rechecks them.
			{"UPDATE migration_units SET state='cleanup_pending',committed_at=?,cleanup_after=? WHERE task_id=? AND unit_id=?", []any{now, now + 3600, l.TaskID, unit}},
			{"UPDATE migration_tasks SET state=CASE WHEN committed_bytes+?=total_bytes THEN 'cleanup_pending' ELSE state END,committed_bytes=committed_bytes+?,revision=revision+1,updated_at=? WHERE task_id=?", []any{bytes, bytes, now, l.TaskID}},
		} {
			if _, e = q.ExecContext(ctx, change.query, change.args...); e != nil {
				return e
			}
		}
		return r.nodeAudit(ctx, q, "resource-migration-unit-committed", "", map[string]any{"task_id": l.TaskID, "unit_id": unit, "source_id": t.SourceID, "target_id": t.TargetID, "objects": count, "bytes": bytes}, a)
	})
}
