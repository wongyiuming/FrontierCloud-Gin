package business

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func validPeerHeader(h store.MigrationPeerHeader) bool {
	return h.Format == "frontiercloud-peer-migration" && h.Version == 1 && nodeIDPattern.MatchString(h.TaskID) && nodeIDPattern.MatchString(h.MasterID) && nodeIDPattern.MatchString(h.SourceID) && nodeIDPattern.MatchString(h.TargetID) && h.SourceID != h.TargetID && h.SourceID != h.MasterID && h.TargetID != h.MasterID && nodeIDPattern.MatchString(h.SourceRelationship) && nodeIDPattern.MatchString(h.TargetRelationship) && h.SourceRelationship != h.TargetRelationship && nodeHashPattern.MatchString(h.PlanSHA) && h.ObjectCount >= 0 && h.ObjectCount <= store.MaxMigrationObjects && h.Bytes >= 0 && h.Bytes <= store.MaxStorageAllocation && ((h.ObjectCount == 0) == (h.Bytes == 0))
}
func (r *Repository) peerIdentity(ctx context.Context, q queryer, relationship string, h store.MigrationPeerHeader) (store.NodeIdentity, error) {
	n, e := r.ownedStorageNode(ctx, q, relationship)
	if e != nil {
		return n, e
	}
	rel, e := scanRelation(q.QueryRowContext(ctx, "SELECT "+relationColumns+" FROM node_relationships WHERE relationship_id=?"+r.lock(), relationship))
	if e != nil {
		return n, e
	}
	if rel.PeerID != h.MasterID || n.ID != h.SourceID && n.ID != h.TargetID || n.ID == h.SourceID && relationship != h.SourceRelationship || n.ID == h.TargetID && relationship != h.TargetRelationship {
		return n, store.ErrMigrationState
	}
	return n, nil
}
func peerLeaseValid(l store.MigrationLease, id string) bool {
	now := time.Now().Unix()
	return l.TaskID == id && nodeIDPattern.MatchString(l.RunnerID) && l.Epoch > 0 && l.ExpiresAt > now && l.ExpiresAt <= now+90
}
func (r *Repository) peerHeader(ctx context.Context, q queryer, id string) (store.MigrationPeerHeader, string, error) {
	var raw []byte
	var state string
	e := q.QueryRowContext(ctx, "SELECT plan,state FROM migration_tasks WHERE task_id=?"+r.lock(), id).Scan(&raw, &state)
	if e != nil {
		return store.MigrationPeerHeader{}, state, e
	}
	if len(raw) > 8192 {
		return store.MigrationPeerHeader{}, state, store.ErrMigrationState
	}
	var h store.MigrationPeerHeader
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if d.Decode(&h) != nil || !validPeerHeader(h) || h.TaskID != id {
		return h, state, store.ErrMigrationState
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return h, state, store.ErrMigrationState
	}
	return h, state, nil
}
func (r *Repository) RegisterPeerMigration(ctx context.Context, relationship string, h store.MigrationPeerHeader, l store.MigrationLease, state string, free int64, a store.NodeAudit) error {
	if !nodeIDPattern.MatchString(relationship) || !validPeerHeader(h) || !peerLeaseValid(l, h.TaskID) || (state != "queued" && state != "cancelling") || free < 0 {
		return store.ErrMigrationState
	}
	raw, e := json.Marshal(h)
	if e != nil {
		return e
	}
	return r.write(ctx, func(q queryer) error {
		if !peerLeaseValid(l, h.TaskID) {
			return store.ErrMigrationLease
		}
		n, e := r.peerIdentity(ctx, q, relationship, h)
		if e != nil {
			return e
		}
		old, phase, e := r.peerHeader(ctx, q, h.TaskID)
		if e == nil {
			previous, _ := json.Marshal(old)
			if string(previous) != string(raw) || phase == "completed" || phase == "cancelled" {
				return store.ErrMigrationState
			}
			var runner string
			var epoch, expiry int64
			if e = q.QueryRowContext(ctx, "SELECT runner_id,epoch,expires_at FROM migration_runners WHERE task_id=?"+r.lock(), h.TaskID).Scan(&runner, &epoch, &expiry); e != nil {
				return e
			}
			if l.Epoch < epoch || l.Epoch == epoch && (l.RunnerID != runner || phase == "paused" || phase == "cancelling" && state != "cancelling" || l.ExpiresAt < expiry) {
				return store.ErrMigrationLease
			}
			if _, e = q.ExecContext(ctx, "UPDATE migration_runners SET runner_id=?,epoch=?,expires_at=? WHERE task_id=?", l.RunnerID, l.Epoch, l.ExpiresAt, h.TaskID); e != nil {
				return e
			}
			_, e = q.ExecContext(ctx, "UPDATE migration_tasks SET state=?,updated_at=? WHERE task_id=?", state, time.Now().Unix(), h.TaskID)
			return e
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		member, e := scanMember(q.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?"+r.lock(), n.ID))
		if e != nil {
			return e
		}
		var pending int
		if n.ID == h.SourceID {
			for _, query := range []string{"SELECT COUNT(*) FROM cluster_upload_sessions WHERE state NOT IN ('complete','cancelled')", "SELECT COUNT(*) FROM media_delete_operations WHERE state<>'rename_done'", "SELECT COUNT(*) FROM karaoke_recordings WHERE state NOT IN ('ready','deleted')", "SELECT COUNT(*) FROM migration_tasks WHERE state NOT IN ('completed','cancelled')"} {
				if e = q.QueryRowContext(ctx, query).Scan(&pending); e != nil {
					return e
				}
				if pending != 0 {
					return store.ErrMigrationState
				}
			}
			if member.Reserved != 0 {
				return store.ErrMigrationState
			}
		} else {
			draining, e := r.migrationDraining(ctx, q, n.ID)
			if e != nil {
				return e
			}
			if draining || member.Enabled != 1 || member.Writable != 1 || member.Health != "online" || min(member.Allocation-member.Used-member.Reserved, free-store.PhysicalReserve-member.Reserved) < h.Bytes {
				return store.ErrStorageCapacity
			}
		}
		now := time.Now().Unix()
		if _, e = q.ExecContext(ctx, "INSERT INTO migration_tasks(task_id,master_id,source_id,target_id,source_relationship,target_relationship,plan_sha256,plan,state,object_count,total_bytes,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", h.TaskID, h.MasterID, h.SourceID, h.TargetID, h.SourceRelationship, h.TargetRelationship, h.PlanSHA, string(raw), state, h.ObjectCount, h.Bytes, now, now); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "INSERT INTO migration_runners(task_id,runner_id,epoch,expires_at) VALUES (?,?,?,?)", h.TaskID, l.RunnerID, l.Epoch, l.ExpiresAt); e != nil {
			return e
		}
		if n.ID == h.SourceID {
			if _, e = q.ExecContext(ctx, "INSERT INTO migration_drains(member_id,owner_id,reason,created_at) VALUES (?,?,'migration',?)", n.ID, h.TaskID, now); e != nil {
				return e
			}
		} else {
			if _, e = q.ExecContext(ctx, "INSERT INTO migration_capacity(task_id,member_id,reserved_bytes,updated_at) VALUES (?,?,?,?)", h.TaskID, n.ID, h.Bytes, now); e != nil {
				return e
			}
			if _, e = q.ExecContext(ctx, "UPDATE cluster_storage_members SET reserved_bytes=reserved_bytes+?,physical_free_bytes=?,updated_at=? WHERE member_id=?", h.Bytes, free, now, n.ID); e != nil {
				return e
			}
		}
		return r.nodeAudit(ctx, q, "peer-migration-registered", relationship, map[string]any{"task_id": h.TaskID, "source_id": h.SourceID, "target_id": h.TargetID, "objects": h.ObjectCount, "bytes": h.Bytes}, a)
	})
}
func (r *Repository) checkPeerLease(ctx context.Context, q queryer, relationship string, l store.MigrationLease) (store.MigrationPeerHeader, store.NodeIdentity, string, error) {
	if _, e := readNode(ctx, q, r.lock()); e != nil {
		return store.MigrationPeerHeader{}, store.NodeIdentity{}, "", e
	}
	if !nodeIDPattern.MatchString(l.RunnerID) || l.Epoch <= 0 || !nodeIDPattern.MatchString(l.TaskID) {
		return store.MigrationPeerHeader{}, store.NodeIdentity{}, "", store.ErrMigrationLease
	}
	h, state, e := r.peerHeader(ctx, q, l.TaskID)
	if e != nil {
		return h, store.NodeIdentity{}, state, e
	}
	n, e := r.peerIdentity(ctx, q, relationship, h)
	if e != nil {
		return h, n, state, e
	}
	var runner string
	var epoch, expires int64
	if e = q.QueryRowContext(ctx, "SELECT runner_id,epoch,expires_at FROM migration_runners WHERE task_id=?"+r.lock(), l.TaskID).Scan(&runner, &epoch, &expires); e != nil {
		return h, n, state, e
	}
	if runner != l.RunnerID || epoch != l.Epoch || expires <= time.Now().Unix() || (state != "queued" && state != "copying" && state != "verifying" && state != "committing" && state != "cleanup_pending" && state != "cancelling") {
		return h, n, state, store.ErrMigrationLease
	}
	return h, n, state, nil
}
func validPeerObject(h store.MigrationPeerHeader, v store.MigrationPeerObject) bool {
	o, p := v.Object, v.Proof
	if p.ID != o.ID || p.Version != o.Version || p.Bytes != o.Bytes || o.Bytes <= 0 || o.Bytes > 10*store.GiB || !nodeHashPattern.MatchString(o.Version) || !nodeHashPattern.MatchString(p.SHA256) {
		return false
	}
	if o.Resource == "media" {
		return nodeHashPattern.MatchString(o.ID) && nodeHashPattern.MatchString(o.ObjectID) && poolPath(store.LocalMedia{MediaObject: store.MediaObject{Path: o.Path, Kind: o.Kind}, Bytes: o.Bytes}) && o.Parent == path.Dir(o.Path) && o.TargetPath == o.Path && (o.Encryption == nil || o.Encryption.Validate() == nil && o.Encryption.CiphertextSize == o.Bytes)
	}
	return o.Resource == "recording" && nodeIDPattern.MatchString(o.ID) && o.ObjectID == o.ID && nodeIDPattern.MatchString(o.Parent) && o.Bytes <= store.MaxRecordingBytes && o.Path == h.SourceRelationship+"/"+o.Parent+"/"+o.ID+".bin" && o.TargetPath == h.TargetRelationship+"/"+o.Parent+"/"+o.ID+".bin" && o.Encryption == nil
}
func (r *Repository) RegisterPeerMigrationObject(ctx context.Context, relationship string, l store.MigrationLease, v store.MigrationPeerObject, a store.NodeAudit) error {
	return r.write(ctx, func(q queryer) error {
		h, n, state, e := r.checkPeerLease(ctx, q, relationship, l)
		if e != nil {
			return e
		}
		if state == "cancelling" || !validPeerObject(h, v) {
			return store.ErrMigrationState
		}
		o := v.Object
		physical := o.Path
		if n.ID == h.TargetID {
			physical = o.TargetPath
		}
		var existingVersion, existingPath, existingHash, existingObject, existingKind, existingUnit string
		var existingSize int64
		e = q.QueryRowContext(ctx, "SELECT source_version,physical_path,sha256,expected_bytes,object_id,resource_kind,unit_id FROM migration_storage_journal WHERE task_id=? AND logical_id=?"+r.lock(), l.TaskID, o.ID).Scan(&existingVersion, &existingPath, &existingHash, &existingSize, &existingObject, &existingKind, &existingUnit)
		if e == nil {
			if existingVersion != o.Version || existingPath != physical || existingHash != v.Proof.SHA256 || existingSize != o.Bytes || existingObject != o.ObjectID || existingKind != o.Resource || existingUnit != migrationUnit(o) {
				return store.ErrMigrationState
			}
			return r.persistPeerObjectBinding(ctx, q, l.TaskID, o)
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		var count, total int64
		if e = q.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(expected_bytes),0) FROM migration_storage_journal WHERE task_id=?", l.TaskID).Scan(&count, &total); e != nil {
			return e
		}
		if count >= h.ObjectCount || total > h.Bytes-o.Bytes {
			return store.ErrMigrationState
		}
		if o.Resource == "media" {
			var id, name, kind string
			e = q.QueryRowContext(ctx, "SELECT media_id,media_path,object_kind FROM media_objects WHERE media_id=? OR path_locator=?"+r.lock(), o.ObjectID, locator(physical)).Scan(&id, &name, &kind)
			if n.ID == h.SourceID {
				if e != nil {
					return e
				}
				if id != o.ObjectID || name != physical || kind != o.Kind {
					return store.ErrMigrationState
				}
				encryption, e := readEncryption(ctx, q, id, r.lock())
				if e != nil {
					return e
				}
				if (encryption == nil) != (o.Encryption == nil) || encryption != nil && *encryption != *o.Encryption {
					return store.ErrMigrationState
				}
			} else if e == nil {
				return store.ErrMigrationState
			} else if !errors.Is(e, sql.ErrNoRows) {
				return e
			}
			if n.ID == h.TargetID {
				where, args := r.pathScope("media_path", o.Parent, true)
				where += " AND LENGTH(media_path)-LENGTH(REPLACE(media_path,'/',''))=?"
				args = append(args, strings.Count(o.Parent, "/")+1)
				var siblings int
				if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM media_objects WHERE object_kind IN ('audio','video') AND "+where, args...).Scan(&siblings); e != nil {
					return e
				}
				if siblings != 0 {
					return store.ErrMigrationState
				}
				where, args = r.pathScope("media_path", o.Parent, true)
				where += " AND LENGTH(media_path)-LENGTH(REPLACE(media_path,'/',''))=?"
				args = append(args, strings.Count(o.Parent, "/")+1)
				if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM cluster_upload_sessions WHERE state='reserved' AND "+where, args...).Scan(&siblings); e != nil {
					return e
				}
				if siblings != 0 {
					return store.ErrMigrationState
				}
			}
		} else {
			v, e := recordingLookup(q.QueryRowContext(ctx, "SELECT "+recordingColumns+" FROM karaoke_recordings WHERE recording_id=?"+r.lock(), o.ID))
			if e != nil {
				return e
			}
			if n.ID == h.SourceID {
				if v == nil || v.UserID != o.Parent || v.State != "ready" || v.MemberID != n.ID || v.Bytes != o.Bytes || v.SHA256 == nil || *v.SHA256 != o.ETag {
					return store.ErrMigrationState
				}
			} else if v != nil {
				return store.ErrMigrationState
			}
		}
		var pending int
		if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM cluster_upload_sessions WHERE state='reserved' AND path_locator=?", locator(physical)).Scan(&pending); e != nil {
			return e
		}
		if pending != 0 {
			return store.ErrMigrationState
		}
		scope := migrationScope(o, n.ID)
		var owner string
		e = q.QueryRowContext(ctx, "SELECT task_id FROM migration_scopes WHERE scope_id=?"+r.lock(), scope).Scan(&owner)
		if e == nil && owner != l.TaskID {
			return store.ErrMigrationState
		}
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if errors.Is(e, sql.ErrNoRows) {
			if _, e = q.ExecContext(ctx, "INSERT INTO migration_scopes(scope_id,task_id,member_id,resource_kind,parent_path,created_at) VALUES (?,?,?,?,?,?)", scope, l.TaskID, n.ID, o.Resource, o.Parent, time.Now().Unix()); e != nil {
				return e
			}
		}
		_, e = q.ExecContext(ctx, "INSERT INTO migration_storage_journal(task_id,logical_id,unit_id,master_id,source_id,target_id,resource_kind,object_id,physical_path,source_version,expected_bytes,sha256,state,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'receiving',?)", l.TaskID, o.ID, migrationUnit(o), h.MasterID, h.SourceID, h.TargetID, o.Resource, o.ObjectID, physical, o.Version, o.Bytes, v.Proof.SHA256, time.Now().Unix())
		if e != nil {
			return e
		}
		return r.persistPeerObjectBinding(ctx, q, l.TaskID, o)
	})
}
func (r *Repository) AuthorizePeerMigration(ctx context.Context, relationship string, l store.MigrationLease, id, operation string) (v store.MigrationPeerObject, e error) {
	e = r.write(ctx, func(q queryer) error {
		h, n, state, e := r.checkPeerLease(ctx, q, relationship, l)
		if e != nil {
			return e
		}
		if operation == "abort" {
			if state != "cancelling" || n.ID != h.TargetID {
				return store.ErrMigrationState
			}
		} else if state == "cancelling" {
			return store.ErrMigrationState
		}
		if operation != "read" && operation != "begin" && operation != "status" && operation != "append" && operation != "verify" && operation != "publish" && operation != "abort" {
			return store.ErrMigrationState
		}
		if operation == "read" && n.ID != h.SourceID || operation != "read" && n.ID != h.TargetID {
			return store.ErrMigrationState
		}
		var count, total int64
		if e = q.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(expected_bytes),0) FROM migration_storage_journal WHERE task_id=?", l.TaskID).Scan(&count, &total); e != nil {
			return e
		}
		if count != h.ObjectCount || total != h.Bytes {
			return store.ErrMigrationState
		}
		var phase string
		if e = q.QueryRowContext(ctx, "SELECT logical_id,object_id,resource_kind,physical_path,source_version,expected_bytes,sha256,state FROM migration_storage_journal WHERE task_id=? AND logical_id=?"+r.lock(), l.TaskID, id).Scan(&v.Object.ID, &v.Object.ObjectID, &v.Object.Resource, &v.Object.Path, &v.Object.Version, &v.Object.Bytes, &v.Proof.SHA256, &phase); e != nil {
			return e
		}
		if phase == "deleted" || phase == "aborted" {
			return store.ErrMigrationState
		}
		if operation == "publish" && phase != "verified" && phase != "publishing" && phase != "published" {
			return store.ErrMigrationState
		}
		v.Proof.ID = v.Object.ID
		v.Proof.Version = v.Object.Version
		v.Proof.Bytes = v.Object.Bytes
		v.Header = h
		v.State = phase
		bound, e := r.peerObjectBinding(ctx, q, l.TaskID, id)
		if errors.Is(e, sql.ErrNoRows) {
			return store.ErrMigrationState
		}
		if e != nil {
			return e
		}
		physical := bound.Path
		if n.ID == h.TargetID {
			physical = bound.TargetPath
		}
		if bound.ObjectID != v.Object.ObjectID || bound.Version != v.Object.Version || bound.Bytes != v.Object.Bytes || bound.Resource != v.Object.Resource || physical != v.Object.Path {
			return store.ErrMigrationState
		}
		v.Object = bound
		v.Object.Path = physical
		return nil
	})
	return
}
func (r *Repository) FencePeerMigration(ctx context.Context, relationship, task string, epoch int64, state string, a store.NodeAudit) error {
	if epoch <= 0 || (state != "paused" && state != "cancelling") {
		return store.ErrMigrationState
	}
	return r.write(ctx, func(q queryer) error {
		if _, e := readNode(ctx, q, r.lock()); e != nil {
			return e
		}
		h, phase, e := r.peerHeader(ctx, q, task)
		if e != nil {
			return e
		}
		if phase == "completed" || phase == "cancelled" {
			return store.ErrMigrationState
		}
		if _, e = r.peerIdentity(ctx, q, relationship, h); e != nil {
			return e
		}
		var current int64
		if e = q.QueryRowContext(ctx, "SELECT epoch FROM migration_runners WHERE task_id=?"+r.lock(), task).Scan(&current); e != nil {
			return e
		}
		if epoch < current {
			return store.ErrMigrationLease
		}
		if _, e = q.ExecContext(ctx, "UPDATE migration_runners SET epoch=?,expires_at=0 WHERE task_id=?", epoch, task); e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, "UPDATE migration_tasks SET state=?,updated_at=? WHERE task_id=?", state, time.Now().Unix(), task); e != nil {
			return e
		}
		return r.nodeAudit(ctx, q, "peer-migration-fenced", relationship, map[string]any{"task_id": task, "state": state, "epoch": epoch}, a)
	})
}

var _ store.MigrationPeerRepository = (*Repository)(nil)

// Only the local byte verifier calls this after actual disk SHA/length proof.
// An incoming control request is never itself evidence of verified bytes.
func (r *Repository) VerifyPeerMigrationObject(ctx context.Context, relationship string, l store.MigrationLease, id string, size int64, sha string) error {
	return r.write(ctx, func(q queryer) error {
		h, n, state, e := r.checkPeerLease(ctx, q, relationship, l)
		if e != nil {
			return e
		}
		if n.ID != h.TargetID || state == "cancelling" {
			return store.ErrMigrationState
		}
		var expected int64
		var hash, phase string
		if e = q.QueryRowContext(ctx, "SELECT expected_bytes,sha256,state FROM migration_storage_journal WHERE task_id=? AND logical_id=?"+r.lock(), l.TaskID, id).Scan(&expected, &hash, &phase); e != nil {
			return e
		}
		if expected != size || hash != sha || phase != "receiving" && phase != "verified" {
			return store.ErrMigrationState
		}
		_, e = q.ExecContext(ctx, "UPDATE migration_storage_journal SET state='verified',updated_at=? WHERE task_id=? AND logical_id=?", time.Now().Unix(), l.TaskID, id)
		return e
	})
}
