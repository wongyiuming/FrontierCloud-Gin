package business

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"time"
)

// AuthorizeMigrationCleanup is a short fenced transaction. Its caller must
// authenticate a fresh target disk verification; there is no browser/CLI path
// that accepts these proof fields directly from an administrator.
func (r *Repository) AuthorizeMigrationCleanup(ctx context.Context, l store.MigrationLease, id string, proof store.MigrationCleanupProof) (grant store.MigrationCleanupGrant, e error) {
	e = r.write(ctx, func(q queryer) error {
		t, e := r.checkMigrationLease(ctx, q, l)
		if e != nil {
			return e
		}
		if t.State != "cleanup_pending" && t.State != "committing" {
			return store.ErrMigrationState
		}
		w, e := r.migrationWork(ctx, q, l.TaskID)
		if e != nil {
			return e
		}
		var object *store.MigrationCheckpoint
		var unit *store.MigrationUnit
		for i := range w.Objects {
			if w.Objects[i].Object.ID == id {
				object = &w.Objects[i]
				break
			}
		}
		if object == nil {
			return store.ErrMigrationState
		}
		for i := range w.Units {
			if w.Units[i].ID == object.UnitID {
				unit = &w.Units[i]
				break
			}
		}
		now := time.Now().Unix()
		if unit == nil || unit.State != "cleanup_pending" || object.State != "cleanup_pending" || unit.CommittedAt <= 0 || unit.CleanupAfter < unit.CommittedAt+3600 || unit.CleanupAfter > now {
			return store.ErrMigrationState
		}
		o := object.Object
		if proof.ID != id || proof.Version != o.Version || proof.Bytes != o.Bytes || proof.SHA256 != object.SourceSHA || object.TargetSHA != object.SourceSHA || object.VerifiedBytes != o.Bytes || proof.VerifiedAt < unit.CommittedAt || proof.VerifiedAt < now-30 || proof.VerifiedAt > now+30 {
			return store.ErrMigrationState
		}
		table, key := "global_media_objects", "media_id"
		if o.Resource == "recording" {
			table, key = "karaoke_recordings", "recording_id"
		}
		var owner, state string
		if e = q.QueryRowContext(ctx, "SELECT storage_member_id,state FROM "+table+" WHERE "+key+"=?"+r.lock(), id).Scan(&owner, &state); e != nil {
			return e
		}
		expectedState := "active"
		if o.Resource == "recording" {
			expectedState = "ready"
		}
		if owner != t.TargetID || state != expectedState {
			return store.ErrMigrationState
		}
		if o.Resource == "media" {
			var physical, path, etag string
			var size int64
			if e = q.QueryRowContext(ctx, "SELECT object_id,media_path,size_bytes,etag FROM global_media_objects WHERE media_id=?"+r.lock(), id).Scan(&physical, &path, &size, &etag); e != nil {
				return e
			}
			if physical != o.ObjectID || path != o.Path || size != o.Bytes || etag != o.ETag {
				return store.ErrMigrationState
			}
		} else {
			current, e := scanRecording(q.QueryRowContext(ctx, "SELECT "+recordingColumns+" FROM karaoke_recordings WHERE recording_id=?"+r.lock(), id))
			if e != nil {
				return e
			}
			if current.Bytes != o.Bytes || current.SHA256 == nil || *current.SHA256 != o.ETag {
				return store.ErrMigrationState
			}
			if o.Recording != nil && (current.Filename != o.Recording.Filename || current.ContentType != o.Recording.ContentType) {
				return store.ErrMigrationState
			}
		}
		// Any still-valid dependency blocks cleanup, including a different logical
		// alias referencing this same source physical identity.
		var reads int
		if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_read_leases WHERE member_id=? AND (logical_id=? OR object_id=?) AND expires_at>?", t.SourceID, id, o.ObjectID, now).Scan(&reads); e != nil {
			return e
		}
		if reads != 0 {
			return store.ErrMigrationState
		}
		source, e := scanMember(q.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?"+r.lock(), t.SourceID))
		if e != nil {
			return e
		}
		target, e := scanMember(q.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM cluster_storage_members WHERE member_id=?"+r.lock(), t.TargetID))
		if e != nil {
			return e
		}
		if source.RelationshipID == nil || target.RelationshipID == nil || source.Health != "online" || target.Health != "online" {
			return store.ErrMigrationState
		}
		for _, entry := range []struct {
			member  store.StorageMember
			binding string
		}{{source, w.Plan.Catalog.SourceBinding}, {target, w.Plan.Catalog.TargetBinding}} {
			rel, e := scanRelation(q.QueryRowContext(ctx, "SELECT "+relationColumns+" FROM node_relationships WHERE relationship_id=?"+r.lock(), *entry.member.RelationshipID))
			if e != nil {
				return e
			}
			binding, e := migrationBinding(rel)
			if e != nil {
				return e
			}
			if binding != entry.binding || rel.Status != "online" || now-rel.LastHeartbeat >= 120 || rel.LastHeartbeat > now+30 {
				return store.ErrMigrationState
			}
		}
		var unitVersion string
		if e = q.QueryRowContext(ctx, "SELECT source_version FROM migration_units WHERE task_id=? AND unit_id=?"+r.lock(), l.TaskID, unit.ID).Scan(&unitVersion); e != nil {
			return e
		}
		grant = store.MigrationCleanupGrant{TaskID: l.TaskID, MasterID: t.MasterID, SourceID: t.SourceID, TargetID: t.TargetID, PlanSHA: t.PlanSHA, UnitID: unit.ID, UnitVersion: unitVersion, Object: o, SHA256: object.SourceSHA, CommittedAt: unit.CommittedAt, CleanupAfter: unit.CleanupAfter, TargetVerifiedAt: proof.VerifiedAt}
		return nil
	})
	return
}
