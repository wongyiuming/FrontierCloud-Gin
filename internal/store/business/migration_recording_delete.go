package business

import (
	"context"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (r *Repository) peerRecordingDelete(ctx context.Context, q queryer, member, task, id string) (*store.Recording, error) {
	h, taskState, e := r.peerHeader(ctx, q, task)
	if e != nil {
		return nil, e
	}
	shadow := h.TargetID == member
	if h.SourceID != member && !shadow || shadow && taskState != "cancelling" {
		return nil, store.ErrMigrationState
	}
	o, e := r.peerObjectBinding(ctx, q, task, id)
	if e != nil {
		return nil, e
	}
	if o.Resource != "recording" || o.Recording == nil {
		return nil, store.ErrMigrationState
	}
	var phase, sha, version string
	var size int64
	if e = q.QueryRowContext(ctx, "SELECT state,sha256,source_version,expected_bytes FROM migration_storage_journal WHERE task_id=? AND logical_id=?"+r.lock(), task, id).Scan(&phase, &sha, &version, &size); e != nil {
		return nil, e
	}
	if phase != "deleting" && phase != "deleted" || sha != o.Recording.SHA256 || size != o.Bytes || version != o.Version {
		return nil, store.ErrMigrationState
	}
	var committed, after int64
	var unitState string
	if e = q.QueryRowContext(ctx, "SELECT state,committed_at,cleanup_after FROM migration_units WHERE task_id=? AND unit_id=?"+r.lock(), task, migrationUnit(o)).Scan(&unitState, &committed, &after); e != nil {
		return nil, e
	}
	if shadow {
		if unitState != "pending" || committed != 0 || after != 0 {
			return nil, store.ErrMigrationState
		}
	} else if unitState != "cleanup_pending" || committed <= 0 || after < committed+3600 || after > time.Now().Unix() {
		return nil, store.ErrMigrationState
	}
	v, e := scanRecording(q.QueryRowContext(ctx, "SELECT "+recordingColumns+" FROM karaoke_recordings WHERE recording_id=?"+r.lock(), id))
	if e != nil {
		return nil, e
	}
	if v.UserID != o.Parent || v.MemberID != member || v.Filename != o.Recording.Filename || v.ContentType != o.Recording.ContentType || v.Bytes != o.Bytes || v.SHA256 == nil || *v.SHA256 != sha {
		return nil, store.ErrMigrationState
	}
	if phase == "deleted" {
		if v.State != "deleted" {
			return nil, store.ErrMigrationState
		}
		return &v, nil
	}
	if v.State != "ready" && v.State != "deleting" || !store.RecordingProofSnapshotMatches(*o.Recording, ptrMetadata(store.RecordingMetadataFor(v))) {
		return nil, store.ErrMigrationState
	}
	var reads int
	if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_read_leases WHERE member_id=? AND (logical_id=? OR object_id=?) AND expires_at>?", member, id, id, time.Now().Unix()).Scan(&reads); e != nil {
		return nil, e
	}
	if reads != 0 {
		return nil, store.ErrMigrationState
	}
	return &v, nil
}

func (r *Repository) StagePeerRecordingDeletion(ctx context.Context, relationship string, l store.MigrationLease, id string) (v *store.Recording, e error) {
	e = r.write(ctx, func(q queryer) error {
		h, n, _, err := r.checkPeerLease(ctx, q, relationship, l)
		if err != nil {
			return err
		}
		if n.ID != h.SourceID && n.ID != h.TargetID {
			return store.ErrMigrationState
		}
		v, err = r.peerRecordingDelete(ctx, q, n.ID, l.TaskID, id)
		if err != nil {
			return err
		}
		if v.State == "deleted" {
			return nil
		}
		if _, err = q.ExecContext(ctx, "UPDATE karaoke_recordings SET state='deleting',updated_at=? WHERE recording_id=?", time.Now().Unix(), id); err != nil {
			return err
		}
		v.State = "deleting"
		return nil
	})
	return
}

// A prepared file intent may finish after restart/lease expiry. Its persisted
// grant, exact recording descriptor and source journal remain mandatory.
func (r *Repository) CompletePeerRecordingDeletion(ctx context.Context, relationship, task, id string, free int64, a store.NodeAudit) error {
	if !nodeIDPattern.MatchString(relationship) || !nodeIDPattern.MatchString(task) || !nodeIDPattern.MatchString(id) || free < 0 {
		return store.ErrMigrationState
	}
	return r.write(ctx, func(q queryer) error {
		n, e := r.ownedStorageNode(ctx, q, relationship)
		if e != nil {
			return e
		}
		v, e := r.peerRecordingDelete(ctx, q, n.ID, task, id)
		if e != nil {
			return e
		}
		if v.State == "deleted" {
			return nil
		}
		if v.State != "deleting" {
			return store.ErrMigrationState
		}
		return r.completeOwnedRecordingDeletion(ctx, q, relationship, v.UserID, id, free, a, task)
	})
}
