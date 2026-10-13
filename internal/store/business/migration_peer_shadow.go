package business

import (
	"context"
	"database/sql"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"time"
)

// This admission persists an exact target cancellation deletion fence. It does
// not delete bytes, change business ownership or refund used/reserved capacity.
func (r *Repository) PreparePeerMigrationShadowDeletion(ctx context.Context, rel string, l store.MigrationLease, g store.MigrationShadowGrant, a store.NodeAudit) error {
	return r.preparePeerMigrationCancellation(ctx, rel, l, g, a, false)
}
func (r *Repository) PreparePeerMigrationPublicationAbort(ctx context.Context, rel string, l store.MigrationLease, g store.MigrationShadowGrant, a store.NodeAudit) error {
	return r.preparePeerMigrationCancellation(ctx, rel, l, g, a, true)
}
func (r *Repository) preparePeerMigrationCancellation(ctx context.Context, rel string, l store.MigrationLease, g store.MigrationShadowGrant, a store.NodeAudit, publicationAbort bool) error {
	initial, working, terminal, action := "published", "deleting", "deleted", "peer-migration-shadow-delete-authorized"
	if publicationAbort {
		initial, working, terminal, action = "verified", "aborting", "aborted", "peer-migration-publication-abort-authorized"
	}
	return r.write(ctx, func(q queryer) error {
		h, n, state, e := r.checkPeerLease(ctx, q, rel, l)
		if e != nil {
			return e
		}
		expected, _ := store.MigrationDigest(h)
		actual, _ := store.MigrationDigest(g.Unit.Header)
		u := g.Unit.Unit
		o := g.Object
		proof := g.SourceProof
		if state != "cancelling" || n.ID != h.TargetID || expected != actual || u.State != "cancelled" || u.CommittedAt != 0 || u.CleanupAfter != 0 || !nodeHashPattern.MatchString(g.Unit.UnitVersion) || !nodeHashPattern.MatchString(g.Unit.ObjectsSHA) || u.ObjectCount <= 0 || u.Bytes <= 0 || o.Resource != "media" && (o.Resource != "recording" || o.Recording == nil) || u.ID != migrationUnit(o) || u.Resource != o.Resource || u.Parent != o.Parent || !validPeerObject(h, store.MigrationPeerObject{Object: o, Proof: proof.MigrationDiskProof}) {
			return store.ErrMigrationState
		}
		bound, e := r.peerObjectBinding(ctx, q, l.TaskID, o.ID)
		if e != nil {
			return e
		}
		expected, e = store.MigrationDigest(bound)
		if e != nil {
			return e
		}
		actual, e = store.MigrationDigest(o)
		if e != nil || expected != actual {
			return store.ErrMigrationState
		}
		// A complete sorted roster is verified once before persisting its root.
		// Replays on a fresh process use only this durable fact plus the exact
		// object binding/current phase/proof below. Legacy unit versions keep
		// the full validation path. Final unit cancellation always scans all.
		var unitState, unitVersion, unitResource, unitParent string
		var count, bytes, committed, after int64
		e = q.QueryRowContext(ctx, "SELECT state,source_version,object_count,total_bytes,committed_at,cleanup_after,resource_kind,parent_path FROM migration_units WHERE task_id=? AND unit_id=?"+r.lock(), l.TaskID, u.ID).Scan(&unitState, &unitVersion, &count, &bytes, &committed, &after, &unitResource, &unitParent)
		unitExists := e == nil
		if unitExists {
			if unitState != "pending" || unitVersion != g.Unit.UnitVersion || count != u.ObjectCount || bytes != u.Bytes || committed != 0 || after != 0 || unitResource != u.Resource || unitParent != u.Parent {
				return store.ErrMigrationState
			}
		} else if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		sealedRoster := unitExists && unitVersion == g.Unit.ObjectsSHA
		if !sealedRoster {
			var rosterCount, rosterBytes int64
			if e = q.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(expected_bytes),0) FROM migration_storage_journal WHERE task_id=?", l.TaskID).Scan(&rosterCount, &rosterBytes); e != nil {
				return e
			}
			if rosterCount != h.ObjectCount || rosterBytes != h.Bytes {
				return store.ErrMigrationState
			}

			var objects store.MigrationSequence
			var total int64
			for object, err := range r.peerObjects(ctx, q, l.TaskID, u.ID) {
				if err != nil {
					return err
				}
				if object.Object.Parent != u.Parent || object.Object.Resource != u.Resource {
					return store.ErrMigrationState
				}
				total += object.Object.Bytes
				object.State = ""
				object.Header = store.MigrationPeerHeader{}
				if e = objects.Add(object.Object.ID, object); e != nil {
					return e
				}
			}
			if objects.Count() != u.ObjectCount || total != u.Bytes || objects.Sum() != g.Unit.ObjectsSHA {
				return store.ErrMigrationState
			}

		}

		var phase, hash, version string
		var size int64
		if e = q.QueryRowContext(ctx, "SELECT state,sha256,source_version,expected_bytes FROM migration_storage_journal WHERE task_id=? AND logical_id=?"+r.lock(), l.TaskID, o.ID).Scan(&phase, &hash, &version, &size); e != nil {
			return e
		}
		if hash != proof.SHA256 || version != proof.Version || size != proof.Bytes || proof.ID != o.ID || phase != initial && phase != working && phase != terminal {
			return store.ErrMigrationState
		}
		now := time.Now().Unix()
		if phase == initial && (proof.VerifiedAt < now-30 || proof.VerifiedAt > now+30) {
			return store.ErrMigrationState
		}
		if !unitExists {
			if phase != initial {
				return store.ErrMigrationState
			}
			if _, e = q.ExecContext(ctx, "INSERT INTO migration_units(task_id,unit_id,resource_kind,parent_path,source_version,state,object_count,total_bytes) VALUES (?,?,?,?,?,'pending',?,?)", l.TaskID, u.ID, u.Resource, u.Parent, g.Unit.UnitVersion, u.ObjectCount, u.Bytes); e != nil {
				return e
			}
		}
		if publicationAbort {
			// SQL-accounted publications never enter this path. A business link
			// can be unlinked only when its metadata is absent or an exact retired
			// recording tombstone belongs to the same physical binding.
			if o.Resource == "media" {
				var present int
				if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM media_objects WHERE media_id=? OR path_locator=?", o.ObjectID, locator(o.TargetPath)).Scan(&present); e != nil {
					return e
				}
				if present != 0 {
					return store.ErrMigrationState
				}
			} else {
				row, e := recordingLookup(q.QueryRowContext(ctx, "SELECT "+recordingColumns+" FROM karaoke_recordings WHERE recording_id=?"+r.lock(), o.ID))
				if e != nil {
					return e
				}
				if row != nil && (row.State != "deleted" || row.MemberID != h.TargetID || row.UserID != o.Parent || row.Bytes != o.Bytes || row.SHA256 == nil || *row.SHA256 != proof.SHA256 || row.Filename != o.Recording.Filename || row.ContentType != o.Recording.ContentType) {
					return store.ErrMigrationState
				}
			}
		}
		if phase == working || phase == terminal {
			var failed int
			if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_objects WHERE task_id=? AND logical_id=? AND state='pending'", l.TaskID, o.ID).Scan(&failed); e != nil {
				return e
			}
			if failed != 0 {
				if proof.VerifiedAt < now-30 || proof.VerifiedAt > now+30 {
					return store.ErrMigrationState
				}
				if _, e = q.ExecContext(ctx, "DELETE FROM migration_objects WHERE task_id=? AND logical_id=? AND state='pending'", l.TaskID, o.ID); e != nil {
					return e
				}
			}
			return nil
		}
		var reads int
		if e = q.QueryRowContext(ctx, "SELECT COUNT(*) FROM migration_read_leases WHERE member_id=? AND (logical_id=? OR object_id=?) AND expires_at>?", n.ID, o.ID, o.ObjectID, now).Scan(&reads); e != nil {
			return e
		}
		if reads != 0 {
			return store.ErrMigrationState
		}
		if _, e = q.ExecContext(ctx, "UPDATE migration_storage_journal SET state=?,updated_at=? WHERE task_id=? AND logical_id=?", working, now, l.TaskID, o.ID); e != nil {
			return e
		}
		return r.nodeAudit(ctx, q, action, rel, map[string]any{"task_id": l.TaskID, "logical_id": o.ID, "unit_id": u.ID, "source_verified_at": proof.VerifiedAt, "source_sha256": proof.SHA256}, a)
	})
}
