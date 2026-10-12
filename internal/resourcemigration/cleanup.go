package resourcemigration

import (
	"context"
	"errors"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (r *Runner) cleanup(ctx context.Context, id, runner string) (err error) {
	l, e := r.Repository.ClaimMigration(ctx, id, runner, time.Minute)
	if e != nil {
		return e
	}
	object := ""
	defer func() {
		finish, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err != nil && ctx.Err() == nil && !errors.Is(err, store.ErrMigrationLease) {
			_ = r.Repository.MigrationRunState(finish, l, "cleanup_pending", object, "source_cleanup", store.NodeAudit{})
		}
		_ = r.Repository.ReleaseMigration(finish, l)
	}()
	w, e := r.Repository.MigrationWork(ctx, id)
	if e != nil {
		return e
	}
	if w.Task.State != "cleanup_pending" || w.Plan.Catalog.Source.RelationshipID == nil || w.Plan.Catalog.Target.RelationshipID == nil {
		return store.ErrMigrationState
	}
	source, e := r.Nodes.Relationship(ctx, *w.Plan.Catalog.Source.RelationshipID)
	if e != nil {
		return e
	}
	target, e := r.Nodes.Relationship(ctx, *w.Plan.Catalog.Target.RelationshipID)
	if e != nil {
		return e
	}
	if source.State != "active" || source.Direction != "downstream" || source.PeerID != w.Task.SourceID || target.State != "active" || target.Direction != "downstream" || target.PeerID != w.Task.TargetID {
		return store.ErrMigrationState
	}
	h := store.MigrationPeerHeader{Format: "frontiercloud-peer-migration", Version: 1, TaskID: id, MasterID: w.Task.MasterID, SourceID: w.Task.SourceID, TargetID: w.Task.TargetID, SourceRelationship: source.ID, TargetRelationship: target.ID, PlanSHA: w.Task.PlanSHA, ObjectCount: w.Task.ObjectCount, Bytes: w.Task.TotalBytes}
	refresh := func() error {
		for _, rel := range []store.Relationship{source, target} {
			if _, e := r.request(ctx, rel, prefix+"register", map[string]any{"header": h, "lease": l, "state": "queued"}); e != nil {
				return e
			}
		}
		return nil
	}
	ensure := func() error {
		if e := r.Repository.ValidateMigrationLease(ctx, l); e != nil {
			return e
		}
		if time.Now().Unix() >= l.ExpiresAt-40 {
			var e error
			l, e = r.Repository.RenewMigration(ctx, l, time.Minute)
			if e != nil {
				return e
			}
			return refresh()
		}
		return ctx.Err()
	}
	for _, cp := range w.Objects {
		if cp.State == "cleaned" {
			continue
		}
		if cp.State != "cleanup_pending" {
			return store.ErrMigrationState
		}
		eligible := false
		for _, u := range w.Units {
			if u.ID == cp.UnitID {
				eligible = u.CommittedAt > 0 && u.CleanupAfter >= u.CommittedAt+3600 && u.CleanupAfter <= time.Now().Unix()
			}
		}
		if !eligible {
			continue
		}
		object = cp.Object.ID
		if cp.Object.Resource != "media" && (cp.Object.Resource != "recording" || cp.Object.Recording == nil) {
			return store.ErrMigrationState
		}
		proof, e := r.FreshTargetProof(ctx, l, object)
		if e != nil {
			return e
		}
		grant, e := r.Repository.AuthorizeMigrationCleanup(ctx, l, object, proof)
		if e != nil {
			return e
		}
		// FreshTargetProof may have renewed this same runner during a long hash.
		l, e = r.Repository.RenewMigration(ctx, l, time.Minute)
		if e != nil {
			return e
		}
		if e = refresh(); e != nil {
			return e
		}
		o := cp.Object
		req := migrationdata.Request{Lease: l, CleanupGrant: &grant, Spec: migrationdata.Spec{TaskID: id, MasterID: w.Task.MasterID, SourceID: w.Task.SourceID, TargetID: w.Task.TargetID, LogicalID: o.ID, ObjectID: o.ObjectID, Resource: o.Resource, TargetPath: o.TargetPath, SourceVersion: o.Version, Bytes: o.Bytes, SHA256: cp.SourceSHA, Encryption: o.Encryption, Recording: o.Recording}}
		deadline := time.Now().Add(30 * time.Minute)
		for {
			if e = ensure(); e != nil {
				return e
			}
			req.Lease = l
			value, e := r.request(ctx, source, prefix+"data/cleanup", req)
			if e != nil {
				return e
			}
			req.CleanupGrant = nil
			if value["state"] == "cleanup_failed" {
				return store.ErrMigrationState
			}
			if value["state"] == "source_deleted" {
				var receipt store.MigrationSourceReceipt
				if e = decode(value["receipt"], &receipt); e != nil {
					return e
				}
				if e = r.Repository.RecordMigrationSourceDeletion(ctx, l, receipt, store.NodeAudit{}); e != nil {
					return e
				}
				break
			}
			if time.Now().After(deadline) {
				return context.DeadlineExceeded
			}
			if e = delay(ctx); e != nil {
				return e
			}
		}
	}
	return nil
}
