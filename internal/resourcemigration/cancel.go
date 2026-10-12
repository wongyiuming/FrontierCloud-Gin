package resourcemigration

import (
	"context"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"time"
)

// Cancellation reconciles persisted units; it never reverses business owners.
func (r *Runner) cancelTask(ctx context.Context, id, runner string) (err error) {
	initial, e := r.Repository.MigrationWork(ctx, id)
	if e != nil {
		return e
	}
	for _, unit := range initial.Units {
		if unit.CommittedAt > 0 && unit.State != "cleaned" && unit.CleanupAfter <= time.Now().Unix() {
			if e = r.cleanup(ctx, id, runner); e != nil {
				return e
			}
			task, e := r.Repository.MigrationTask(ctx, id)
			if e != nil {
				return e
			}
			if task.State == "cancelled" {
				return nil
			}
			break
		}
	}
	l, e := r.Repository.ClaimMigration(ctx, id, runner, time.Minute)
	if e != nil {
		return e
	}
	object := ""
	defer func() {
		finish, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err != nil && ctx.Err() == nil && !errors.Is(err, store.ErrMigrationLease) {
			_ = r.Repository.MigrationRunState(finish, l, "cancelling", object, "cancel_cleanup", store.NodeAudit{})
		}
		_ = r.Repository.ReleaseMigration(finish, l)
	}()
	w, e := r.Repository.MigrationWork(ctx, id)
	if e != nil {
		return e
	}
	if w.Task.State != "cancelling" || w.Plan.Catalog.Source.RelationshipID == nil || w.Plan.Catalog.Target.RelationshipID == nil {
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
	allTerminal := true
	for _, u := range w.Units {
		if u.State != "cleaned" && u.State != "cancelled" {
			allTerminal = false
		}
	}
	refresh := func() error {
		for _, rel := range []store.Relationship{source, target} {
			if _, e := r.request(ctx, rel, prefix+"register", map[string]any{"header": h, "lease": l, "state": "cancelling"}); e != nil {
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
			if !allTerminal {
				return refresh()
			}
		}
		return ctx.Err()
	}
	if !allTerminal || len(w.Units) == 0 {
		if e = refresh(); e != nil {
			return e
		}
		for _, cp := range w.Objects {
			if e = ensure(); e != nil {
				return e
			}
			p := store.MigrationPeerObject{Object: cp.Object, Proof: store.MigrationDiskProof{ID: cp.Object.ID, Version: cp.Object.Version, Bytes: cp.Object.Bytes, SHA256: cp.SourceSHA}}
			for _, rel := range []store.Relationship{source, target} {
				if _, e = r.request(ctx, rel, prefix+"object", map[string]any{"lease": l, "object": p}); e != nil {
					return e
				}
			}
		}
	}
	for _, u := range w.Units {
		if u.State == "cleaned" || u.State == "cancelled" {
			continue
		}
		// Committed-unit cleanup and published shadows use their distinct managed
		// deletion protocols. Unknown/published bytes must never use staging Abort.
		if u.CommittedAt != 0 {
			continue
		}
		g, e := r.Repository.MigrationUnitCancelGrant(ctx, l, u.ID)
		if e != nil {
			return e
		}
		for _, cp := range w.Objects {
			if cp.UnitID != u.ID {
				continue
			}
			object = cp.Object.ID
			if e = ensure(); e != nil {
				return e
			}
			o := cp.Object
			spec := migrationdata.Spec{TaskID: id, MasterID: h.MasterID, SourceID: h.SourceID, TargetID: h.TargetID, LogicalID: o.ID, ObjectID: o.ObjectID, Resource: o.Resource, TargetPath: o.TargetPath, SourceVersion: o.Version, Bytes: o.Bytes, SHA256: cp.SourceSHA, Encryption: o.Encryption, Recording: o.Recording}
			response, e := r.request(ctx, target, prefix+"data/abort", migrationdata.Request{Lease: l, Spec: spec})
			if e != nil {
				return e
			}
			var checkpoint migrationdata.Checkpoint
			if e = decode(response, &checkpoint); e != nil {
				return e
			}
			expected, _ := store.MigrationDigest(spec)
			actual, _ := store.MigrationDigest(checkpoint.Spec)
			if expected != actual || checkpoint.State != "aborted" {
				return store.ErrMigrationState
			}
		}
		receipts := make([]store.MigrationUnitFinishReceipt, 0, 2)
		for _, rel := range []store.Relationship{source, target} {
			if e = ensure(); e != nil {
				return e
			}
			response, e := r.request(ctx, rel, prefix+"cancel-unit", map[string]any{"lease": l, "grant": g})
			if e != nil {
				return e
			}
			var receipt store.MigrationUnitFinishReceipt
			if e = decode(response, &receipt); e != nil {
				return e
			}
			receipts = append(receipts, receipt)
		}
		if e = r.Repository.CompleteMigrationUnitCancellation(ctx, l, receipts[0], receipts[1], store.NodeAudit{}); e != nil {
			return e
		}
	}
	current, e := r.Repository.MigrationWork(ctx, id)
	if e != nil {
		return e
	}
	for _, unit := range current.Units {
		if unit.State != "cleaned" && unit.State != "cancelled" {
			return nil
		}
	}
	allTerminal = true
	if e = ensure(); e != nil {
		return e
	}
	g, e := r.Repository.MigrationTaskCancelGrant(ctx, l)
	if e != nil {
		return e
	}
	receipts := make([]store.MigrationTaskFinishReceipt, 0, 2)
	for _, rel := range []store.Relationship{source, target} {
		if e = ensure(); e != nil {
			return e
		}
		response, e := r.request(ctx, rel, prefix+"cancel-task", map[string]any{"lease": l, "grant": g})
		if e != nil {
			return e
		}
		var receipt store.MigrationTaskFinishReceipt
		if e = decode(response, &receipt); e != nil {
			return e
		}
		receipts = append(receipts, receipt)
	}
	return r.Repository.CompleteMigrationTaskCancellation(ctx, l, receipts[0], receipts[1], store.NodeAudit{})
}
