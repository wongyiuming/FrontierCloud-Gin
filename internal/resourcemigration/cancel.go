package resourcemigration

import (
	"context"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"time"
)

// Cancellation reconciles persisted units; it never reverses business owners.
func (r *Runner) cancelTask(ctx context.Context, id, runner string) (err error) {
	var e error
	for unit, pageErr := range r.units(ctx, id) {
		if pageErr != nil {
			return pageErr
		}
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
	w, e := r.header(ctx, id)
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
	for u, pageErr := range r.units(ctx, id) {
		if pageErr != nil {
			return pageErr
		}
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
	scheduler := trafficSchedule{runner: r, source: source, target: target, task: id, master: w.Task.MasterID}
	ensureLease := ensure
	ensure = func() error {
		if allTerminal {
			return ensureLease()
		}
		return scheduler.wait(ctx, &l, "cancelling", object, ensureLease)
	}
	requestData := func(rel store.Relationship, route string, req migrationdata.Request) (map[string]any, error) {
		for {
			if err := ensure(); err != nil {
				return nil, err
			}
			req.Lease = l
			value, err := r.request(ctx, rel, route, req)
			if err != nil || value["waiting_traffic"] != true {
				return value, err
			}
			if err = scheduler.markWait(ctx, l, "cancelling", object, rel.PeerID); err != nil {
				return nil, err
			}
			scheduler.expires = time.Time{}
			if err = ensure(); err != nil {
				return nil, err
			}
			if req.ShadowGrant != nil {
				return map[string]any{"state": "grant_required"}, nil
			}
		}
	}
	if !allTerminal || w.Task.ObjectCount == 0 {
		if e = refresh(); e != nil {
			return e
		}
		for cp, pageErr := range r.objects(ctx, id, "") {
			if pageErr != nil {
				return pageErr
			}
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
	for u, pageErr := range r.units(ctx, id) {
		if pageErr != nil {
			return pageErr
		}
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
		for cp, pageErr := range r.objects(ctx, id, u.ID) {
			if pageErr != nil {
				return pageErr
			}
			if cp.UnitID != u.ID {
				continue
			}
			object = cp.Object.ID
			if e = ensure(); e != nil {
				return e
			}
			o := cp.Object
			spec := migrationdata.Spec{TaskID: id, MasterID: h.MasterID, SourceID: h.SourceID, TargetID: h.TargetID, LogicalID: o.ID, ObjectID: o.ObjectID, Resource: o.Resource, TargetPath: o.TargetPath, SourceVersion: o.Version, Bytes: o.Bytes, SHA256: cp.SourceSHA, Encryption: o.Encryption, Recording: o.Recording}
			response, e := requestData(target, prefix+"data/abort", migrationdata.Request{Lease: l, Spec: spec})
			if errors.Is(e, node.ErrRemoteConflict) && (o.Resource == "media" || o.Resource == "recording" && o.Recording != nil) {
				proof, err := r.FreshCancellationSourceProof(ctx, l, o.ID)
				if err != nil {
					return err
				}
				grant, err := r.Repository.AuthorizeMigrationShadowDeletion(ctx, l, o.ID, proof)
				if err != nil {
					return err
				}
				l, err = r.Repository.RenewMigration(ctx, l, time.Minute)
				if err != nil {
					return err
				}
				if err = refresh(); err != nil {
					return err
				}
				req := migrationdata.Request{Lease: l, Spec: spec, ShadowGrant: &grant}
				operation := "unpublish"
				deadline := time.Now().Add(targetCompletionTTL(o.Bytes))
				waitingAtStart := scheduler.waited
				for {
					if err = ensure(); err != nil {
						return err
					}
					req.Lease = l
					value, err := requestData(target, prefix+"data/"+operation, req)
					// A SQL-accounted publication requires managed deletion and a used
					// refund. It must never be treated as an unaccounted hard link.
					if operation == "unpublish" && errors.Is(err, node.ErrRemoteConflict) {
						operation = "shadow"
						req.ShadowGrant = &grant
						continue
					}
					if err != nil {
						return err
					}
					req.ShadowGrant = nil
					if value["state"] == "grant_required" {
						proof, err := r.FreshCancellationSourceProof(ctx, l, o.ID)
						if err != nil {
							return err
						}
						grant, err = r.Repository.AuthorizeMigrationShadowDeletion(ctx, l, o.ID, proof)
						if err != nil {
							return err
						}
						req.ShadowGrant = &grant
					}
					if value["state"] == "shadow_failed" || value["state"] == "unpublish_failed" {
						return store.ErrMigrationState
					}
					if value["state"] == "shadow_deleted" || value["state"] == "publication_aborted" {
						var cp migrationdata.Checkpoint
						if err = decode(value["checkpoint"], &cp); err != nil {
							return err
						}
						expected, _ := store.MigrationDigest(spec)
						actual, _ := store.MigrationDigest(cp.Spec)
						valid := value["state"] == "shadow_deleted" && cp.State == "published" && cp.AnchorRetired && !cp.AnchorRetiring || value["state"] == "publication_aborted" && cp.State == "aborted" && cp.PublicationCancelling && cp.PublicationUnlinked
						if expected != actual || !valid {
							return store.ErrMigrationState
						}
						break
					}
					if time.Now().After(deadline.Add(scheduler.waited - waitingAtStart)) {
						return context.DeadlineExceeded
					}
					if err = delay(ctx); err != nil {
						return err
					}
				}
				continue
			}
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
	for unit, pageErr := range r.units(ctx, id) {
		if pageErr != nil {
			return pageErr
		}
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
