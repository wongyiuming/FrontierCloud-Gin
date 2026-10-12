package resourcemigration

import (
	"context"
	"errors"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (r *Runner) cleanup(ctx context.Context, id, runner string) (err error) {
	task, e := r.Repository.MigrationTask(ctx, id)
	if e != nil {
		return e
	}
	phase := "cleanup_pending"
	if task.State == "cancelling" {
		phase = "cancelling"
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
			_ = r.Repository.MigrationRunState(finish, l, phase, object, "source_cleanup", store.NodeAudit{})
		}
		_ = r.Repository.ReleaseMigration(finish, l)
	}()
	w, e := r.Repository.MigrationWork(ctx, id)
	if e != nil {
		return e
	}
	if w.Task.State != "cleanup_pending" && w.Task.State != "cancelling" || w.Plan.Catalog.Source.RelationshipID == nil || w.Plan.Catalog.Target.RelationshipID == nil {
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
	peerState := "queued"
	if phase == "cancelling" {
		peerState = "cancelling"
	}
	refresh := func() error {
		for _, rel := range []store.Relationship{source, target} {
			if _, e := r.request(ctx, rel, prefix+"register", map[string]any{"header": h, "lease": l, "state": peerState}); e != nil {
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
			if phase == "cancelling" {
				continue
			}
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
	// The source checkpoint is durable; private target-anchor retirement can
	// resume independently after a lost reply or a Master restart.
	w, e = r.Repository.MigrationWork(ctx, id)
	if e != nil {
		return e
	}
	for _, cp := range w.Objects {
		finished := false
		for _, unit := range w.Units {
			if unit.ID == cp.UnitID && unit.State == "cleaned" {
				finished = true
			}
		}
		if finished {
			continue
		}
		if cp.State != "cleaned" {
			continue
		}
		proof, e := r.FreshTargetProof(ctx, l, cp.Object.ID)
		if e != nil {
			return e
		}
		grant, e := r.Repository.AuthorizeMigrationAnchorRetirement(ctx, l, cp.Object.ID, proof)
		if e != nil {
			return e
		}
		l, e = r.Repository.RenewMigration(ctx, l, time.Minute)
		if e != nil {
			return e
		}
		if e = refresh(); e != nil {
			return e
		}
		o := cp.Object
		object = o.ID
		req := migrationdata.Request{Lease: l, CleanupGrant: &grant, Spec: migrationdata.Spec{TaskID: id, MasterID: w.Task.MasterID, SourceID: w.Task.SourceID, TargetID: w.Task.TargetID, LogicalID: o.ID, ObjectID: o.ObjectID, Resource: o.Resource, TargetPath: o.TargetPath, SourceVersion: o.Version, Bytes: o.Bytes, SHA256: cp.SourceSHA, Encryption: o.Encryption, Recording: o.Recording}}
		deadline := time.Now().Add(30 * time.Minute)
		submitted := false
		for {
			if e = ensure(); e != nil {
				return e
			}
			req.Lease = l
			if !submitted {
				result, err := r.request(ctx, target, prefix+"data/retire", req)
				if err != nil {
					return err
				}
				submitted = result["state"] != "waiting"
			}
			value, e := r.request(ctx, target, prefix+"data/status", req)
			if e != nil {
				return e
			}
			var checkpoint migrationdata.Checkpoint
			if e = decode(value["checkpoint"], &checkpoint); e != nil {
				return e
			}
			expected, _ := store.MigrationDigest(req.Spec)
			actual, _ := store.MigrationDigest(checkpoint.Spec)
			if expected != actual || checkpoint.State != "published" || value["peer_state"] != "published" {
				return store.ErrMigrationState
			}
			if checkpoint.AnchorError != "" {
				return store.ErrMigrationState
			}
			if checkpoint.AnchorRetired && !checkpoint.AnchorRetiring {
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
	w, e = r.Repository.MigrationWork(ctx, id)
	if e != nil {
		return e
	}
	for _, unit := range w.Units {
		if unit.State == "cleaned" || phase == "cancelling" && unit.CommittedAt == 0 {
			continue
		}
		ready := true
		for _, cp := range w.Objects {
			if cp.UnitID == unit.ID && cp.State != "cleaned" {
				ready = false
			}
		}
		if !ready {
			continue
		}
		if e = ensure(); e != nil {
			return e
		}
		grant, e := r.Repository.MigrationUnitFinishGrant(ctx, l, unit.ID)
		if e != nil {
			return e
		}
		var receipts [2]store.MigrationUnitFinishReceipt
		for i, rel := range []store.Relationship{source, target} {
			if e = ensure(); e != nil {
				return e
			}
			value, e := r.request(ctx, rel, prefix+"finish-unit", map[string]any{"lease": l, "grant": grant})
			if e != nil {
				return e
			}
			if e = decode(value, &receipts[i]); e != nil {
				return e
			}
		}
		if e = r.Repository.CompleteMigrationUnitCleanup(ctx, l, receipts[0], receipts[1], store.NodeAudit{}); e != nil {
			return e
		}
	}
	w, e = r.Repository.MigrationWork(ctx, id)
	if e != nil {
		return e
	}
	allClean := true
	for _, unit := range w.Units {
		if unit.State != "cleaned" && !(phase == "cancelling" && unit.State == "cancelled") {
			allClean = false
		}
	}
	if allClean {
		if e = r.Repository.ValidateMigrationLease(ctx, l); e != nil {
			return e
		}
		l, e = r.Repository.RenewMigration(ctx, l, time.Minute)
		if e != nil {
			return e
		}
		grant, e := r.Repository.MigrationTaskFinishGrant(ctx, l)
		if phase == "cancelling" {
			grant, e = r.Repository.MigrationTaskCancelGrant(ctx, l)
		}
		if e != nil {
			return e
		}
		var receipts [2]store.MigrationTaskFinishReceipt
		for i, rel := range []store.Relationship{source, target} {
			if e = r.Repository.ValidateMigrationLease(ctx, l); e != nil {
				return e
			}
			endpoint := "finish-task"
			if phase == "cancelling" {
				endpoint = "cancel-task"
			}
			value, e := r.request(ctx, rel, prefix+endpoint, map[string]any{"lease": l, "grant": grant})
			if e != nil {
				return e
			}
			if e = decode(value, &receipts[i]); e != nil {
				return e
			}
		}
		if phase == "cancelling" {
			return r.Repository.CompleteMigrationTaskCancellation(ctx, l, receipts[0], receipts[1], store.NodeAudit{})
		}
		return r.Repository.CompleteMigrationTask(ctx, l, receipts[0], receipts[1], store.NodeAudit{})
	}
	return nil
}
