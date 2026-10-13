package resourcemigration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"time"
)

// FreshTargetProof accepts only the persisted task/object, creates a new request
// ID and awaits that exact authenticated target receipt. Administrator-supplied
// SHA/time values and an old published checkpoint are never accepted here.
func (r *Runner) FreshTargetProof(ctx context.Context, l store.MigrationLease, id string) (proof store.MigrationCleanupProof, e error) {
	if e = r.Repository.ValidateMigrationLease(ctx, l); e != nil {
		return proof, e
	}
	w, e := r.objectWork(ctx, l.TaskID, id)
	if e != nil {
		return proof, e
	}
	var checkpoint *store.MigrationCheckpoint
	for i := range w.Objects {
		if w.Objects[i].Object.ID == id {
			checkpoint = &w.Objects[i]
			break
		}
	}
	if checkpoint == nil || checkpoint.State != "cleanup_pending" && checkpoint.State != "cleaned" || w.Plan.Catalog.Target.RelationshipID == nil || w.Plan.Catalog.Source.RelationshipID == nil {
		return proof, store.ErrMigrationState
	}
	o := checkpoint.Object
	target, e := r.Nodes.Relationship(ctx, *w.Plan.Catalog.Target.RelationshipID)
	if e != nil {
		return proof, e
	}
	if target.PeerID != w.Task.TargetID || target.State != "active" || target.Direction != "downstream" {
		return proof, store.ErrMigrationState
	}
	raw := make([]byte, 16)
	if _, e = rand.Read(raw); e != nil {
		return proof, e
	}
	requestID := hex.EncodeToString(raw)
	req := migrationdata.Request{Lease: l, RecheckID: requestID, Spec: migrationdata.Spec{TaskID: l.TaskID, MasterID: w.Task.MasterID, SourceID: w.Task.SourceID, TargetID: w.Task.TargetID, LogicalID: o.ID, ObjectID: o.ObjectID, Resource: o.Resource, TargetPath: o.TargetPath, SourceVersion: o.Version, Bytes: o.Bytes, SHA256: checkpoint.SourceSHA, Encryption: o.Encryption, Recording: o.Recording}}
	source, e := r.Nodes.Relationship(ctx, *w.Plan.Catalog.Source.RelationshipID)
	if e != nil {
		return proof, e
	}
	if source.PeerID != w.Task.SourceID || source.State != "active" || source.Direction != "downstream" {
		return proof, store.ErrMigrationState
	}
	h := store.MigrationPeerHeader{Format: "frontiercloud-peer-migration", Version: 1, TaskID: l.TaskID, MasterID: w.Task.MasterID, SourceID: w.Task.SourceID, TargetID: w.Task.TargetID, SourceRelationship: source.ID, TargetRelationship: target.ID, PlanSHA: w.Task.PlanSHA, ObjectCount: w.Task.ObjectCount, Bytes: w.Task.TotalBytes}
	peerState := "queued"
	if w.Task.State == "cancelling" {
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
	if e = refresh(); e != nil {
		return proof, e
	}
	started := time.Now().Unix()
	deadline := time.Now().Add(30 * time.Minute)
	scheduler := trafficSchedule{runner: r, source: source, target: target, task: l.TaskID, master: w.Task.MasterID}
	ensure := func() error {
		if err := r.Repository.ValidateMigrationLease(ctx, l); err != nil {
			return err
		}
		if time.Now().Unix() >= l.ExpiresAt-40 {
			var err error
			l, err = r.Repository.RenewMigration(ctx, l, time.Minute)
			if err != nil {
				return err
			}
			req.Lease = l
			return refresh()
		}
		return ctx.Err()
	}
	for {
		if e = scheduler.wait(ctx, &l, w.Task.State, id, ensure); e != nil {
			return proof, e
		}
		if e = r.Repository.ValidateMigrationLease(ctx, l); e != nil {
			return proof, e
		}
		if time.Now().Unix() >= l.ExpiresAt-40 {
			l, e = r.Repository.RenewMigration(ctx, l, time.Minute)
			if e != nil {
				return proof, e
			}
			req.Lease = l
			if e = refresh(); e != nil {
				return proof, e
			}
		}
		if _, e = r.request(ctx, target, prefix+"data/recheck", req); e != nil {
			return proof, e
		}
		value, e := r.request(ctx, target, prefix+"data/status", req)
		if e != nil {
			return proof, e
		}
		var cp migrationdata.Checkpoint
		if e = decode(value["checkpoint"], &cp); e != nil {
			return proof, e
		}
		expected, _ := store.MigrationDigest(req.Spec)
		actual, _ := store.MigrationDigest(cp.Spec)
		if cp.RecheckID == requestID {
			if cp.RecheckError != "" || expected != actual || value["peer_state"] != "published" || cp.State != "published" || cp.Offset != o.Bytes || cp.PrefixSHA != checkpoint.SourceSHA || cp.RecheckedAt < started || cp.RecheckedAt < time.Now().Unix()-30 || cp.RecheckedAt > time.Now().Unix()+30 {
				return proof, store.ErrMigrationState
			}
			return store.MigrationCleanupProof{MigrationDiskProof: store.MigrationDiskProof{ID: id, Version: o.Version, Bytes: o.Bytes, SHA256: checkpoint.SourceSHA}, VerifiedAt: cp.RecheckedAt}, nil
		}
		if time.Now().After(deadline.Add(scheduler.waited)) {
			return proof, context.DeadlineExceeded
		}
		if e = delay(ctx); e != nil {
			return proof, e
		}
	}
}
