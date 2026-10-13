package resourcemigration

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"time"
)

// FreshCancellationSourceProof requests a fresh source-local byte scan. Master
// receives only the exact version-bound proof, never the authoritative bytes.
// A new observation ID prevents reuse of a prior scan as cancellation authority.
func (r *Runner) FreshCancellationSourceProof(ctx context.Context, l store.MigrationLease, id string) (proof store.MigrationCleanupProof, e error) {
	if e = r.Repository.ValidateMigrationLease(ctx, l); e != nil {
		return proof, e
	}
	w, e := r.objectWork(ctx, l.TaskID, id)
	if e != nil {
		return proof, e
	}
	if w.Task.State != "cancelling" || w.Plan.Catalog.Source.RelationshipID == nil || w.Plan.Catalog.Target.RelationshipID == nil {
		return proof, store.ErrMigrationState
	}
	var cp *store.MigrationCheckpoint
	for i := range w.Objects {
		if w.Objects[i].Object.ID == id {
			cp = &w.Objects[i]
			break
		}
	}
	if cp == nil || cp.State == "cancelled" {
		return proof, store.ErrMigrationState
	}
	grant, e := r.cancellationObjectGrant(ctx, l, id, cp.UnitID)
	if e != nil {
		return proof, e
	}
	source, e := r.Nodes.Relationship(ctx, *w.Plan.Catalog.Source.RelationshipID)
	if e != nil {
		return proof, e
	}
	if source.PeerID != w.Task.SourceID || source.State != "active" || source.Direction != "downstream" {
		return proof, store.ErrMigrationState
	}
	refresh := func() error {
		_, e := r.request(ctx, source, prefix+"register", map[string]any{"header": grant.Header, "lease": l, "state": "cancelling"})
		return e
	}
	if e = refresh(); e != nil {
		return proof, e
	}
	o := cp.Object
	req := migrationdata.Request{Lease: l, Spec: migrationdata.Spec{TaskID: l.TaskID, MasterID: w.Task.MasterID, SourceID: w.Task.SourceID, TargetID: w.Task.TargetID, LogicalID: o.ID, ObjectID: o.ObjectID, Resource: o.Resource, TargetPath: o.TargetPath, SourceVersion: o.Version, Bytes: o.Bytes, SHA256: cp.SourceSHA, Encryption: o.Encryption, Recording: o.Recording}}
	req.RecheckID, e = planToken()
	if e != nil {
		return proof, e
	}
	started := time.Now().Unix()
	for {
		if e = r.Repository.ValidateMigrationLease(ctx, l); e != nil {
			return proof, e
		}
		if time.Now().Unix() >= l.ExpiresAt-40 {
			l, e = r.Repository.RenewMigration(ctx, l, time.Minute)
			if e != nil {
				return proof, e
			}
			if e = refresh(); e != nil {
				return proof, e
			}
		}
		req.Lease = l
		response, err := r.request(ctx, source, prefix+"data/source-proof", req)
		if err != nil {
			return proof, err
		}
		var result struct {
			State     string                       `json:"state"`
			RecheckID string                       `json:"recheck_id"`
			Proof     *store.MigrationCleanupProof `json:"proof"`
		}
		if e = decode(response, &result); e != nil {
			return proof, e
		}
		if result.RecheckID != req.RecheckID {
			return proof, store.ErrMigrationState
		}
		if result.State == "verified" {
			if result.Proof == nil || result.Proof.ID != id || result.Proof.Version != o.Version || result.Proof.Bytes != o.Bytes || result.Proof.SHA256 != cp.SourceSHA || result.Proof.VerifiedAt < started || result.Proof.VerifiedAt > time.Now().Unix() {
				return proof, store.ErrMigrationState
			}
			proof = *result.Proof
			break
		}
		if result.State != "waiting" && result.State != "running" && result.State != "waiting_traffic" {
			return proof, store.ErrMigrationState
		}
		if result.Proof != nil {
			return proof, store.ErrMigrationState
		}
		if e = delay(ctx); e != nil {
			return proof, e
		}
	}
	if e = r.Repository.ValidateMigrationLease(ctx, l); e != nil {
		return proof, e
	}
	// Recheck the still-uncommitted authoritative unit after the last byte.
	if _, e = r.cancellationObjectGrant(ctx, l, id, cp.UnitID); e != nil {
		return proof, e
	}
	return proof, nil
}

func (r *Runner) cancellationObjectGrant(ctx context.Context, l store.MigrationLease, id, unit string) (store.MigrationUnitFinishGrant, error) {
	if repo, ok := r.Repository.(store.MigrationCancellationObjectRepository); ok {
		return repo.MigrationCancellationObjectGrant(ctx, l, id)
	}
	return r.Repository.MigrationUnitCancelGrant(ctx, l, unit)
}
