// Package resourcemigration coordinates durable Master tasks through existing
// authenticated node calls. It never caches whole files or owns a SQL handle.
package resourcemigration

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/businesstraffic"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"sync"
	"time"
)

type Caller interface {
	Call(context.Context, store.Relationship, string, any) (map[string]any, error)
}
type Runner struct {
	Repository     store.MigrationRepository
	Nodes          store.NodeRepository
	Client         Caller
	Traffic        *businesstraffic.Monitor
	executionMutex sync.RWMutex
	execution      *store.MigrationExecution
}

const prefix = "/internal/v1/resource-migration/"

func decode(value any, out any) error {
	raw, e := json.Marshal(value)
	if e != nil {
		return e
	}
	return json.Unmarshal(raw, out)
}
func delay(ctx context.Context) error {
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Run executes one stored task under its monotonic SQL lease. On restart the
// peer's persisted offset/hash and publication receipt determine the next step.
// Source removal and cancellation reconciliation are distinct later phases.
func (r *Runner) Run(ctx context.Context, id, runner string) (err error) {
	task, e := r.Repository.MigrationTask(ctx, id)
	if e != nil {
		return e
	}
	if task.State == "cleanup_pending" {
		return r.cleanup(ctx, id, runner)
	}
	if task.State == "completed" || task.State == "cancelled" {
		return nil
	}
	if task.State == "cancelling" {
		return r.cancelTask(ctx, id, runner)
	}
	lease, e := r.Repository.ClaimMigration(ctx, id, runner, time.Minute)
	if e != nil {
		return e
	}
	defer func() {
		release, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = r.Repository.ReleaseMigration(release, lease)
	}()
	var source, target store.Relationship
	object, code := "", "peer_conflict"
	defer func() {
		if err == nil || ctx.Err() != nil || errors.Is(err, store.ErrMigrationLease) {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if r.Repository.MigrationRunState(cleanup, lease, "failed", object, code, store.NodeAudit{}) == nil {
			for _, rel := range []store.Relationship{source, target} {
				if rel.ID != "" {
					_, _ = r.request(cleanup, rel, prefix+"fence", map[string]any{"task_id": id, "epoch": lease.Epoch, "state": "paused"})
				}
			}
		}
	}()
	w, e := r.header(ctx, id)
	if e != nil {
		return e
	}
	if w.Task.State == "cancelling" {
		return store.ErrMigrationState
	}
	if w.Plan.Catalog.Source.RelationshipID == nil || w.Plan.Catalog.Target.RelationshipID == nil {
		return store.ErrMigrationState
	}
	source, e = r.Nodes.Relationship(ctx, *w.Plan.Catalog.Source.RelationshipID)
	if e != nil {
		return e
	}
	target, e = r.Nodes.Relationship(ctx, *w.Plan.Catalog.Target.RelationshipID)
	if e != nil {
		return e
	}
	if source.PeerID != w.Task.SourceID || target.PeerID != w.Task.TargetID || source.State != "active" || target.State != "active" || source.Direction != "downstream" || target.Direction != "downstream" {
		return store.ErrMigrationState
	}
	h := store.MigrationPeerHeader{Format: "frontiercloud-peer-migration", Version: 1, TaskID: id, MasterID: w.Task.MasterID, SourceID: w.Task.SourceID, TargetID: w.Task.TargetID, SourceRelationship: source.ID, TargetRelationship: target.ID, PlanSHA: w.Task.PlanSHA, ObjectCount: w.Task.ObjectCount, Bytes: w.Task.TotalBytes}
	code = "peer_transport"
	register := func() error {
		for _, rel := range []store.Relationship{source, target} {
			if _, e := r.request(ctx, rel, prefix+"register", map[string]any{"header": h, "lease": lease, "state": "queued"}); e != nil {
				return e
			}
		}
		return nil
	}
	ensure := func() error {
		// Current task state/epoch are checked even before the renewal threshold.
		if e := r.Repository.ValidateMigrationLease(ctx, lease); e != nil {
			return e
		}
		if time.Now().Unix() < lease.ExpiresAt-40 {
			return ctx.Err()
		}
		lease, e = r.Repository.RenewMigration(ctx, lease, time.Minute)
		if e != nil {
			return e
		}
		return register()
	}
	if e = register(); e != nil {
		return e
	}
	scheduler := trafficSchedule{runner: r, source: source, target: target, task: id, master: w.Task.MasterID}
	waitTraffic := func(phase, object string) error { return scheduler.wait(ctx, &lease, phase, object, ensure) }
	if e = waitTraffic(w.Task.State, ""); e != nil {
		return e
	}
	for c, pageErr := range r.objects(ctx, id, "") {
		if pageErr != nil {
			return pageErr
		}
		object = c.Object.ID
		if e = waitTraffic(w.Task.State, object); e != nil {
			return e
		}
		if e = ensure(); e != nil {
			return e
		}
		p := store.MigrationPeerObject{Object: c.Object, Proof: store.MigrationDiskProof{ID: object, Version: c.Object.Version, Bytes: c.Object.Bytes, SHA256: c.SourceSHA}}
		for _, rel := range []store.Relationship{source, target} {
			if _, e = r.request(ctx, rel, prefix+"object", map[string]any{"lease": lease, "object": p}); e != nil {
				return e
			}
		}
	}
	call := func(rel store.Relationship, op string, req *migrationdata.Request) (map[string]any, error) {
		for {
			if e := ensure(); e != nil {
				return nil, e
			}
			req.Lease = lease
			value, err := r.request(ctx, rel, prefix+"data/"+op, *req)
			if err != nil || value["waiting_traffic"] != true {
				return value, err
			}
			phase := "copying"
			if op == "verify" {
				phase = "verifying"
			}
			if op == "publish" {
				phase = "committing"
			}
			if err = scheduler.markWait(ctx, lease, phase, req.Spec.LogicalID, rel.PeerID); err != nil {
				return nil, err
			}
			scheduler.expires = time.Time{}
			if err = waitTraffic(phase, req.Spec.LogicalID); err != nil {
				return nil, err
			}
		}
	}
	status := func(req *migrationdata.Request) (migrationdata.Checkpoint, string, error) {
		v, e := call(target, "status", req)
		if e != nil {
			return migrationdata.Checkpoint{}, "", e
		}
		var cp migrationdata.Checkpoint
		if e = decode(v["checkpoint"], &cp); e != nil {
			return cp, "", e
		}
		phase, _ := v["peer_state"].(string)
		expected, _ := store.MigrationDigest(req.Spec)
		actual, _ := store.MigrationDigest(cp.Spec)
		if expected != actual || cp.Offset < 0 || cp.Offset > req.Spec.Bytes {
			return cp, phase, store.ErrMigrationState
		}
		return cp, phase, nil
	}
	for unit, pageErr := range r.units(ctx, id) {
		if pageErr != nil {
			return pageErr
		}
		if unit.State == "cleanup_pending" || unit.State == "cleaned" || unit.State == "committed" {
			continue
		}
		for c, pageErr := range r.objects(ctx, id, unit.ID) {
			if pageErr != nil {
				return pageErr
			}
			if c.UnitID != unit.ID {
				continue
			}
			object = c.Object.ID
			code = "peer_transport"
			if e = r.Repository.MigrationRunState(ctx, lease, "copying", object, "", store.NodeAudit{}); e != nil {
				return e
			}
			o := c.Object
			req := migrationdata.Request{Spec: migrationdata.Spec{TaskID: id, MasterID: h.MasterID, SourceID: h.SourceID, TargetID: h.TargetID, LogicalID: o.ID, ObjectID: o.ObjectID, Resource: o.Resource, TargetPath: o.TargetPath, SourceVersion: o.Version, Bytes: o.Bytes, SHA256: c.SourceSHA, Encryption: o.Encryption, Recording: o.Recording}}
			if _, e = call(target, "begin", &req); e != nil {
				return e
			}
			cp, phase, e := status(&req)
			if e != nil {
				return e
			}
			var grantLease store.MigrationLease
			r.progress(id, "copying", object, cp.Offset, o.Bytes)
			for cp.Offset < o.Bytes {
				if cp.State != "receiving" || cp.Offset%migrationdata.ChunkBytes != 0 {
					return store.ErrMigrationState
				}
				if e = waitTraffic("copying", object); e != nil {
					return e
				}
				req.Offset = cp.Offset
				req.Length = int(min(int64(migrationdata.ChunkBytes), o.Bytes-cp.Offset))
				req.Lease = lease
				if req.TransferGrant == nil || grantLease != lease {
					grantRequest := req
					grantRequest.TransferGrant = nil
					grantRequest.SourcePublicKey = ""
					grantRequest.SourceEndpoint = ""
					grantRequest.TargetPublicKey = target.PublicKey
					value, err := r.request(ctx, source, prefix+"data/delegate", grantRequest)
					if err != nil {
						return err
					}
					var grant migrationdata.Signed
					if e = decode(value, &grant); e != nil {
						return e
					}
					req.TransferGrant = &grant
					grantLease = lease
				}
				req.SourcePublicKey = source.PublicKey
				req.SourceEndpoint = source.Endpoint
				code = "direct_peer_transfer"
				value, e := r.request(ctx, target, prefix+"data/pull", req)
				if e != nil {
					return e
				}
				if value["waiting_traffic"] == true {
					var waiting struct {
						Checkpoint migrationdata.Checkpoint `json:"checkpoint"`
						NodeID     string                   `json:"waiting_node_id"`
						Traffic    businesstraffic.View     `json:"traffic"`
					}
					if e = decode(value, &waiting); e != nil || waiting.Checkpoint.Offset != req.Offset || waiting.NodeID != h.SourceID && waiting.NodeID != h.TargetID {
						return store.ErrMigrationState
					}
					if e = scheduler.observePeerWait(waiting.NodeID, waiting.Traffic); e != nil {
						return e
					}
					if e = scheduler.markWait(ctx, lease, "copying", object, waiting.NodeID); e != nil {
						return e
					}
					scheduler.expires = time.Time{}
					if e = trafficDelay(ctx); e != nil {
						return e
					}
					continue
				}
				if e = decode(value, &cp); e != nil {
					return e
				}
				expected, _ := store.MigrationDigest(req.Spec)
				actual, _ := store.MigrationDigest(cp.Spec)
				if expected != actual || cp.Offset != req.Offset+int64(req.Length) {
					return store.ErrMigrationState
				}
				r.progress(id, "copying", object, cp.Offset, o.Bytes)
			}
			code = "target_verification"
			if e = r.Repository.MigrationRunState(ctx, lease, "verifying", object, "", store.NodeAudit{}); e != nil {
				return e
			}
			deadline := time.Now().Add(30 * time.Minute)
			waitingAtStart := scheduler.waited
			for phase != "verified" && phase != "published" {
				if e = waitTraffic("verifying", object); e != nil {
					return e
				}
				if cp.State != "received" && cp.State != "verified" {
					return store.ErrMigrationState
				}
				if _, e = call(target, "verify", &req); e != nil {
					return e
				}
				if e = delay(ctx); e != nil {
					return e
				}
				cp, phase, e = status(&req)
				if e != nil {
					return e
				}
				if time.Now().After(deadline.Add(scheduler.waited - waitingAtStart)) {
					return context.DeadlineExceeded
				}
			}
			if cp.Offset != o.Bytes || cp.PrefixSHA != c.SourceSHA || (cp.State != "verified" && cp.State != "publishing" && cp.State != "published") {
				return store.ErrMigrationState
			}
			if e = r.Repository.VerifyMigrationObject(ctx, lease, object, o.Bytes, c.SourceSHA); e != nil {
				return e
			}
		}
		code = "unit_commit"
		if e = waitTraffic("verifying", ""); e != nil {
			return e
		}
		if e = r.Repository.PrepareMigrationPublication(ctx, lease, unit.ID); e != nil {
			return e
		}
		if e = r.Repository.MigrationRunState(ctx, lease, "committing", "", "", store.NodeAudit{}); e != nil {
			return e
		}
		for c, pageErr := range r.objects(ctx, id, unit.ID) {
			if pageErr != nil {
				return pageErr
			}
			if c.UnitID != unit.ID {
				continue
			}
			object = c.Object.ID
			code = "target_publication"
			o := c.Object
			req := migrationdata.Request{Spec: migrationdata.Spec{TaskID: id, MasterID: h.MasterID, SourceID: h.SourceID, TargetID: h.TargetID, LogicalID: o.ID, ObjectID: o.ObjectID, Resource: o.Resource, TargetPath: o.TargetPath, SourceVersion: o.Version, Bytes: o.Bytes, SHA256: c.SourceSHA, Encryption: o.Encryption, Recording: o.Recording}}
			deadline := time.Now().Add(30 * time.Minute)
			waitingAtStart := scheduler.waited
			for {
				if e = waitTraffic("committing", object); e != nil {
					return e
				}
				cp, phase, e := status(&req)
				if e != nil {
					return e
				}
				if phase == "published" && cp.State == "published" && cp.Offset == o.Bytes && cp.PrefixSHA == c.SourceSHA {
					break
				}
				if _, e = call(target, "publish", &req); e != nil {
					return e
				}
				if e = delay(ctx); e != nil {
					return e
				}
				if time.Now().After(deadline.Add(scheduler.waited - waitingAtStart)) {
					return context.DeadlineExceeded
				}
			}
			if e = r.Repository.PublishMigrationObject(ctx, lease, object); e != nil {
				return e
			}
		}
		code = "unit_commit"
		object = ""
		if e = ensure(); e != nil {
			return e
		}
		if e = r.Repository.CommitMigrationUnit(ctx, lease, unit.ID, store.NodeAudit{}); e != nil {
			return e
		}
	}
	return r.Repository.MigrationRunState(ctx, lease, "cleanup_pending", "", "", store.NodeAudit{})
}

func (r *Runner) request(ctx context.Context, rel store.Relationship, path string, value any) (map[string]any, error) {
	raw, e := json.Marshal(value)
	if e != nil {
		return nil, e
	}
	body, e := protocol.ParseStrictJSON(raw, 512<<10)
	if e != nil {
		return nil, e
	}
	return r.Client.Call(ctx, rel, path, body)
}
