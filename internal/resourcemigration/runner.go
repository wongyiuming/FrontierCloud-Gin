// Package resourcemigration coordinates durable Master tasks through existing
// authenticated node calls. It never caches whole files or owns a SQL handle.
package resourcemigration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"time"
)

type Caller interface {
	Call(context.Context, store.Relationship, string, any) (map[string]any, error)
}
type Runner struct {
	Repository store.MigrationRepository
	Nodes      store.NodeRepository
	Client     Caller
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
	w, e := r.Repository.MigrationWork(ctx, id)
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
	for _, c := range w.Objects {
		object = c.Object.ID
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
		if e := ensure(); e != nil {
			return nil, e
		}
		req.Lease = lease
		return r.request(ctx, rel, prefix+"data/"+op, *req)
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
	for _, unit := range w.Units {
		if unit.State == "cleanup_pending" || unit.State == "cleaned" || unit.State == "committed" {
			continue
		}
		for _, c := range w.Objects {
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
			for cp.Offset < o.Bytes {
				if cp.State != "receiving" || cp.Offset%migrationdata.ChunkBytes != 0 {
					return store.ErrMigrationState
				}
				req.Offset = cp.Offset
				req.Length = int(min(int64(migrationdata.ChunkBytes), o.Bytes-cp.Offset))
				value, e := call(source, "read", &req)
				if e != nil {
					return e
				}
				var chunk struct {
					Data    []byte `json:"data"`
					Offset  int64  `json:"offset"`
					Size    int    `json:"size_bytes"`
					SHA     string `json:"chunk_sha256"`
					Version string `json:"source_version"`
				}
				if e = decode(value, &chunk); e != nil {
					return e
				}
				sum := sha256.Sum256(chunk.Data)
				if len(chunk.Data) != req.Length || chunk.Size != req.Length || chunk.Offset != req.Offset || chunk.Version != o.Version || hex.EncodeToString(sum[:]) != chunk.SHA {
					return store.ErrMigrationState
				}
				req.Data = chunk.Data
				req.SHA = chunk.SHA
				value, e = call(target, "append", &req)
				req.Data = nil
				req.SHA = ""
				if e != nil {
					return e
				}
				if e = decode(value, &cp); e != nil {
					return e
				}
				if cp.Offset != req.Offset+int64(req.Length) {
					return store.ErrMigrationState
				}
			}
			code = "target_verification"
			if e = r.Repository.MigrationRunState(ctx, lease, "verifying", object, "", store.NodeAudit{}); e != nil {
				return e
			}
			deadline := time.Now().Add(30 * time.Minute)
			for phase != "verified" && phase != "published" {
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
				if time.Now().After(deadline) {
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
		if e = r.Repository.PrepareMigrationPublication(ctx, lease, unit.ID); e != nil {
			return e
		}
		if e = r.Repository.MigrationRunState(ctx, lease, "committing", "", "", store.NodeAudit{}); e != nil {
			return e
		}
		for _, c := range w.Objects {
			if c.UnitID != unit.ID {
				continue
			}
			object = c.Object.ID
			code = "target_publication"
			o := c.Object
			req := migrationdata.Request{Spec: migrationdata.Spec{TaskID: id, MasterID: h.MasterID, SourceID: h.SourceID, TargetID: h.TargetID, LogicalID: o.ID, ObjectID: o.ObjectID, Resource: o.Resource, TargetPath: o.TargetPath, SourceVersion: o.Version, Bytes: o.Bytes, SHA256: c.SourceSHA, Encryption: o.Encryption, Recording: o.Recording}}
			deadline := time.Now().Add(30 * time.Minute)
			for {
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
				if time.Now().After(deadline) {
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
