package resourcemigration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"time"
)

// FreshCancellationSourceProof hashes the whole authoritative source through
// the authenticated bounded channel. It neither caches files on Master disk nor
// treats saved inventory/SHA/HTTP status as proof of current source bytes.
func (r *Runner) FreshCancellationSourceProof(ctx context.Context, l store.MigrationLease, id string) (proof store.MigrationCleanupProof, e error) {
	if e = r.Repository.ValidateMigrationLease(ctx, l); e != nil {
		return proof, e
	}
	w, e := r.Repository.MigrationWork(ctx, l.TaskID)
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
	grant, e := r.Repository.MigrationUnitCancelGrant(ctx, l, cp.UnitID)
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
	hash := sha256.New()
	for offset := int64(0); offset < o.Bytes; {
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
		req.Offset = offset
		req.Length = int(min(int64(migrationdata.ChunkBytes), o.Bytes-offset))
		response, e := r.request(ctx, source, prefix+"data/cancel-read", req)
		if e != nil {
			return proof, e
		}
		var chunk struct {
			Data    []byte `json:"data"`
			Offset  int64  `json:"offset"`
			Size    int    `json:"size_bytes"`
			SHA     string `json:"chunk_sha256"`
			Version string `json:"source_version"`
		}
		if e = decode(response, &chunk); e != nil {
			return proof, e
		}
		sha := sha256.Sum256(chunk.Data)
		if chunk.Offset != offset || chunk.Size != req.Length || len(chunk.Data) != req.Length || chunk.Version != o.Version || chunk.SHA != hex.EncodeToString(sha[:]) {
			return proof, store.ErrMigrationState
		}
		_, _ = hash.Write(chunk.Data)
		offset += int64(len(chunk.Data))
	}
	if hex.EncodeToString(hash.Sum(nil)) != cp.SourceSHA {
		return proof, store.ErrMigrationState
	}
	if e = r.Repository.ValidateMigrationLease(ctx, l); e != nil {
		return proof, e
	}
	// Recheck the still-uncommitted authoritative unit after the last byte.
	if _, e = r.Repository.MigrationUnitCancelGrant(ctx, l, cp.UnitID); e != nil {
		return proof, e
	}
	return store.MigrationCleanupProof{MigrationDiskProof: store.MigrationDiskProof{ID: id, Version: o.Version, Bytes: o.Bytes, SHA256: cp.SourceSHA}, VerifiedAt: time.Now().Unix()}, nil
}
