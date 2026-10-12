package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recording"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type migrationDataRequest struct {
	Lease  store.MigrationLease `json:"lease"`
	Spec   migrationdata.Spec   `json:"binding"`
	Offset int64                `json:"offset"`
	Length int                  `json:"length"`
	Data   []byte               `json:"data,omitempty"`
	SHA    string               `json:"chunk_sha256,omitempty"`
}
type migrationVerifyJob struct {
	request      migrationDataRequest
	relationship string
	receiver     *migrationdata.Receiver
}

func migrationRequestMatches(v migrationDataRequest, p store.MigrationPeerObject) bool {
	s, h, o := v.Spec, p.Header, p.Object
	return s.TaskID == v.Lease.TaskID && s.TaskID == h.TaskID && s.MasterID == h.MasterID && s.SourceID == h.SourceID && s.TargetID == h.TargetID && s.LogicalID == o.ID && s.ObjectID == o.ObjectID && s.Resource == o.Resource && s.SourceVersion == o.Version && s.Bytes == o.Bytes && s.SHA256 == p.Proof.SHA256 && (s.TargetPath == o.Path || s.Resource == "recording" && strings.HasPrefix(o.Path, h.SourceRelationship+"/") && s.TargetPath == h.TargetRelationship+strings.TrimPrefix(o.Path, h.SourceRelationship))
}

// One joined local verification worker scans disk outside HTTP request timeouts
// and SQL/global mutation locks. Transfer messages remain within control limits;
// Master relays one bounded chunk instead of buffering whole files on disk.
func RegisterNodeMigrationData(router *gin.Engine, settings config.Config, resolver *network.Resolver, control *node.Service, volume *media.Service, recordings *recording.Storage, repo store.MigrationPeerRepository) func() error {
	if repo == nil {
		return func() error { return nil }
	}
	ctx, cancel := context.WithCancel(context.Background())
	jobs := make(chan migrationVerifyJob, 1)
	var workers sync.WaitGroup
	var mutex sync.Mutex
	active := map[string]bool{}
	dataSlots := make(chan struct{}, 2)
	var pace sync.Mutex
	var next time.Time
	paceBytes := func(ctx context.Context, size int) error {
		pace.Lock()
		now := time.Now()
		if next.Before(now) {
			next = now
		}
		wait := time.Until(next)
		next = next.Add(time.Duration(size) * time.Second / (8 << 20))
		pace.Unlock()
		if wait <= 0 {
			return ctx.Err()
		}
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}
	key := func(v migrationDataRequest) string { return v.Lease.TaskID + ":" + v.Spec.LogicalID }
	admission := func(ctx context.Context, rel string, v migrationDataRequest, op string) error {
		p, e := repo.AuthorizePeerMigration(ctx, rel, v.Lease, v.Spec.LogicalID, op)
		if e != nil {
			return e
		}
		if !migrationRequestMatches(v, p) {
			return store.ErrMigrationState
		}
		return nil
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case job := <-jobs:
				v := job.request
				c, e := job.receiver.Verify(ctx, v.Spec, func() error { return admission(ctx, job.relationship, v, "verify") })
				if e == nil {
					_ = repo.VerifyPeerMigrationObject(ctx, job.relationship, v.Lease, v.Spec.LogicalID, c.Offset, c.PrefixSHA)
				}
				mutex.Lock()
				delete(active, key(v))
				mutex.Unlock()
			}
		}
	}()
	register := func(operation string, action func(*gin.Context, store.Relationship, migrationDataRequest, store.MigrationPeerObject) (any, error)) {
		router.POST("/internal/v1/resource-migration/data/"+operation, func(c *gin.Context) {
			if !nodeHTTPS(c, settings, resolver) {
				return
			}
			select {
			case dataSlots <- struct{}{}:
				defer func() { <-dataSlots }()
			default:
				c.Header("Retry-After", "1")
				detail(c, 429, "Migration data concurrency limit reached")
				return
			}
			body, ok := nodeBody(c)
			if !ok {
				return
			}
			uri := c.Request.URL.EscapedPath()
			if c.Request.URL.RawQuery != "" {
				uri += "?" + c.Request.URL.RawQuery
			}
			rel, e := control.Authenticate(c.Request.Context(), c.Request.Header, c.Request.Method, uri, body, false, false)
			if e != nil {
				detail(c, 401, "Invalid migration relationship authentication")
				return
			}
			if e = control.RequireFollower(c.Request.Context(), rel); e != nil {
				detail(c, 403, "Migration data requires the active upstream Master")
				return
			}
			var v migrationDataRequest
			if controlJSON(body, &v) != nil {
				detail(c, 400, "Invalid bounded migration data request")
				return
			}
			p, e := repo.AuthorizePeerMigration(c.Request.Context(), rel.ID, v.Lease, v.Spec.LogicalID, operation)
			if e == nil && !migrationRequestMatches(v, p) {
				e = store.ErrMigrationState
			}
			var result any
			if e == nil {
				result, e = action(c, rel, v, p)
			}
			if e != nil {
				if errors.Is(e, store.ErrMigrationState) || errors.Is(e, store.ErrMigrationLease) || errors.Is(e, migrationdata.ErrState) || errors.Is(e, os.ErrNotExist) {
					detail(c, 409, "Migration bytes conflict with task, version, lease or disk state")
				} else {
					internalError(c, e)
				}
				return
			}
			c.JSON(200, result)
		})
	}
	receiver := func(ctx context.Context, s migrationdata.Spec) (*migrationdata.Receiver, error) {
		if s.Resource == "media" {
			return volume.MigrationReceiver(ctx)
		}
		if s.Resource == "recording" && recordings != nil {
			return recordings.MigrationReceiver(ctx)
		}
		return nil, store.ErrMigrationState
	}
	register("read", func(c *gin.Context, rel store.Relationship, v migrationDataRequest, p store.MigrationPeerObject) (any, error) {
		if v.Length < 1 || v.Length > migrationdata.ChunkBytes || v.Offset < 0 || v.Offset%migrationdata.ChunkBytes != 0 || v.Offset > v.Spec.Bytes-int64(v.Length) {
			return nil, store.ErrMigrationState
		}
		if e := paceBytes(c.Request.Context(), v.Length); e != nil {
			return nil, e
		}
		var data []byte
		var e error
		if v.Spec.Resource == "media" {
			data, e = volume.MigrationChunk(c.Request.Context(), p.Object.ObjectID, p.Object.Path, v.Spec.Bytes, v.Offset, v.Length)
		} else if recordings != nil {
			parts := strings.Split(p.Object.Path, "/")
			if len(parts) != 3 {
				return nil, store.ErrMigrationState
			}
			data, e = recordings.MigrationChunk(c.Request.Context(), rel.ID, parts[1], p.Object.ObjectID, v.Spec.Bytes, v.Offset, v.Length)
		} else {
			return nil, store.ErrMigrationState
		}
		if e != nil {
			return nil, e
		}
		if e = admission(c.Request.Context(), rel.ID, v, "read"); e != nil {
			return nil, e
		}
		sum := sha256.Sum256(data)
		return gin.H{"data": data, "offset": v.Offset, "size_bytes": len(data), "chunk_sha256": hex.EncodeToString(sum[:]), "source_version": v.Spec.SourceVersion}, nil
	})
	register("begin", func(c *gin.Context, rel store.Relationship, v migrationDataRequest, p store.MigrationPeerObject) (any, error) {
		r, e := receiver(c.Request.Context(), v.Spec)
		if e != nil {
			return nil, e
		}
		cp, e := r.Status(c.Request.Context(), v.Spec)
		if errors.Is(e, os.ErrNotExist) {
			cp, e = r.Begin(c.Request.Context(), v.Spec)
		}
		return cp, e
	})
	register("status", func(c *gin.Context, rel store.Relationship, v migrationDataRequest, p store.MigrationPeerObject) (any, error) {
		r, e := receiver(c.Request.Context(), v.Spec)
		if e != nil {
			return nil, e
		}
		cp, e := r.Status(c.Request.Context(), v.Spec)
		if e != nil {
			return nil, e
		}
		return gin.H{"checkpoint": cp, "peer_state": p.State}, nil
	})
	register("append", func(c *gin.Context, rel store.Relationship, v migrationDataRequest, p store.MigrationPeerObject) (any, error) {
		if len(v.Data) < 1 || len(v.Data) > migrationdata.ChunkBytes {
			return nil, store.ErrMigrationState
		}
		if e := paceBytes(c.Request.Context(), len(v.Data)); e != nil {
			return nil, e
		}
		r, e := receiver(c.Request.Context(), v.Spec)
		if e != nil {
			return nil, e
		}
		return r.AppendAdmitted(c.Request.Context(), v.Spec, v.Offset, v.Data, v.SHA, func() error { return admission(c.Request.Context(), rel.ID, v, "append") })
	})
	register("verify", func(c *gin.Context, rel store.Relationship, v migrationDataRequest, p store.MigrationPeerObject) (any, error) {
		r, e := receiver(c.Request.Context(), v.Spec)
		if e != nil {
			return nil, e
		}
		cp, e := r.Status(c.Request.Context(), v.Spec)
		if e != nil {
			return nil, e
		}
		if cp.State != "received" && cp.State != "verified" {
			return nil, store.ErrMigrationState
		}
		mutex.Lock()
		defer mutex.Unlock()
		if active[key(v)] {
			return gin.H{"status": "verifying"}, nil
		}
		select {
		case jobs <- migrationVerifyJob{v, rel.ID, r}:
			active[key(v)] = true
			return gin.H{"status": "verifying"}, nil
		default:
			return gin.H{"status": "waiting"}, nil
		}
	})
	register("abort", func(c *gin.Context, rel store.Relationship, v migrationDataRequest, p store.MigrationPeerObject) (any, error) {
		r, e := receiver(c.Request.Context(), v.Spec)
		if e != nil {
			return nil, e
		}
		return r.Abort(c.Request.Context(), v.Spec, func() error { return admission(c.Request.Context(), rel.ID, v, "abort") })
	})
	var once sync.Once
	return func() error { once.Do(func() { cancel(); workers.Wait() }); return nil }
}
