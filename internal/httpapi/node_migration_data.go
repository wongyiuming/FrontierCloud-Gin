package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/businesstraffic"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recording"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type migrationDataRequest = migrationdata.Request

type migrationVerifyJob struct {
	request      migrationDataRequest
	relationship string
	receiver     *migrationdata.Receiver
	operation    string
}

func migrationRequestMatches(v migrationDataRequest, p store.MigrationPeerObject) bool {
	s, h, o := v.Spec, p.Header, p.Object
	return s.TaskID == v.Lease.TaskID && s.TaskID == h.TaskID && s.MasterID == h.MasterID && s.SourceID == h.SourceID && s.TargetID == h.TargetID && s.LogicalID == o.ID && s.ObjectID == o.ObjectID && s.Resource == o.Resource && s.SourceVersion == o.Version && s.Bytes == o.Bytes && s.SHA256 == p.Proof.SHA256 && reflect.DeepEqual(s.Encryption, o.Encryption) && reflect.DeepEqual(s.Recording, o.Recording) && (s.TargetPath == o.Path || s.Resource == "recording" && strings.HasPrefix(o.Path, h.SourceRelationship+"/") && s.TargetPath == h.TargetRelationship+strings.TrimPrefix(o.Path, h.SourceRelationship))
}

// One joined local verification worker scans disk outside HTTP request timeouts
// and SQL/global mutation locks. Transfer messages remain within control limits;
// Migration bytes travel only from source to target. Master handles control
// metadata and checkpoints; even authenticated Master byte relay is forbidden.
func RegisterNodeMigrationData(router *gin.Engine, settings config.Config, resolver *network.Resolver, control *node.Service, volume *media.Service, recordings *recording.Storage, repo store.MigrationPeerRepository) func() error {
	if repo == nil {
		return func() error { return nil }
	}
	registerMigrationTraffic(router, settings, resolver, control)
	lowTraffic := func() error {
		if !control.BusinessTraffic().CanRun {
			return businesstraffic.ErrWait
		}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	jobs := make(chan migrationVerifyJob, 1)
	var workers sync.WaitGroup
	var mutex sync.Mutex
	active := map[string]bool{}
	dataSlots := make(chan struct{}, 2)
	var pace sync.Mutex
	var next time.Time
	type sourceProofResult struct {
		request migrationDataRequest
		state   string
		proof   *store.MigrationCleanupProof
	}
	var sourceProof *sourceProofResult // one bounded observation, joined worker
	readSource := func(ctx context.Context, rel string, v migrationDataRequest, p store.MigrationPeerObject) ([]byte, error) {
		if v.Spec.Resource == "media" {
			return volume.MigrationChunk(ctx, p.Object.ObjectID, p.Object.Path, v.Spec.Bytes, v.Offset, v.Length)
		}
		if recordings == nil {
			return nil, store.ErrMigrationState
		}
		parts := strings.Split(p.Object.Path, "/")
		if len(parts) != 3 {
			return nil, store.ErrMigrationState
		}
		return recordings.MigrationChunk(ctx, rel, parts[1], p.Object.ObjectID, v.Spec.Bytes, v.Offset, v.Length)
	}
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
				func() {
					ctx, release, e := control.ActiveFollowerWork(ctx, job.relationship)
					if e != nil {
						return
					}
					defer release()
					ctx = migrationdata.WithScanAdmission(ctx, lowTraffic)
					if job.operation == "source-proof" {
						hash := sha256.New()
						var proofErr error
						for offset := int64(0); offset < v.Spec.Bytes; {
							if e := lowTraffic(); e != nil {
								proofErr = e
								break
							}
							p, e := repo.AuthorizePeerMigration(ctx, job.relationship, v.Lease, v.Spec.LogicalID, "cancel-read")
							if e != nil || !migrationRequestMatches(v, p) {
								proofErr = store.ErrMigrationState
								break
							}
							v.Offset = offset
							v.Length = int(min(int64(migrationdata.ChunkBytes), v.Spec.Bytes-offset))
							if e = paceBytes(ctx, v.Length); e != nil {
								proofErr = e
								break
							}
							data, e := readSource(ctx, job.relationship, v, p)
							if e != nil {
								proofErr = e
								break
							}
							if e = admission(ctx, job.relationship, v, "cancel-read"); e != nil {
								proofErr = e
								break
							}
							hash.Write(data)
							offset += int64(len(data))
						}
						if proofErr == nil && hex.EncodeToString(hash.Sum(nil)) != v.Spec.SHA256 {
							proofErr = store.ErrMigrationState
						}
						if proofErr == nil {
							proofErr = admission(ctx, job.relationship, v, "cancel-read")
						}
						mutex.Lock()
						if sourceProof != nil && sourceProof.request.RecheckID == v.RecheckID && key(sourceProof.request) == key(v) {
							sourceProof.state = "failed"
							if errors.Is(proofErr, businesstraffic.ErrWait) {
								sourceProof.state = "waiting_traffic"
							}
							if proofErr == nil {
								sourceProof.state = "verified"
								sourceProof.proof = &store.MigrationCleanupProof{MigrationDiskProof: store.MigrationDiskProof{ID: v.Spec.LogicalID, Version: v.Spec.SourceVersion, Bytes: v.Spec.Bytes, SHA256: v.Spec.SHA256}, VerifiedAt: time.Now().Unix()}
							}
						}
						mutex.Unlock()
					} else if job.operation == "unpublish" {
						var e error
						if v.ShadowGrant == nil {
							e = store.ErrMigrationState
						} else if v.Spec.Resource == "recording" && recordings != nil {
							e = recordings.MigrationCancelPublication(ctx, job.relationship, v.Lease, *v.ShadowGrant, repo, store.NodeAudit{})
						} else {
							e = volume.MigrationCancelPublication(ctx, job.relationship, v.Lease, *v.ShadowGrant, repo, store.NodeAudit{})
						}
						if e != nil && ctx.Err() == nil && !errors.Is(e, businesstraffic.ErrWait) {
							_ = repo.FailPeerMigrationShadowCleanup(ctx, job.relationship, v.Lease, v.Spec.LogicalID, store.NodeAudit{})
						}
					} else if job.operation == "shadow" {
						var e error
						if v.Spec.Resource == "recording" && recordings != nil {
							e = recordings.MigrationShadowCleanupAuthorized(ctx, job.relationship, v.Lease, v.Spec.LogicalID, repo)
						} else {
							e = volume.MigrationShadowCleanupAuthorized(ctx, job.relationship, v.Lease, v.Spec.LogicalID, repo, store.NodeAudit{})
						}
						if e != nil && ctx.Err() == nil && !errors.Is(e, businesstraffic.ErrWait) {
							_ = repo.FailPeerMigrationShadowCleanup(ctx, job.relationship, v.Lease, v.Spec.LogicalID, store.NodeAudit{})
						}
					} else if job.operation == "cleanup" {
						var e error
						if v.Spec.Resource == "recording" && recordings != nil {
							e = recordings.MigrationCleanupAuthorized(ctx, job.relationship, v.Lease, v.Spec.LogicalID, repo)
						} else {
							e = volume.MigrationCleanupAuthorized(ctx, job.relationship, v.Lease, v.Spec.LogicalID, repo, store.NodeAudit{})
						}
						if e != nil && ctx.Err() == nil && !errors.Is(e, businesstraffic.ErrWait) {
							_ = repo.FailPeerMigrationCleanup(ctx, job.relationship, v.Lease, v.Spec.LogicalID, store.NodeAudit{})
						}
					} else if job.operation == "retire" {
						check := func() error {
							if v.CleanupGrant == nil {
								return store.ErrMigrationState
							}
							if e := repo.ValidatePeerAnchorRetirement(ctx, job.relationship, v.Lease, *v.CleanupGrant, false); e != nil {
								return e
							}
							return admission(ctx, job.relationship, v, "retire")
						}
						if v.Spec.Resource == "recording" && recordings != nil {
							_, _ = recordings.MigrationRetireAnchor(ctx, v.Spec, check)
						} else {
							_, _ = volume.MigrationRetireAnchor(ctx, v.Spec, check)
						}
					} else if job.operation == "recheck" {
						if v.Spec.Resource == "recording" && recordings != nil {
							_, _ = recordings.MigrationRecheck(ctx, v.Spec, v.RecheckID, func() error { return admission(ctx, job.relationship, v, "recheck") })
						} else {
							_, _ = volume.MigrationRecheck(ctx, v.Spec, v.RecheckID, func() error { return admission(ctx, job.relationship, v, "recheck") })
						}
					} else if job.operation == "publish" {
						if v.Spec.Resource == "recording" && recordings != nil {
							_, _ = recordings.MigrationPublish(ctx, v.Spec, func() error { return admission(ctx, job.relationship, v, "publish") }, func(receipt store.RecordingReceipt, free int64) error {
								return repo.CompletePeerRecordingPublication(ctx, job.relationship, v.Lease, v.Spec.LogicalID, receipt, free, store.NodeAudit{})
							})
						} else {
							_, _ = volume.MigrationPublish(ctx, v.Spec, func() error { return admission(ctx, job.relationship, v, "publish") }, func(o store.MediaObject, free int64) error {
								return repo.CompletePeerMediaPublication(ctx, job.relationship, v.Lease, v.Spec.LogicalID, o, v.Spec.Bytes, v.Spec.SHA256, free, store.NodeAudit{})
							})
						}
					} else {
						c, e := job.receiver.Verify(ctx, v.Spec, func() error { return admission(ctx, job.relationship, v, "verify") })
						if e == nil {
							_ = repo.VerifyPeerMigrationObject(ctx, job.relationship, v.Lease, v.Spec.LogicalID, c.Offset, c.PrefixSHA)
						}
					}
				}()
				mutex.Lock()
				delete(active, key(v))
				if job.operation == "source-proof" && sourceProof != nil && sourceProof.state == "running" && sourceProof.request.RecheckID == v.RecheckID {
					sourceProof.state = "failed"
				}
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
			authorizeOperation := operation
			if operation == "delegate" {
				authorizeOperation = "read"
			}
			if operation == "pull" {
				authorizeOperation = "append"
			}
			if operation == "source-proof" {
				authorizeOperation = "cancel-read"
			}
			// Initial unpublish admission needs a verified roster, before persisting
			// the cancellation fence. Status authorizes no byte or metadata mutation.
			if operation == "unpublish" && v.ShadowGrant != nil {
				authorizeOperation = "status"
			}
			p, e := repo.AuthorizePeerMigration(c.Request.Context(), rel.ID, v.Lease, v.Spec.LogicalID, authorizeOperation)
			if operation == "unpublish" && e != nil && v.ShadowGrant != nil {
				p, e = repo.AuthorizePeerMigration(c.Request.Context(), rel.ID, v.Lease, v.Spec.LogicalID, "unpublish")
			}
			if e == nil && !migrationRequestMatches(v, p) {
				e = store.ErrMigrationState
			}
			var result any
			if e == nil {
				c.Request = c.Request.WithContext(migrationdata.WithScanAdmission(c.Request.Context(), lowTraffic))
				if operation != "status" && operation != "delegate" && operation != "source-proof" && operation != "read" && operation != "append" && operation != "cancel-read" && operation != "pull" {
					e = lowTraffic()
				}
			}
			if e == nil {
				result, e = action(c, rel, v, p)
			}
			if e != nil {
				if errors.Is(e, businesstraffic.ErrWait) {
					c.JSON(200, gin.H{"waiting_traffic": true, "waiting_node_id": v.Spec.TargetID, "traffic": control.BusinessTraffic()})
				} else if errors.Is(e, node.ErrMigrationDirect) {
					detail(c, 409, "Direct storage connectivity required; migration relay is prohibited")
				} else if errors.Is(e, store.ErrMigrationState) || errors.Is(e, store.ErrMigrationLease) || errors.Is(e, migrationdata.ErrState) || errors.Is(e, node.ErrCapability) || errors.Is(e, os.ErrNotExist) {
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
	readChunk := func(operation string) func(c *gin.Context, rel store.Relationship, v migrationDataRequest, p store.MigrationPeerObject) (any, error) {
		return func(c *gin.Context, rel store.Relationship, v migrationDataRequest, p store.MigrationPeerObject) (any, error) {
			if v.Length < 1 || v.Length > migrationdata.ChunkBytes || v.Offset < 0 || v.Offset%migrationdata.ChunkBytes != 0 || v.Offset > v.Spec.Bytes-int64(v.Length) {
				return nil, store.ErrMigrationState
			}
			if e := paceBytes(c.Request.Context(), v.Length); e != nil {
				return nil, e
			}
			if e := lowTraffic(); e != nil {
				return nil, e
			}
			data, e := readSource(c.Request.Context(), rel.ID, v, p)
			if e != nil {
				return nil, e
			}
			if e = admission(c.Request.Context(), rel.ID, v, operation); e != nil {
				return nil, e
			}
			sum := sha256.Sum256(data)
			return gin.H{"data": data, "offset": v.Offset, "size_bytes": len(data), "chunk_sha256": hex.EncodeToString(sum[:]), "source_version": v.Spec.SourceVersion}, nil
		}
	}
	// Keep deterministic rejection for old callers/restarted old tasks. No
	// administrator setting or node transport type can enable these paths.
	for _, operation := range []string{"read", "cancel-read", "append"} {
		register(operation, func(*gin.Context, store.Relationship, migrationDataRequest, store.MigrationPeerObject) (any, error) {
			return nil, store.ErrMigrationState
		})
	}
	register("delegate", func(c *gin.Context, rel store.Relationship, v migrationDataRequest, p store.MigrationPeerObject) (any, error) {
		if len(v.Data) != 0 || v.SHA != "" || v.TransferGrant != nil {
			return nil, store.ErrMigrationState
		}
		return control.MigrationDelegate(c.Request.Context(), rel, v, p.Header)
	})
	register("pull", func(c *gin.Context, rel store.Relationship, v migrationDataRequest, p store.MigrationPeerObject) (any, error) {
		if v.Length < 1 || v.Length > migrationdata.ChunkBytes || v.Offset < 0 || v.Offset%migrationdata.ChunkBytes != 0 || v.Offset > v.Spec.Bytes-int64(v.Length) || len(v.Data) != 0 || v.SHA != "" {
			return nil, store.ErrMigrationState
		}
		r, e := receiver(c.Request.Context(), v.Spec)
		if e != nil {
			return nil, e
		}
		// Replayed control calls reconcile the persisted chunk and never fetch
		// completed bytes again. Receiver verifies its exact prefix on restart.
		cp, e := r.Status(c.Request.Context(), v.Spec)
		if e != nil {
			return nil, e
		}
		if cp.Offset == v.Offset+int64(v.Length) {
			return cp, nil
		}
		if cp.Offset != v.Offset {
			return nil, store.ErrMigrationState
		}
		traffic := control.BusinessTraffic()
		if !traffic.CanRun {
			return gin.H{"checkpoint": cp, "waiting_traffic": true, "waiting_node_id": v.Spec.TargetID, "traffic": traffic}, nil
		}
		chunk, e := control.MigrationPull(c.Request.Context(), rel, v, p.Header)
		if e != nil {
			return nil, e
		}
		if chunk.Waiting {
			return gin.H{"checkpoint": cp, "waiting_traffic": true, "waiting_node_id": v.Spec.SourceID, "traffic": chunk.Traffic}, nil
		}
		return r.AppendAdmitted(c.Request.Context(), v.Spec, v.Offset, chunk.Data, chunk.SHA, func() error { return admission(c.Request.Context(), rel.ID, v, "append") })
	})
	register("source-proof", func(c *gin.Context, rel store.Relationship, v migrationDataRequest, p store.MigrationPeerObject) (any, error) {
		if !migrationdata.ValidRecheckID(v.RecheckID) || len(v.Data) != 0 || v.TransferGrant != nil {
			return nil, store.ErrMigrationState
		}
		mutex.Lock()
		defer mutex.Unlock()
		if sourceProof != nil && sourceProof.request.RecheckID == v.RecheckID && key(sourceProof.request) == key(v) && sourceProof.state != "waiting_traffic" {
			if sourceProof.request.Lease.TaskID != v.Lease.TaskID || sourceProof.request.Lease.Epoch != v.Lease.Epoch || sourceProof.request.Lease.RunnerID != v.Lease.RunnerID || !reflect.DeepEqual(sourceProof.request.Spec, v.Spec) {
				return nil, store.ErrMigrationState
			}
			return gin.H{"state": sourceProof.state, "recheck_id": v.RecheckID, "proof": sourceProof.proof}, nil
		}
		if active[key(v)] || sourceProof != nil && sourceProof.state == "running" {
			return gin.H{"state": "waiting", "recheck_id": v.RecheckID}, nil
		}
		select {
		case jobs <- migrationVerifyJob{v, rel.ID, nil, "source-proof"}:
			active[key(v)] = true
			sourceProof = &sourceProofResult{request: v, state: "running"}
			return gin.H{"state": "running", "recheck_id": v.RecheckID}, nil
		default:
			return gin.H{"state": "waiting", "recheck_id": v.RecheckID}, nil
		}
	})
	router.POST(migrationdata.PeerReadRoute, func(c *gin.Context) {
		if !nodeHTTPS(c, settings, resolver) {
			return
		}
		if c.Request.URL.RawQuery != "" {
			detail(c, 400, "Invalid direct migration route")
			return
		}
		select {
		case dataSlots <- struct{}{}:
			defer func() { <-dataSlots }()
		default:
			detail(c, 429, "Migration data concurrency limit reached")
			return
		}
		body, ok := nodeBody(c)
		if !ok {
			return
		}
		var signed migrationdata.Signed
		value, e := protocol.ParseStrictJSON(body, node.MaxControlBytes)
		if e != nil || migrationDecodePeer(value, &signed) != nil {
			detail(c, 400, "Invalid direct migration proof")
			return
		}
		rel, v, nonce, e := control.AuthenticateMigrationRead(c.Request.Context(), signed)
		if e != nil {
			detail(c, 401, "Invalid direct migration identity proof")
			return
		}
		p, e := repo.AuthorizePeerMigration(c.Request.Context(), rel.ID, v.Lease, v.Spec.LogicalID, "read")
		if e != nil || !migrationRequestMatches(v, p) {
			detail(c, 409, "Direct migration task or source version changed")
			return
		}
		traffic := control.BusinessTraffic()
		if !traffic.CanRun {
			proof, e := control.MigrationSignChunk(c.Request.Context(), migrationdata.DirectChunk{Nonce: nonce, Offset: v.Offset, Version: v.Spec.SourceVersion, Waiting: true, Traffic: &traffic})
			if e != nil {
				internalError(c, e)
				return
			}
			c.JSON(200, proof)
			return
		}
		result, e := readChunk("read")(c, rel, v, p)
		if errors.Is(e, businesstraffic.ErrWait) {
			traffic := control.BusinessTraffic()
			proof, err := control.MigrationSignChunk(c.Request.Context(), migrationdata.DirectChunk{Nonce: nonce, Offset: v.Offset, Version: v.Spec.SourceVersion, Waiting: true, Traffic: &traffic})
			if err != nil {
				internalError(c, err)
				return
			}
			c.JSON(200, proof)
			return
		}
		if e != nil {
			detail(c, 409, "Direct migration source unavailable")
			return
		}
		var chunk migrationdata.DirectChunk
		if migrationDecodePeer(result, &chunk) != nil {
			detail(c, 409, "Direct migration byte proof unavailable")
			return
		}
		chunk.Nonce = nonce
		proof, e := control.MigrationSignChunk(c.Request.Context(), chunk)
		if e != nil {
			internalError(c, e)
			return
		}
		c.JSON(200, proof)
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
		mutex.Lock()
		working := active[key(v)]
		mutex.Unlock()
		r, e := receiver(c.Request.Context(), v.Spec)
		if e != nil {
			return nil, e
		}
		cp, e := r.Status(c.Request.Context(), v.Spec)
		if e != nil {
			return nil, e
		}
		return gin.H{"checkpoint": cp, "peer_state": p.State, "worker_active": working}, nil
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
		case jobs <- migrationVerifyJob{v, rel.ID, r, "verify"}:
			active[key(v)] = true
			return gin.H{"status": "verifying"}, nil
		default:
			return gin.H{"status": "waiting"}, nil
		}
	})
	register("publish", func(c *gin.Context, rel store.Relationship, v migrationDataRequest, p store.MigrationPeerObject) (any, error) {
		if v.Spec.Resource != "media" && (v.Spec.Resource != "recording" || recordings == nil || v.Spec.Recording == nil) {
			return nil, store.ErrMigrationState
		}
		r, e := receiver(c.Request.Context(), v.Spec)
		if e != nil {
			return nil, e
		}
		cp, e := r.Status(c.Request.Context(), v.Spec)
		if e != nil {
			return nil, e
		}
		if cp.State != "verified" && cp.State != "publishing" && cp.State != "published" {
			return nil, store.ErrMigrationState
		}
		mutex.Lock()
		defer mutex.Unlock()
		if active[key(v)] {
			return gin.H{"status": "waiting"}, nil
		}
		select {
		case jobs <- migrationVerifyJob{v, rel.ID, r, "publish"}:
			active[key(v)] = true
			return gin.H{"status": "publishing"}, nil
		default:
			return gin.H{"status": "waiting"}, nil
		}
	})
	register("recheck", func(c *gin.Context, rel store.Relationship, v migrationDataRequest, p store.MigrationPeerObject) (any, error) {
		if !migrationdata.ValidRecheckID(v.RecheckID) {
			return nil, store.ErrMigrationState
		}
		r, e := receiver(c.Request.Context(), v.Spec)
		if e != nil {
			return nil, e
		}
		cp, e := r.Status(c.Request.Context(), v.Spec)
		if e != nil {
			return nil, e
		}
		if cp.State != "published" {
			return nil, store.ErrMigrationState
		}
		if cp.RecheckID == v.RecheckID {
			return gin.H{"status": "rechecked", "checkpoint": cp}, nil
		}
		mutex.Lock()
		defer mutex.Unlock()
		if active[key(v)] {
			return gin.H{"status": "waiting"}, nil
		}
		select {
		case jobs <- migrationVerifyJob{v, rel.ID, r, "recheck"}:
			active[key(v)] = true
			return gin.H{"status": "rechecking"}, nil
		default:
			return gin.H{"status": "waiting"}, nil
		}
	})
	register("abort", func(c *gin.Context, rel store.Relationship, v migrationDataRequest, p store.MigrationPeerObject) (any, error) {
		r, e := receiver(c.Request.Context(), v.Spec)
		if e != nil {
			return nil, e
		}
		cp, e := r.Abort(c.Request.Context(), v.Spec, func() error { return admission(c.Request.Context(), rel.ID, v, "abort") })
		if e != nil {
			return nil, e
		}
		if e = repo.CompletePeerMigrationAbort(c.Request.Context(), rel.ID, v.Lease, v.Spec.LogicalID, store.NodeAudit{}); e != nil {
			return nil, e
		}
		return cp, nil
	})
	register("retire", func(c *gin.Context, rel store.Relationship, v migrationDataRequest, p store.MigrationPeerObject) (any, error) {
		if v.CleanupGrant == nil || v.Spec.Resource != "media" && (v.Spec.Resource != "recording" || recordings == nil) {
			return nil, store.ErrMigrationState
		}
		if e := repo.ValidatePeerAnchorRetirement(c.Request.Context(), rel.ID, v.Lease, *v.CleanupGrant, true); e != nil {
			return nil, e
		}
		r, e := receiver(c.Request.Context(), v.Spec)
		if e != nil {
			return nil, e
		}
		cp, e := r.Status(c.Request.Context(), v.Spec)
		if e != nil {
			return nil, e
		}
		if cp.State != "published" {
			return nil, store.ErrMigrationState
		}
		if cp.AnchorRetired {
			return gin.H{"state": "anchor_retired", "checkpoint": cp}, nil
		}
		mutex.Lock()
		defer mutex.Unlock()
		if active[key(v)] {
			return gin.H{"state": "waiting"}, nil
		}
		select {
		case jobs <- migrationVerifyJob{v, rel.ID, r, "retire"}:
			active[key(v)] = true
			return gin.H{"state": "working"}, nil
		default:
			return gin.H{"state": "waiting"}, nil
		}
	})
	register("unpublish", func(c *gin.Context, rel store.Relationship, v migrationDataRequest, p store.MigrationPeerObject) (any, error) {
		if settings.NginxMedia || v.Spec.Resource != "media" && (v.Spec.Resource != "recording" || recordings == nil || v.Spec.Recording == nil) {
			return nil, store.ErrMigrationState
		}
		if v.ShadowGrant != nil {
			if v.ShadowGrant.Object.ID != v.Spec.LogicalID || v.ShadowGrant.Unit.Header.TaskID != v.Lease.TaskID {
				return nil, store.ErrMigrationState
			}
			if e := repo.PreparePeerMigrationPublicationAbort(c.Request.Context(), rel.ID, v.Lease, *v.ShadowGrant, store.NodeAudit{}); e != nil {
				return nil, e
			}
		}
		var e error
		p, e = repo.AuthorizePeerMigration(c.Request.Context(), rel.ID, v.Lease, v.Spec.LogicalID, "unpublish")
		if e != nil {
			return nil, e
		}
		failed, e := repo.PeerMigrationShadowCleanupFailed(c.Request.Context(), rel.ID, v.Lease, v.Spec.LogicalID)
		if e != nil {
			return nil, e
		}
		if failed {
			return gin.H{"state": "unpublish_failed"}, nil
		}
		r, e := receiver(c.Request.Context(), v.Spec)
		if e != nil {
			return nil, e
		}
		cp, e := r.Status(c.Request.Context(), v.Spec)
		if e != nil {
			return nil, e
		}
		if p.State == "aborted" && cp.State == "aborted" && cp.PublicationCancelling && cp.PublicationUnlinked {
			return gin.H{"state": "publication_aborted", "checkpoint": cp}, nil
		}
		if cp.State != "publishing" && !(cp.State == "aborting" && cp.PublicationCancelling) && !(cp.State == "aborted" && cp.PublicationUnlinked) {
			return nil, store.ErrMigrationState
		}
		mutex.Lock()
		defer mutex.Unlock()
		if active[key(v)] {
			return gin.H{"state": "waiting"}, nil
		}
		// Storage restart can lose a queued worker, but never its durable intent.
		// Require a newly authenticated source proof before scheduling it again.
		if v.ShadowGrant == nil {
			return gin.H{"state": "grant_required"}, nil
		}
		select {
		case jobs <- migrationVerifyJob{v, rel.ID, r, "unpublish"}:
			active[key(v)] = true
			return gin.H{"state": "working"}, nil
		default:
			return gin.H{"state": "waiting"}, nil
		}
	})
	register("shadow", func(c *gin.Context, rel store.Relationship, v migrationDataRequest, p store.MigrationPeerObject) (any, error) {
		if settings.NginxMedia || v.Spec.Resource != "media" && (v.Spec.Resource != "recording" || recordings == nil || v.Spec.Recording == nil) {
			return nil, store.ErrMigrationState
		}
		if v.ShadowGrant != nil {
			if v.ShadowGrant.Object.ID != v.Spec.LogicalID || v.ShadowGrant.Unit.Header.TaskID != v.Lease.TaskID {
				return nil, store.ErrMigrationState
			}
			if e := repo.PreparePeerMigrationShadowDeletion(c.Request.Context(), rel.ID, v.Lease, *v.ShadowGrant, store.NodeAudit{}); e != nil {
				return nil, e
			}
			var e error
			p, e = repo.AuthorizePeerMigration(c.Request.Context(), rel.ID, v.Lease, v.Spec.LogicalID, "shadow")
			if e != nil {
				return nil, e
			}
		}
		if p.State == "published" {
			return nil, store.ErrMigrationState
		}
		failed, e := repo.PeerMigrationShadowCleanupFailed(c.Request.Context(), rel.ID, v.Lease, v.Spec.LogicalID)
		if e != nil {
			return nil, e
		}
		if failed {
			return gin.H{"state": "shadow_failed"}, nil
		}
		r, e := receiver(c.Request.Context(), v.Spec)
		if e != nil {
			return nil, e
		}
		if p.State == "deleted" {
			var finished bool
			var e error
			if v.Spec.Resource == "recording" {
				finished, e = recordings.MigrationCleanupFinished(c.Request.Context(), v.Lease.TaskID, v.Spec.LogicalID)
			} else {
				finished, e = volume.MigrationCleanupFinished(c.Request.Context(), v.Lease.TaskID, v.Spec.LogicalID)
			}
			if e != nil {
				return nil, e
			}
			cp, e := r.Status(c.Request.Context(), v.Spec)
			if e != nil {
				return nil, e
			}
			if finished && cp.AnchorRetired && !cp.AnchorRetiring {
				return gin.H{"state": "shadow_deleted", "checkpoint": cp}, nil
			}
		}
		mutex.Lock()
		defer mutex.Unlock()
		if active[key(v)] {
			return gin.H{"state": "waiting"}, nil
		}
		select {
		case jobs <- migrationVerifyJob{v, rel.ID, r, "shadow"}:
			active[key(v)] = true
			return gin.H{"state": "working"}, nil
		default:
			return gin.H{"state": "waiting"}, nil
		}
	})
	register("cleanup", func(c *gin.Context, rel store.Relationship, v migrationDataRequest, p store.MigrationPeerObject) (any, error) {
		// A legacy accelerated transfer has no proven Go response lifetime.
		if settings.NginxMedia || v.Spec.Resource != "media" && (v.Spec.Resource != "recording" || recordings == nil || v.Spec.Recording == nil) {
			return nil, store.ErrMigrationState
		}
		if v.CleanupGrant != nil {
			g := *v.CleanupGrant
			if g.TaskID != v.Lease.TaskID || g.Object.ID != v.Spec.LogicalID {
				return nil, store.ErrMigrationState
			}
			if e := repo.PreparePeerMigrationCleanup(c.Request.Context(), rel.ID, v.Lease, g, store.NodeAudit{}); e != nil {
				return nil, e
			}
			var e error
			p, e = repo.AuthorizePeerMigration(c.Request.Context(), rel.ID, v.Lease, v.Spec.LogicalID, "cleanup")
			if e != nil {
				return nil, e
			}
		}
		if p.State == "receiving" {
			return nil, store.ErrMigrationState
		}
		failed, e := repo.PeerMigrationCleanupFailed(c.Request.Context(), rel.ID, v.Lease, v.Spec.LogicalID)
		if e != nil {
			return nil, e
		}
		if failed {
			return gin.H{"state": "cleanup_failed"}, nil
		}
		if p.State == "deleted" {
			var finished bool
			var e error
			if v.Spec.Resource == "recording" {
				finished, e = recordings.MigrationCleanupFinished(c.Request.Context(), v.Lease.TaskID, v.Spec.LogicalID)
			} else {
				finished, e = volume.MigrationCleanupFinished(c.Request.Context(), v.Lease.TaskID, v.Spec.LogicalID)
			}
			if e != nil {
				return nil, e
			}
			if finished {
				if v.Spec.Resource == "recording" {
					finished, e = recordings.MigrationHistoryFinished(c.Request.Context(), p)
				} else {
					finished, e = volume.MigrationHistoryFinished(c.Request.Context(), p)
				}
				if e != nil {
					return nil, e
				}
			}
			if finished {
				return gin.H{"state": "source_deleted", "receipt": store.MigrationSourceReceipt{TaskID: v.Lease.TaskID, SourceID: p.Header.SourceID, TargetID: p.Header.TargetID, PlanSHA: p.Header.PlanSHA, Proof: p.Proof, ManagedCopyDeleted: true}}, nil
			}
		}
		mutex.Lock()
		defer mutex.Unlock()
		if active[key(v)] {
			return gin.H{"state": "waiting"}, nil
		}
		select {
		case jobs <- migrationVerifyJob{v, rel.ID, nil, "cleanup"}:
			active[key(v)] = true
			return gin.H{"state": "working"}, nil
		default:
			return gin.H{"state": "waiting"}, nil
		}
	})
	router.POST("/internal/v1/resource-migration/finish-unit", func(c *gin.Context) {
		if !nodeHTTPS(c, settings, resolver) {
			return
		}
		body, ok := nodeBody(c)
		if !ok {
			return
		}
		rel, e := control.Authenticate(c.Request.Context(), c.Request.Header, c.Request.Method, c.Request.URL.RequestURI(), body, false, false)
		if e != nil {
			detail(c, 401, "Invalid migration relationship authentication")
			return
		}
		if e = control.RequireFollower(c.Request.Context(), rel); e != nil {
			detail(c, 403, "Unit completion requires the active upstream Master")
			return
		}
		var v struct {
			Lease store.MigrationLease           `json:"lease"`
			Grant store.MigrationUnitFinishGrant `json:"grant"`
		}
		if controlJSON(body, &v) != nil {
			detail(c, 400, "Invalid unit completion binding")
			return
		}

		identity, e := volume.IdentityState(c.Request.Context())
		if e != nil {
			internalError(c, e)
			return
		}
		for object, pageErr := range peerMigrationUnitObjects(c.Request.Context(), repo, rel.ID, v.Lease, v.Grant, false) {
			if pageErr != nil {
				detail(c, 409, "Unit checkpoint changed during native verification")
				return
			}
			object.Header = v.Grant.Header
			if identity.ID == v.Grant.Header.SourceID {
				var done bool
				if object.Object.Resource == "recording" && recordings != nil {
					done, e = recordings.MigrationCleanupFinished(c.Request.Context(), v.Lease.TaskID, object.Object.ID)
					if e == nil && done {
						done, e = recordings.MigrationHistoryFinished(c.Request.Context(), object)
					}
				} else if object.Object.Resource == "media" {
					done, e = volume.MigrationCleanupFinished(c.Request.Context(), v.Lease.TaskID, object.Object.ID)
					if e == nil && done {
						done, e = volume.MigrationHistoryFinished(c.Request.Context(), object)
					}
				} else {
					e = store.ErrMigrationState
				}
				if e != nil || !done {
					detail(c, 409, "Source unit has retained cleanup material")
					return
				}
			} else {
				o := object.Object
				s := migrationdata.Spec{TaskID: v.Lease.TaskID, MasterID: v.Grant.Header.MasterID, SourceID: v.Grant.Header.SourceID, TargetID: v.Grant.Header.TargetID, LogicalID: o.ID, ObjectID: o.ObjectID, Resource: o.Resource, TargetPath: o.TargetPath, SourceVersion: o.Version, Bytes: o.Bytes, SHA256: object.Proof.SHA256, Encryption: o.Encryption, Recording: o.Recording}
				r, e := receiver(c.Request.Context(), s)
				if e != nil {
					detail(c, 409, "Target unit receiver unavailable")
					return
				}
				cp, e := r.Status(c.Request.Context(), s)
				if e != nil || !cp.AnchorRetired || cp.AnchorRetiring || cp.AnchorError != "" {
					detail(c, 409, "Target unit anchors are not retired")
					return
				}
			}
		}
		receipt, e := repo.CompletePeerMigrationUnit(c.Request.Context(), rel.ID, v.Lease, v.Grant, store.NodeAudit{Actor: rel.PeerID, RequestID: c.GetString("request_id"), TraceID: c.GetString("trace_id")})
		if e != nil {
			detail(c, 409, "Unit completion changed before commit")
			return
		}
		c.JSON(200, receipt)
	})
	router.POST("/internal/v1/resource-migration/cancel-unit", func(c *gin.Context) {
		if !nodeHTTPS(c, settings, resolver) {
			return
		}
		body, ok := nodeBody(c)
		if !ok {
			return
		}
		rel, e := control.Authenticate(c.Request.Context(), c.Request.Header, c.Request.Method, c.Request.URL.RequestURI(), body, false, false)
		if e != nil {
			detail(c, 401, "Invalid migration relationship authentication")
			return
		}
		if e = control.RequireFollower(c.Request.Context(), rel); e != nil {
			detail(c, 403, "Unit cancellation requires the active upstream Master")
			return
		}
		var v struct {
			Lease store.MigrationLease           `json:"lease"`
			Grant store.MigrationUnitFinishGrant `json:"grant"`
		}
		if controlJSON(body, &v) != nil {
			detail(c, 400, "Invalid unit cancellation binding")
			return
		}

		identity, e := volume.IdentityState(c.Request.Context())
		if e != nil {
			internalError(c, e)
			return
		}
		if identity.ID == v.Grant.Header.TargetID {
			for object, pageErr := range peerMigrationUnitObjects(c.Request.Context(), repo, rel.ID, v.Lease, v.Grant, true) {
				if pageErr != nil {
					detail(c, 409, "Unit checkpoint changed during native verification")
					return
				}
				o := object.Object
				spec := migrationdata.Spec{TaskID: v.Lease.TaskID, MasterID: v.Grant.Header.MasterID, SourceID: v.Grant.Header.SourceID, TargetID: v.Grant.Header.TargetID, LogicalID: o.ID, ObjectID: o.ObjectID, Resource: o.Resource, TargetPath: o.TargetPath, SourceVersion: o.Version, Bytes: o.Bytes, SHA256: object.Proof.SHA256, Encryption: o.Encryption, Recording: o.Recording}
				r, e := receiver(c.Request.Context(), spec)
				if e != nil {
					detail(c, 409, "Target cancellation receiver unavailable")
					return
				}
				cp, e := r.Status(c.Request.Context(), spec)
				finished := e == nil && cp.State == "aborted"
				if object.State == "deleted" {
					finished = e == nil && cp.State == "published" && cp.AnchorRetired && !cp.AnchorRetiring
					if finished {
						if o.Resource == "recording" && recordings != nil {
							finished, e = recordings.MigrationCleanupFinished(c.Request.Context(), v.Lease.TaskID, o.ID)
						} else {
							finished, e = volume.MigrationCleanupFinished(c.Request.Context(), v.Lease.TaskID, o.ID)
						}
					}
				}
				if e != nil || !finished {
					detail(c, 409, "Target staging cleanup is incomplete")
					return
				}
			}
		}
		receipt, e := repo.CompletePeerMigrationUnitCancellation(c.Request.Context(), rel.ID, v.Lease, v.Grant, store.NodeAudit{Actor: rel.PeerID, RequestID: c.GetString("request_id"), TraceID: c.GetString("trace_id")})
		if e != nil {
			detail(c, 409, "Unit cancellation changed before commit")
			return
		}
		c.JSON(200, receipt)
	})
	var once sync.Once
	return func() error { once.Do(func() { cancel(); workers.Wait() }); return nil }
}
