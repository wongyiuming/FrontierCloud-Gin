package httpapi

import (
	"context"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recording"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// The peer performs its own final native scan while holding media and recording
// mutation barriers. No request contains a caller-supplied clearance or path.
func RegisterNodeRetirementPeer(router *gin.Engine, settings config.Config, resolver *network.Resolver, control *node.Service, repository store.PoolRepository, volume *media.Service, recordings *recording.Storage) (func() error, error) {
	fence, ok := repository.(store.RetirementFenceRepository)
	if !ok || volume == nil || recordings == nil {
		return nil, store.ErrNodeState
	}
	inventory, ok := repository.(store.PhysicalInventoryRepository)
	if !ok {
		return nil, store.ErrNodeState
	}
	root, e := os.OpenRoot(settings.DataRoot)
	if e != nil {
		return nil, e
	}
	nativeState, e := newRetirementNativeInventory(context.Background(), root, settings, inventory, control)
	if e != nil {
		root.Close()
		return nil, e
	}
	shutdown, cancel := context.WithCancel(context.Background())
	var active sync.WaitGroup
	var guard sync.Mutex
	closed := false
	slot := make(chan struct{}, 1)
	router.POST("/internal/v1/retirement", func(c *gin.Context) {
		if !nodeHTTPS(c, settings, resolver) {
			return
		}
		raw, ok := nodeBody(c)
		if !ok {
			return
		}
		rel, e := control.AuthenticateRetirement(c.Request.Context(), c.Request.Header, c.Request.Method, c.Request.URL.RequestURI(), raw)
		if e != nil {
			detail(c, 401, "Invalid retirement authentication")
			return
		}
		identity, e := control.IdentityState(c.Request.Context())
		if e != nil {
			internalError(c, e)
			return
		}
		var req struct {
			Action string `json:"action"`
			Member string `json:"confirm_member_id"`
		}
		d := json.NewDecoder(strings.NewReader(string(raw)))
		d.DisallowUnknownFields()
		if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF || req.Member != identity.ID || identity.Role != "Follower" || rel.Direction != "upstream" {
			detail(c, 400, "Invalid retirement identity confirmation")
			return
		}
		guard.Lock()
		if closed {
			guard.Unlock()
			detail(c, 503, "Retirement service is closing")
			return
		}
		active.Add(1)
		guard.Unlock()
		defer active.Done()
		select {
		case slot <- struct{}{}:
			defer func() { <-slot }()
		default:
			detail(c, 429, "Retirement reconciliation is running")
			return
		}
		ctx, stop := context.WithTimeout(c.Request.Context(), 4*time.Minute)
		defer stop()
		unhook := context.AfterFunc(shutdown, stop)
		defer unhook()
		audit := store.NodeAudit{Actor: rel.PeerID}
		var result store.RetirementFence
		switch req.Action {
		case "begin":
			result, e = fence.BeginRetirement(ctx, rel.ID, identity.ID, audit)
		case "status":
			result, e = fence.RetirementFence(ctx, rel.ID, identity.ID)
		case "complete":
			result, e = fence.RetirementFence(ctx, rel.ID, identity.ID)
			if e == nil && result.CompletedAt == 0 {
				if settings.NginxMedia {
					e = store.ErrNodeState
					break
				}
				var release func()
				ctx, release, e = control.RetirementRequestLease(ctx, true)
				if e != nil {
					break
				}
				defer release()
				e = volume.RetirementBarrier(ctx, func() error {
					return recordings.RetirementBarrier(ctx, func() error {
						if e := inspectRetirementRoots(ctx, root, volume.InventoryRoot(), recordings.InventoryRoot(), inventory, nativeState, rel.ID, identity.ID, rel.PeerID); e != nil {
							return e
						}
						var err error
						result, err = fence.CompleteRetirement(ctx, rel.ID, identity.ID, audit)
						return err
					})
				})
			}
		default:
			e = store.ErrNodeState
		}
		if e != nil {
			detail(c, 409, "Retirement remains fenced or blocked; resolve ledger and native inventory concerns before retrying")
			return
		}
		c.JSON(200, result)
	})
	var once sync.Once
	var closeErr error
	return func() error {
		once.Do(func() {
			guard.Lock()
			closed = true
			cancel()
			guard.Unlock()
			active.Wait()
			closeErr = root.Close()
		})
		return closeErr
	}, nil
}

func inspectRetirementRoots(ctx context.Context, data, mediaRoot, recordingRoot *os.Root, repo store.PhysicalInventoryRepository, nativeState *retirementNativeInventory, relationship, member, master string) error {
	if e := nativeState.validate(ctx); e != nil {
		return e
	}
	roots := map[string]*os.Root{"data": data, "media": mediaRoot, "recordings": recordingRoot}
	excluded := map[string]os.FileInfo{}
	for _, scope := range []string{"media", "recordings"} {
		actual, e := roots[scope].Stat(".")
		if e != nil {
			return e
		}
		local, e := data.Lstat(scope)
		if e == nil && local.IsDir() && os.SameFile(local, actual) {
			excluded[scope] = actual
		}
	}
	for _, scope := range []string{"data", "media", "recordings"} {
		var scan *resourceinventory.Scanner
		var e error
		if scope == "data" {
			scan, e = resourceinventory.NewExcluding(data, excluded)
		} else {
			scan, e = resourceinventory.New(roots[scope])
		}
		if e != nil {
			return e
		}
		e = func() error {
			defer scan.Close()
			for sequence := uint64(0); sequence < 100000; sequence++ {
				page, e := scan.Next(ctx, sequence)
				if e != nil {
					return e
				}
				entries := make([]store.PhysicalInventoryEntry, 0, len(page.Entries))
				for _, entry := range page.Entries {
					name := entry.Path
					if scope != "data" {
						name = scope + "/" + name
					}
					entries = append(entries, store.PhysicalInventoryEntry{Path: name, Kind: entry.Kind, LogicalBytes: entry.LogicalBytes})
				}
				facts, e := repo.ClassifyPhysicalInventory(ctx, relationship, member, master, entries)
				if e != nil {
					return e
				}
				if len(facts) != len(entries) {
					return resourceinventory.ErrLimit
				}
				for i, entry := range page.Entries {
					fact := facts[i]
					if scope == "data" {
						fact = nativeState.classify(ctx, entry, fact)
						for _, native := range []string{"media", "recordings"} {
							if excluded[native] == nil && (entry.Path == native || strings.HasPrefix(entry.Path, native+"/")) && entry.Kind == "regular" {
								fact.Blocking = true
							}
						}
					} else {
						held := scope == "media" && entry.Path == ".media-mutation.lock" || scope == "recordings" && entry.Path == ".recordings-mutation.lock"
						if held {
							// These exact inodes are already held exclusively by the caller's
							// native services, so probing another fd would report our own lock.
							info, e := roots[scope].Lstat(entry.Path)
							if e != nil || !info.Mode().IsRegular() || info.Size() != 0 || entry.LogicalBytes != 0 || info.ModTime().UnixNano() != entry.ModifiedNS {
								return resourceinventory.ErrChanged
							}
							fact.Blocking = false
						} else {
							if fact.Category == "migration_material" {
								fact, _ = retirementCheckpointInventory(ctx, roots[scope], repo, relationship, member, master, scope, entry, fact)
							}
							if scope == "media" {
								var owned bool
								fact, owned = nativeState.controlLease(roots[scope], entry, fact)
								if !owned {
									fact, _ = media.InventoryState(ctx, roots[scope], entry, fact)
								}
							} else {
								fact, _ = recording.InventoryState(ctx, roots[scope], entry, fact)
							}
						}
					}
					if fact.Blocking {
						return store.ErrNodeState
					}
				}
				if page.Complete {
					return nil
				}
			}
			return resourceinventory.ErrLimit
		}()
		if e != nil {
			return e
		}
	}
	return nativeState.validate(ctx)
}
