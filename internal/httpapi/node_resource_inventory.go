package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
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

// RegisterNodePhysicalInventory observes the data root and optional borrowed
// native media/recording mounts. It accepts no arbitrary path, URL, role, identity or expiry.
// This observation endpoint does not grant migration, deletion or retirement.
func RegisterNodePhysicalInventory(router *gin.Engine, settings config.Config, resolver *network.Resolver, control *node.Service, repository store.PhysicalInventoryRepository, nativeRoots ...*os.Root) (func() error, error) {
	if repository == nil {
		return nil, errors.New("physical inventory repository unavailable")
	}
	root, e := os.OpenRoot(settings.DataRoot)
	if e != nil {
		return nil, e
	}
	nativeState, e := newRetirementNativeInventory(context.Background(), root, settings, repository, control)
	if e != nil {
		root.Close()
		return nil, e
	}
	expectedRepository, ok := repository.(store.ExpectedPhysicalRepository)
	if !ok {
		root.Close()
		return nil, errors.New("expected physical inventory repository unavailable")
	}
	roots := map[string]*os.Root{"data": root}
	excluded := map[string]os.FileInfo{}
	sessions := resourceinventory.NewSessions(root, nil)
	if len(nativeRoots) != 0 {
		if len(nativeRoots) != 2 || nativeRoots[0] == nil || nativeRoots[1] == nil {
			root.Close()
			return nil, resourceinventory.ErrSession
		}
		roots["media"], roots["recordings"] = nativeRoots[0], nativeRoots[1]
		for _, scope := range []string{"media", "recordings"} {
			actual, err := roots[scope].Stat(".")
			if err != nil {
				root.Close()
				return nil, err
			}
			local, err := root.Lstat(scope)
			if err == nil && local.IsDir() && local.Mode()&os.ModeSymlink == 0 && os.SameFile(local, actual) {
				excluded[scope] = actual
			}
		}
		sessions, e = resourceinventory.NewVolumeSessions(root, nativeRoots[0], nativeRoots[1], excluded, nil)
		if e != nil {
			root.Close()
			return nil, e
		}
	}
	shutdown, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-shutdown.Done():
				return
			case <-ticker.C:
				_ = sessions.Expire()
			}
		}
	}()
	slots := make(chan struct{}, 1)
	type classifiedPage struct {
		resourceinventory.SessionPage
		Facts []store.PhysicalInventoryFact `json:"facts"`
	}
	var last *classifiedPage
	type expectedResponse struct {
		Session  resourceinventory.Session    `json:"session"`
		Manifest store.ExpectedPhysicalPage   `json:"manifest"`
		Presence []resourceinventory.Presence `json:"presence"`
	}
	var lastExpected *expectedResponse
	router.POST("/internal/v1/resource-inventory", func(c *gin.Context) {
		if !nodeHTTPS(c, settings, resolver) {
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
		rel, e := control.AuthenticateRetirement(c.Request.Context(), c.Request.Header, c.Request.Method, uri, body)
		if e != nil {
			detail(c, 401, "Invalid inventory relationship authentication")
			return
		}
		if e = control.RequireInventoryFollower(c.Request.Context(), rel); e != nil {
			detail(c, 403, "Inventory requires the active upstream Master")
			return
		}
		identity, e := control.IdentityState(c.Request.Context())
		if e != nil {
			internalError(c, e)
			return
		}
		var request struct {
			Action      string `json:"action"`
			MemberID    string `json:"member_id"`
			Scope       string `json:"scope"`
			SessionID   string `json:"session_id"`
			Incarnation string `json:"incarnation"`
			Sequence    uint64 `json:"sequence"`
			Resource    string `json:"resource"`
			After       string `json:"after"`
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		decodeError := decoder.Decode(&request)
		var tail any
		if decodeError == nil && decoder.Decode(&tail) != io.EOF {
			decodeError = resourceinventory.ErrSession
		}
		if decodeError != nil || request.MemberID != identity.ID || roots[request.Scope] == nil || request.Action != "expected" && (request.Resource != "" || request.After != "") {
			detail(c, 400, "Invalid identity-bound inventory request")
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			detail(c, 429, "Inventory page is already being observed")
			return
		}
		if request.Scope != "data" && (request.Action == "expected" || request.Action == "volumes") {
			detail(c, 400, "Metadata requires the data scope")
			return
		}
		ctx, cancel := context.WithCancel(c.Request.Context())
		defer cancel()
		unhook := context.AfterFunc(shutdown, cancel)
		defer unhook()
		if len(nativeRoots) == 2 && nativeState.validate(ctx) != nil {
			detail(c, 409, "Retained native state changed; reconcile the selected runtime files")
			return
		}
		binding := resourceinventory.Binding{MemberID: identity.ID, MasterID: rel.PeerID, RelationshipID: rel.ID, Scope: request.Scope}
		var result any
		switch request.Action {
		case "open":
			if request.Incarnation != "" || request.Sequence != 0 {
				e = resourceinventory.ErrSession
				break
			}
			result, e = sessions.Open(ctx, request.SessionID, binding)
		case "page":
			var observed resourceinventory.SessionPage
			observed, e = sessions.Page(ctx, request.SessionID, request.Incarnation, binding, request.Sequence)
			if e != nil {
				break
			}
			if last != nil && last.Session == observed.Session && last.Page.Sequence == observed.Page.Sequence {
				result = last
				break
			}
			entries := make([]store.PhysicalInventoryEntry, 0, len(observed.Page.Entries))
			for _, entry := range observed.Page.Entries {
				name := entry.Path
				if request.Scope != "data" {
					name = request.Scope + "/" + name
				}
				entries = append(entries, store.PhysicalInventoryEntry{Path: name, Kind: entry.Kind, LogicalBytes: entry.LogicalBytes})
			}
			var facts []store.PhysicalInventoryFact
			facts, e = repository.ClassifyPhysicalInventory(ctx, rel.ID, identity.ID, rel.PeerID, entries)
			if e == nil && len(facts) == len(entries) && request.Scope == "data" && len(nativeRoots) == 2 {
				for i, entry := range observed.Page.Entries {
					facts[i] = nativeState.classify(ctx, entry, facts[i])
					for _, scope := range []string{"media", "recordings"} {
						if excluded[scope] == nil && (entry.Path == scope || strings.HasPrefix(entry.Path, scope+"/")) && entry.Kind == "regular" {
							facts[i] = store.PhysicalInventoryFact{Category: "unmanaged_file", Blocking: true, Reason: "outside_native_mount"}
						}
					}
				}
			}
			if e == nil && len(facts) == len(entries) && request.Scope != "data" {
				original := append([]store.PhysicalInventoryFact(nil), facts...)
				indices := []int{}
				for i, entry := range observed.Page.Entries {
					handled := false
					if facts[i].Category == "migration_material" {
						facts[i], handled = retirementCheckpointInventory(ctx, roots[request.Scope], repository, rel.ID, identity.ID, rel.PeerID, request.Scope, entry, facts[i])
					}
					if request.Scope == "media" {
						var native bool
						facts[i], native = nativeState.controlLease(roots[request.Scope], entry, facts[i])
						if !native {
							facts[i], native = media.InventoryState(ctx, roots[request.Scope], entry, facts[i])
						}
						handled = handled || native
					}
					if request.Scope == "recordings" {
						var native bool
						facts[i], native = recording.InventoryState(ctx, roots[request.Scope], entry, facts[i])
						handled = handled || native
					}
					if handled {
						indices = append(indices, i)
					}
				}
				if len(indices) > 0 {
					repeated, err := repository.ClassifyPhysicalInventory(ctx, rel.ID, identity.ID, rel.PeerID, entries)
					e = err
					if e == nil {
						if len(repeated) != len(original) {
							e = resourceinventory.ErrChanged
						} else {
							for _, i := range indices {
								if repeated[i] != original[i] {
									e = resourceinventory.ErrChanged
									break
								}
							}
						}
					}
					if e != nil {
						_ = sessions.Cancel(request.SessionID, request.Incarnation, binding)
					}
				}
			}
			if e == nil && len(facts) != len(entries) {
				e = resourceinventory.ErrLimit
			}
			if e == nil {
				for _, fact := range facts {
					encoded, err := json.Marshal(fact)
					if err != nil || len(encoded) > resourceinventory.FactBytes {
						e = resourceinventory.ErrLimit
						break
					}
				}
			}
			if e != nil {
				_ = sessions.Cancel(request.SessionID, request.Incarnation, binding)
				break
			}
			if _, e = sessions.Page(ctx, request.SessionID, request.Incarnation, binding, request.Sequence); e != nil {
				break
			}
			last = &classifiedPage{SessionPage: observed, Facts: facts}
			result = last
		case "expected":
			if request.Sequence != 0 {
				e = resourceinventory.ErrSession
				break
			}
			var session resourceinventory.Session
			session, e = sessions.Validate(request.SessionID, request.Incarnation, binding)
			if e != nil {
				break
			}
			if lastExpected != nil && lastExpected.Session == session && lastExpected.Manifest.Resource == request.Resource && lastExpected.Manifest.After == request.After {
				result = lastExpected
				break
			}
			var manifest store.ExpectedPhysicalPage
			manifest, e = expectedRepository.ExpectedPhysicalInventory(ctx, rel.ID, identity.ID, rel.PeerID, request.Resource, request.After)
			if e != nil {
				break
			}
			observations := make([]resourceinventory.Presence, 0, len(manifest.Items))
			for _, item := range manifest.Items {
				if item.Backing == "database" || item.Backing == "pending" {
					state := "database_backed_unverified"
					if item.Backing == "pending" {
						state = "pending_backup"
					}
					observations = append(observations, resourceinventory.Presence{State: state})
					continue
				}
				presenceRoot, name := root, item.Path
				for _, scope := range []string{"media", "recordings"} {
					if roots[scope] != nil && strings.HasPrefix(name, scope+"/") {
						presenceRoot = roots[scope]
						name = strings.TrimPrefix(name, scope+"/")
						break
					}
				}
				present, err := resourceinventory.PresenceAt(ctx, presenceRoot, name)
				if err != nil {
					e = err
					break
				}
				if present.State == "present" && item.ExpectedBytes != nil && present.LogicalBytes != *item.ExpectedBytes {
					present.State = "length_mismatch"
				}
				observations = append(observations, present)
			}
			if e != nil {
				break
			}
			if _, e = sessions.Validate(request.SessionID, request.Incarnation, binding); e != nil {
				break
			}
			lastExpected = &expectedResponse{Session: session, Manifest: manifest, Presence: observations}
			result = lastExpected
		case "volumes":
			if request.Sequence != 0 || len(nativeRoots) != 2 {
				e = resourceinventory.ErrSession
				break
			}
			if _, e = sessions.Validate(request.SessionID, request.Incarnation, binding); e != nil {
				break
			}
			volumes := make([]resourceinventory.Volume, 0, 3)
			for _, scope := range []string{"data", "media", "recordings"} {
				total, free, err := fsutil.DiskUsage(roots[scope])
				if err != nil {
					e = err
					break
				}
				if total < 0 || free < 0 || free > total {
					e = resourceinventory.ErrSession
					break
				}
				volumes = append(volumes, resourceinventory.Volume{Scope: scope, InDataRoot: excluded[scope] != nil, TotalBytes: total, FreeBytes: free, ObservedAt: time.Now().Unix()})
			}
			if e == nil {
				_, e = sessions.Validate(request.SessionID, request.Incarnation, binding)
			}
			if e == nil {
				session, err := sessions.Validate(request.SessionID, request.Incarnation, binding)
				e = err
				result = gin.H{"session": session, "volumes": volumes}
			}
		case "ledger":
			if request.Sequence != 0 {
				e = resourceinventory.ErrSession
				break
			}
			if _, e = sessions.Validate(request.SessionID, request.Incarnation, binding); e != nil {
				break
			}
			ledgerRepository, ok := repository.(store.RetirementRepository)
			if !ok {
				e = resourceinventory.ErrSession
				break
			}
			result, e = ledgerRepository.RetirementLedger(ctx, rel.ID, identity.ID)
			if e == nil {
				_, e = sessions.Validate(request.SessionID, request.Incarnation, binding)
			}
		case "close":
			if request.Sequence != 0 {
				e = resourceinventory.ErrSession
				break
			}
			e = sessions.Cancel(request.SessionID, request.Incarnation, binding)
			result = gin.H{"session_id": request.SessionID, "closed": true}
		default:
			e = resourceinventory.ErrSession
		}
		if e != nil {
			if errors.Is(e, resourceinventory.ErrBusy) {
				detail(c, 429, "Another inventory session is active")
			} else {
				detail(c, 409, "Inventory observation expired, changed, exceeded bounds or conflicts with its session; restart the scan")
			}
			return
		}
		c.JSON(200, result)
	})
	var once sync.Once
	var closeError error
	return func() error {
		once.Do(func() { stop(); <-done; closeError = errors.Join(sessions.Close(), root.Close()) })
		return closeError
	}, nil
}
