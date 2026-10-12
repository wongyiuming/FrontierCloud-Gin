package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"io"
	"os"
	"sync"
	"time"
)

// RegisterNodePhysicalInventory exposes only metadata under the configured
// data root. It accepts no arbitrary path, URL, role, identity or expiry.
// This observation endpoint does not grant migration, deletion or retirement.
func RegisterNodePhysicalInventory(router *gin.Engine, settings config.Config, resolver *network.Resolver, control *node.Service, repository store.PhysicalInventoryRepository) (func() error, error) {
	if repository == nil {
		return nil, errors.New("physical inventory repository unavailable")
	}
	root, e := os.OpenRoot(settings.DataRoot)
	if e != nil {
		return nil, e
	}
	sessions := resourceinventory.NewSessions(root, nil)
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
		rel, e := control.Authenticate(c.Request.Context(), c.Request.Header, c.Request.Method, uri, body, false, false)
		if e != nil {
			detail(c, 401, "Invalid inventory relationship authentication")
			return
		}
		if e = control.RequireFollower(c.Request.Context(), rel); e != nil {
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
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		decodeError := decoder.Decode(&request)
		var tail any
		if decodeError == nil && decoder.Decode(&tail) != io.EOF {
			decodeError = resourceinventory.ErrSession
		}
		if decodeError != nil || request.MemberID != identity.ID || request.Scope != "data" {
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
		ctx, cancel := context.WithCancel(c.Request.Context())
		defer cancel()
		unhook := context.AfterFunc(shutdown, cancel)
		defer unhook()
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
				entries = append(entries, store.PhysicalInventoryEntry{Path: entry.Path, Kind: entry.Kind, LogicalBytes: entry.LogicalBytes})
			}
			var facts []store.PhysicalInventoryFact
			facts, e = repository.ClassifyPhysicalInventory(ctx, rel.ID, identity.ID, rel.PeerID, entries)
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
