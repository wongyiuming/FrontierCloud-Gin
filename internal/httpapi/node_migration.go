package httpapi

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Metadata registration uses the existing HTTPS/raw-body authentication and
// durable nonce ledger. The unfinished data capability remains unadvertised.
func RegisterNodeMigrationControl(router *gin.Engine, settings config.Config, resolver *network.Resolver, control *node.Service, volume *media.Service, repo store.MigrationPeerRepository) {
	if repo == nil {
		return
	}
	register := func(route string, action func(*gin.Context, store.Relationship, []byte) error) {
		router.POST(route, func(c *gin.Context) {
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
				detail(c, 401, "Invalid migration relationship authentication")
				return
			}
			if e = control.RequireFollower(c.Request.Context(), rel); e != nil {
				detail(c, 403, "Migration control requires the active upstream Master")
				return
			}
			if e = action(c, rel, body); e != nil {
				if errors.Is(e, store.ErrMigrationState) || errors.Is(e, store.ErrMigrationLease) || errors.Is(e, store.ErrStorageCapacity) || errors.Is(e, store.ErrNodeState) {
					detail(c, 409, "Migration registration conflicts with identity, task, capacity or lease")
				} else {
					internalError(c, e)
				}
				return
			}
			c.JSON(200, gin.H{"status": "registered"})
		})
	}
	register("/internal/v1/resource-migration/register", func(c *gin.Context, rel store.Relationship, body []byte) error {
		var v struct {
			Header store.MigrationPeerHeader `json:"header"`
			Lease  store.MigrationLease      `json:"lease"`
			State  string                    `json:"state"`
		}
		if controlJSON(body, &v) != nil {
			return store.ErrMigrationState
		}
		_, free, e := volume.PhysicalCapacity(c.Request.Context())
		if e != nil {
			return e
		}
		return repo.RegisterPeerMigration(c.Request.Context(), rel.ID, v.Header, v.Lease, v.State, free, store.NodeAudit{Actor: rel.PeerID, RequestID: c.GetString("request_id"), TraceID: c.GetString("trace_id")})
	})
	register("/internal/v1/resource-migration/object", func(c *gin.Context, rel store.Relationship, body []byte) error {
		var v struct {
			Lease  store.MigrationLease      `json:"lease"`
			Object store.MigrationPeerObject `json:"object"`
		}
		if controlJSON(body, &v) != nil {
			return store.ErrMigrationState
		}
		return repo.RegisterPeerMigrationObject(c.Request.Context(), rel.ID, v.Lease, v.Object, store.NodeAudit{Actor: rel.PeerID, RequestID: c.GetString("request_id"), TraceID: c.GetString("trace_id")})
	})
	register("/internal/v1/resource-migration/fence", func(c *gin.Context, rel store.Relationship, body []byte) error {
		var v struct {
			Task  string `json:"task_id"`
			Epoch int64  `json:"epoch"`
			State string `json:"state"`
		}
		if controlJSON(body, &v) != nil {
			return store.ErrMigrationState
		}
		return repo.FencePeerMigration(c.Request.Context(), rel.ID, v.Task, v.Epoch, v.State, store.NodeAudit{Actor: rel.PeerID, RequestID: c.GetString("request_id"), TraceID: c.GetString("trace_id")})
	})
}
