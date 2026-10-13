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
)

type managedContentReader interface {
	ObserveManagedContent(context.Context, store.ExpectedPhysicalItem, int64, func() error) (resourceinventory.ContentObservation, error)
}

// RegisterNodeContentObservation exposes bounded ephemeral observations. It
// grants no migration, deletion, immutable-version or retirement authority.
// Close joins the reader before native services close their borrowed roots.
func RegisterNodeContentObservation(router *gin.Engine, settings config.Config, resolver *network.Resolver, control *node.Service, repository store.ManagedPhysicalRepository, media, recordings managedContentReader) (func() error, error) {
	if repository == nil || media == nil {
		return nil, resourceinventory.ErrSession
	}
	jobs, err := resourceinventory.NewContentJobs(context.Background(), func(ctx context.Context, request resourceinventory.ContentRequest) (resourceinventory.ContentObservation, error) {
		var item store.ExpectedPhysicalItem
		check := func() error {
			identity, e := control.IdentityState(ctx)
			if e != nil || identity.ID != request.Binding.MemberID || identity.Role != "Follower" {
				return resourceinventory.ErrSession
			}
			current, e := repository.ExpectedPhysicalObject(ctx, request.Binding.RelationshipID, request.Binding.MemberID, request.Binding.MasterID, request.Resource, request.ObjectID)
			if e != nil {
				return e
			}
			if current.MetadataSHA256 != request.MetadataSHA || current.ExpectedBytes != nil && *current.ExpectedBytes != request.Bytes {
				return resourceinventory.ErrSession
			}
			if item.Path != "" && (item.Path != current.Path || item.State != current.State) {
				return resourceinventory.ErrSession
			}
			item = current
			return nil
		}
		if e := check(); e != nil {
			return resourceinventory.ContentObservation{}, e
		}
		reader := media
		if request.Resource == "recording" {
			reader = recordings
		}
		if reader == nil {
			return resourceinventory.ContentObservation{}, resourceinventory.ErrSession
		}
		return reader.ObserveManagedContent(ctx, item, request.Bytes, check)
	}, nil)
	if err != nil {
		return nil, err
	}
	router.POST("/internal/v1/content-observation", func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
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
			detail(c, 401, "Invalid content observation authentication")
			return
		}
		if e = control.RequireFollower(c.Request.Context(), rel); e != nil {
			detail(c, 403, "Content observation requires active upstream Master")
			return
		}
		identity, e := control.IdentityState(c.Request.Context())
		if e != nil {
			detail(c, 409, "Content observation identity unavailable")
			return
		}
		var request struct {
			Action string `json:"action"`
			resourceinventory.ContentRequest
			Incarnation string `json:"incarnation"`
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		var tail any
		if decoder.Decode(&request) != nil || decoder.Decode(&tail) != io.EOF || c.Request.URL.RawQuery != "" {
			detail(c, 400, "Invalid content observation request")
			return
		}
		binding := resourceinventory.Binding{MemberID: identity.ID, MasterID: rel.PeerID, RelationshipID: rel.ID, Scope: "data"}
		if request.Binding != binding {
			detail(c, 400, "Invalid content observation binding")
			return
		}
		// Revalidate ready metadata and the live relationship for every operation,
		// including cached status and cancellation. No caller-supplied path is used.
		item, e := repository.ExpectedPhysicalObject(c.Request.Context(), rel.ID, identity.ID, rel.PeerID, request.Resource, request.ObjectID)
		if e != nil || item.MetadataSHA256 != request.MetadataSHA || item.ExpectedBytes != nil && *item.ExpectedBytes != request.Bytes {
			detail(c, 409, "Content observation metadata changed or unavailable")
			return
		}
		var result resourceinventory.ContentJob
		switch request.Action {
		case "start":
			if request.Incarnation != "" {
				e = resourceinventory.ErrSession
			} else {
				result, e = jobs.Start(request.ContentRequest)
			}
		case "status", "cancel":
			result, e = jobs.Status(request.ID, request.Incarnation, binding)
			if e == nil && result.Request != request.ContentRequest {
				e = resourceinventory.ErrSession
			}
			if e == nil && request.Action == "cancel" {
				result, e = jobs.Cancel(request.ID, request.Incarnation, binding)
			}
		default:
			e = resourceinventory.ErrSession
		}
		if errors.Is(e, resourceinventory.ErrBusy) {
			detail(c, 429, "Content observation worker busy")
			return
		}
		if e != nil {
			detail(c, 409, "Content observation expired or invalid")
			return
		}
		c.JSON(200, result)
	})
	return func() error { jobs.Close(); return nil }, nil
}
