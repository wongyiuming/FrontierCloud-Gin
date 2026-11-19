package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type OpaqueFollowerRelay struct {
	origin   string
	media    *media.Service
	control  *node.Service
	sessions *mediacrypto.Manager
	tree     *sealedtree.SQLStore
	reads    chan struct{}
}

// RegisterOpaqueFollowerRelay is explicit and is not called by product startup
// while encrypted-tree migration and lifecycle readiness remain incomplete.
func RegisterOpaqueFollowerRelay(router *gin.Engine, service *media.Service, control *node.Service, sessions *mediacrypto.Manager, tree *sealedtree.SQLStore) (*OpaqueFollowerRelay, error) {
	if router == nil || service == nil || control == nil || sessions == nil || tree == nil {
		return nil, errors.New("incomplete opaque relay configuration")
	}
	h := &OpaqueFollowerRelay{media: service, control: control, sessions: sessions, tree: tree, reads: make(chan struct{}, 4)}
	router.GET("/api/v1/media/opaque-follower-relay/:resource", h.serve)
	router.HEAD("/api/v1/media/opaque-follower-relay/:resource", h.serve)
	return h, nil
}

func (h *OpaqueFollowerRelay) serve(c *gin.Context) {
	noStore(c)
	assertion, local, ok := network.PublicIngressIdentityFromContext(c.Request.Context())
	if !ok || h == nil || c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery || !masterRelayID.MatchString(c.Param("resource")) || len(c.Request.Header.Values("Range")) > 1 {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	origins := c.Request.Header.Values("Origin")
	if len(origins) > 1 || len(origins) == 1 && origins[0] != assertion.PublicOrigin {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	values := c.Request.Header.Values("X-Media-Relay")
	if len(values) != 1 || values[0] == "" || len(values[0]) > 4096 {
		detail(c, http.StatusUnauthorized, "Resource authorization invalid or expired")
		return
	}
	select {
	case h.reads <- struct{}{}:
		defer func() { <-h.reads }()
	default:
		detail(c, http.StatusServiceUnavailable, "Resource access busy")
		return
	}
	ctx := c.Request.Context()
	var prerequisite store.IngressPrerequisite
	var owned node.IngressPrerequisiteLease
	var localState *localFollowerRelayAdmission
	if local {
		localState, ok = ctx.Value(localFollowerRelayAdmissionKey{}).(*localFollowerRelayAdmission)
		var held bool
		prerequisite, held = store.IngressPrerequisiteFromContext(ctx)
		if localState == nil || !held || prerequisite == nil {
			detail(c, http.StatusServiceUnavailable, "Resource access unavailable")
			return
		}
	} else {
		var err error
		ctx, owned, err = h.control.AcquireResourcePrerequisite(ctx)
		if err != nil || owned == nil {
			detail(c, http.StatusServiceUnavailable, "Resource access unavailable")
			return
		}
		prerequisite = owned
		defer owned.Release()
	}
	c.Request = c.Request.WithContext(ctx)
	placement, claim, err := h.media.OpaqueFollowerRelayObject(ctx, h.tree, values[0], c.Param("resource"))
	if err != nil || !h.sessions.CheckDirectSession(claim.SessionID) {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	deadline := time.Unix(claim.ExpiresAt, 0)
	if limit := time.Now().Add(masterRelayReadDrain); limit.Before(deadline) {
		deadline = limit
	}
	if !deadline.After(time.Now()) {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	response, err := h.control.OpenOpaqueFollowerRelayStream(bounded, values[0], placement.ReadAlias, placement.BlobID, claim.Revision, placement.SHA256, placement.Bytes, placement.Encryption, h.sessions, c.Request.Method, c.Request.Header.Get("Range"))
	if errors.Is(err, node.ErrFollowerRelayRange) {
		c.Header("Content-Range", "bytes */"+strconv.FormatInt(placement.Bytes, 10))
		detail(c, http.StatusRequestedRangeNotSatisfiable, "Invalid range")
		return
	}
	if err != nil {
		detail(c, http.StatusBadGateway, "Resource access unavailable")
		return
	}
	defer response.Body.Close()
	if prerequisite.Check(ctx) != nil {
		detail(c, http.StatusServiceUnavailable, "Resource access unavailable")
		return
	}
	if local {
		if bounded.Err() != nil || localState.lease.Commit() != nil || !localState.admission.Commit() {
			detail(c, http.StatusServiceUnavailable, "Resource access unavailable")
			return
		}
	} else {
		owned.Release()
	}
	controller := http.NewResponseController(c.Writer)
	if err := controller.SetWriteDeadline(deadline); err != nil {
		detail(c, http.StatusServiceUnavailable, "Resource access unavailable")
		return
	}
	defer controller.SetWriteDeadline(time.Time{})
	c.Header("Content-Type", "application/octet-stream")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Accept-Ranges", "bytes")
	c.Header("Content-Length", strconv.FormatInt(response.Length, 10))
	if response.ContentRange != "" {
		c.Header("Content-Range", response.ContentRange)
	}
	c.Status(response.Status)
	if c.Request.Method == http.MethodHead {
		return
	}
	if _, err := io.CopyBuffer(c.Writer, response.Body, make([]byte, 32<<10)); err != nil {
		panic(http.ErrAbortHandler)
	}
}
