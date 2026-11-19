package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// MasterLocalMedia is installed only in isolated fixtures until the tree,
// write/recovery lifecycle and full ingress readiness gates are complete.
type MasterLocalMedia struct {
	origin     string
	url        *url.URL
	media      *media.Service
	control    *node.Service
	sessions   *mediacrypto.Manager
	edge       *network.Resolver
	tree       *sealedtree.SQLStore
	nginxMedia bool
	reads      chan struct{}
}

func (p *Public) masterLocalMediaReady(ctx context.Context) bool {
	local, ok := network.LocalPublicIngressFromContext(ctx)
	return ok && p != nil && p.masterLocalMedia != nil && p.masterLocalMedia.tree == p.opaqueTree && p.masterLocalMedia.media == p.media && p.masterLocalMedia.control == p.control && p.masterLocalMedia.origin == local.PublicOrigin
}

func RegisterOpaqueMasterLocalMedia(router *gin.Engine, settings config.Config, origin string, service *media.Service, control *node.Service, sessions *mediacrypto.Manager, tree *sealedtree.SQLStore) (*MasterLocalMedia, error) {
	if router == nil || service == nil || control == nil || sessions == nil || tree == nil || !settings.TLSEnabled || node.ValidateMasterResourceOrigin(origin) != nil {
		return nil, errors.New("invalid Master Local media configuration")
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return nil, err
	}
	edge, err := network.New(settings.PublicIngressTrustedProxyNetworks)
	if err != nil {
		return nil, err
	}
	h := &MasterLocalMedia{origin: origin, url: parsed, media: service, control: control, sessions: sessions, edge: edge, tree: tree, nginxMedia: settings.NginxMedia, reads: make(chan struct{}, maxMasterDirectReads)}
	router.GET("/api/v1/media/master-local/:resource", h.serve)
	router.HEAD("/api/v1/media/master-local/:resource", h.serve)
	return h, nil
}

func (h *MasterLocalMedia) serve(c *gin.Context) {
	noStore(c)
	c.Header("X-Content-Type-Options", "nosniff")
	if h == nil || h.edge == nil || c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery || !masterDirectObject.MatchString(c.Param("resource")) || !strings.EqualFold(c.Request.Host, h.url.Host) {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	identity := h.edge.Resolve(c.Request)
	if c.Request.TLS == nil && !(identity.FromTrustedProxy && h.edge.SecureAdmin(c.Request)) {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	origins := c.Request.Header.Values("Origin")
	if len(origins) > 1 || len(origins) == 1 && origins[0] != h.origin {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	values := c.Request.Header.Values("X-Media-Capability")
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
	if _, peer := network.AuthenticatedIngressFromContext(ctx); peer {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	current, lease, err := h.control.AcquireCurrentIngress(ctx)
	if err != nil || lease == nil {
		if lease != nil {
			lease.Release()
		}
		detail(c, http.StatusServiceUnavailable, "Resource access unavailable")
		return
	}
	defer lease.Release()
	master, err := h.control.IdentityState(ctx)
	if err != nil || master.Role != "Master" || current.NodeID != master.ID || current.PublicOrigin != h.origin {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	ctx, err = store.BindIngressPrerequisite(ctx, lease)
	if err != nil {
		detail(c, http.StatusServiceUnavailable, "Resource access unavailable")
		return
	}
	ctx, admission := network.WithPublicAdmission(ctx)
	defer admission.Abort()
	ctx, err = network.WithLocalPublicIngress(ctx, network.LocalPublicIngress{NodeID: current.NodeID, Generation: current.Generation, PublicOrigin: current.PublicOrigin})
	if err != nil {
		detail(c, http.StatusServiceUnavailable, "Resource access unavailable")
		return
	}
	claim, err := h.control.VerifyMasterLocalMediaCapability(ctx, values[0], c.Param("resource"))
	if err != nil || !h.sessions.CheckDirectSession(claim.SessionID) {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	deadline := time.Unix(claim.ExpiresAt, 0)
	if !deadline.After(time.Now()) {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	controller := http.NewResponseController(c.Writer)
	if controller.SetWriteDeadline(deadline) != nil {
		detail(c, http.StatusServiceUnavailable, "Resource access unavailable")
		return
	}
	defer controller.SetWriteDeadline(time.Time{})
	bounded, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	stream, checked, err := h.media.OpenOpaqueMasterLocalMedia(bounded, h.tree, h.sessions, values[0], c.Param("resource"), func(size int64) bool {
		return opaqueBrowserCipherRange(c.Request, size)
	})
	if err != nil {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	defer stream.Close()
	if checked.ExpiresAt != claim.ExpiresAt || !h.sessions.CheckDirectSession(checked.SessionID) || !deadline.After(time.Now()) || bounded.Err() != nil || lease.Commit() != nil || !admission.Commit() {
		detail(c, http.StatusServiceUnavailable, "Resource access unavailable")
		return
	}
	c.Request = c.Request.WithContext(bounded)
	c.Header("Content-Type", "application/octet-stream")
	http.ServeContent(c.Writer, opaqueEmptyRangeRequest(c.Request, stream.Info.Size(), h.nginxMedia), "blob", time.Time{}, stream.Reader)
	if verified, ok := stream.Reader.(interface{ Err() error }); ok && verified.Err() != nil {
		panic(http.ErrAbortHandler)
	}
}
