package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"path"
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

// MasterLocalLyric reads Master-owned bytes in-process while Master is the
// current ingress. It is explicitly installed only in isolated fixtures until
// the encrypted-tree lifecycle and deployment gates are complete.
type MasterLocalLyric struct {
	origin   string
	url      *url.URL
	media    *media.Service
	control  *node.Service
	sessions *mediacrypto.Manager
	edge     *network.Resolver
	tree     *sealedtree.SQLStore
	reads    chan struct{}
}

func RegisterOpaqueMasterLocalLyric(router *gin.Engine, settings config.Config, origin string, service *media.Service, control *node.Service, sessions *mediacrypto.Manager, tree *sealedtree.SQLStore) (*MasterLocalLyric, error) {
	if router == nil || service == nil || control == nil || sessions == nil || tree == nil || !settings.TLSEnabled || node.ValidateMasterResourceOrigin(origin) != nil {
		return nil, errors.New("invalid Master Local lyric configuration")
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return nil, err
	}
	edge, err := network.New(settings.PublicIngressTrustedProxyNetworks)
	if err != nil {
		return nil, err
	}
	h := &MasterLocalLyric{origin: origin, url: parsed, media: service, control: control, sessions: sessions, edge: edge, tree: tree, reads: make(chan struct{}, maxMasterDirectReads)}
	router.GET("/api/v1/media/master-local-lyric/:resource", h.serve)
	router.HEAD("/api/v1/media/master-local-lyric/:resource", h.serve)
	return h, nil
}

func (h *MasterLocalLyric) Issue(ctx context.Context, trackID, lyricID, binding, sessionID string) (string, map[string]string, string, int64, error) {
	if h == nil || h.tree == nil {
		return "", nil, "", 0, media.ErrUnavailable
	}
	ctx, err := h.sessions.WithDirectSession(ctx, binding, sessionID)
	if err != nil {
		return "", nil, "", 0, err
	}
	source, token, err := h.media.OpaqueMasterLyricLocalSource(ctx, h.tree, trackID, lyricID)
	if err != nil {
		return "", nil, "", 0, err
	}
	u, err := url.Parse(source)
	if err != nil || u.Scheme != "https" || u.Host != h.url.Host || u.RawQuery != "" || u.Fragment != "" {
		return "", nil, "", 0, media.ErrUnavailable
	}
	alias := path.Base(u.Path)
	if !masterDirectObject.MatchString(alias) || u.Path != "/api/v1/media/master-local-lyric/"+alias || alias == lyricID {
		return "", nil, "", 0, media.ErrUnavailable
	}
	claim, err := h.control.VerifyMasterLocalLyricCapability(ctx, token, alias)
	if err != nil || claim.PublicOrigin != h.origin || !h.sessions.CheckDirectSession(claim.SessionID) || claim.ExpiresAt <= time.Now().Unix() {
		return "", nil, "", 0, media.ErrUnavailable
	}
	return source, map[string]string{"X-Media-Capability": token}, alias, claim.ExpiresAt, nil
}

func (h *MasterLocalLyric) serve(c *gin.Context) {
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
	claim, err := h.control.VerifyMasterLocalLyricCapability(ctx, values[0], c.Param("resource"))
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
	stream, checked, err := h.media.OpenOpaqueMasterLyricLocal(bounded, h.tree, h.sessions, values[0], c.Param("resource"))
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
	http.ServeContent(c.Writer, c.Request, "blob", time.Time{}, stream.Reader)
	if verified, ok := stream.Reader.(interface{ Err() error }); ok && verified.Err() != nil {
		panic(http.ErrAbortHandler)
	}
}
