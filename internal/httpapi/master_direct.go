package httpapi

import (
	"context"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
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

const maxMasterDirectOrigins = 64
const maxMasterDirectReads = 8
const masterDirectReadDrain = 30 * time.Minute

var masterDirectObject = regexp.MustCompile(`^[a-f0-9]{64}$`)

// MasterDirect is a narrowly scoped public resource reader. Its origin is
// explicit deployment configuration, not derived from the request or node
// control address. The registry permits browser preflight for previously
// issued origins only until the corresponding short-lived grants expire.
type MasterDirect struct {
	origin     string
	url        *url.URL
	media      *media.Service
	control    *node.Service
	sessions   *mediacrypto.Manager
	edge       *network.Resolver
	mu         sync.Mutex
	origins    map[string]time.Time
	reads      chan struct{}
	opaqueTree *sealedtree.SQLStore
	nginxMedia bool
}

// ConfigureMasterDirect is startup-only; an empty resource origin keeps the
// reader unavailable and never infers an address from another service role.
func (p *Public) ConfigureMasterDirect(router *gin.Engine, settings config.Config, control *node.Service) error {
	reader, err := RegisterMasterDirect(router, settings, settings.MasterResourceOrigin, p.media, control, p.crypto)
	if err != nil {
		return err
	}
	p.masterDirect = reader
	return nil
}

// RegisterMasterDirect mounts only GET, HEAD and CORS preflight. An empty
// resource origin leaves the feature disabled rather than inferring a host.
func RegisterMasterDirect(router *gin.Engine, settings config.Config, resourceOrigin string, service *media.Service, control *node.Service, sessions *mediacrypto.Manager) (*MasterDirect, error) {
	if resourceOrigin == "" {
		return nil, nil
	}
	if router == nil || service == nil || control == nil || sessions == nil || !settings.TLSEnabled || node.ValidateMasterResourceOrigin(resourceOrigin) != nil {
		return nil, errors.New("invalid Master direct resource configuration")
	}
	parsed, err := url.Parse(resourceOrigin)
	if err != nil {
		return nil, err
	}
	edge, err := network.New(settings.PublicIngressTrustedProxyNetworks)
	if err != nil {
		return nil, err
	}
	h := &MasterDirect{origin: resourceOrigin, url: parsed, media: service, control: control, sessions: sessions, edge: edge, origins: make(map[string]time.Time), reads: make(chan struct{}, maxMasterDirectReads), nginxMedia: settings.NginxMedia}
	router.GET("/api/v1/media/master-direct/:resource", h.serve)
	router.HEAD("/api/v1/media/master-direct/:resource", h.serve)
	router.OPTIONS("/api/v1/media/master-direct/:resource", h.serve)
	router.GET("/api/v1/media/master-direct-lyric/:resource", h.serve)
	router.HEAD("/api/v1/media/master-direct-lyric/:resource", h.serve)
	router.OPTIONS("/api/v1/media/master-direct-lyric/:resource", h.serve)
	return h, nil
}

// Issue returns a URL and a separate capability header. The caller must hold
// the verifier's admission fence until its response commits.
func (h *MasterDirect) Issue(ctx context.Context, object store.MediaObject, binding, sessionID string) (string, map[string]string, error) {
	if h == nil || h.opaqueTree != nil {
		return "", nil, media.ErrUnavailable
	}
	ctx, err := h.sessions.WithDirectSession(ctx, binding, sessionID)
	if err != nil {
		return "", nil, err
	}
	var source, token string
	if object.Kind == "lyric" {
		source, token, err = h.media.MasterLyricDirectSource(ctx, object, h.origin)
	} else {
		source, token, err = h.media.MasterDirectSource(ctx, object, h.origin)
	}
	if err != nil {
		return "", nil, err
	}
	claim, err := h.control.VerifyMasterDirectCapability(ctx, token, h.origin, object.ID)
	if err != nil {
		return "", nil, err
	}
	now, until := time.Now(), time.Unix(claim.ExpiresAt, 0)
	h.mu.Lock()
	defer h.mu.Unlock()
	for origin, deadline := range h.origins {
		if !deadline.After(now) {
			delete(h.origins, origin)
		}
	}
	if _, exists := h.origins[claim.PublicOrigin]; !exists && len(h.origins) >= maxMasterDirectOrigins {
		return "", nil, media.ErrUnavailable
	}
	if h.origins[claim.PublicOrigin].Before(until) {
		h.origins[claim.PublicOrigin] = until
	}
	return source, map[string]string{"X-Media-Capability": token}, nil
}

// IssueOpaqueMedia issues an encrypted-tree audio/video grant under the
// caller's current ingress/tree admission. It also records the sole allowed
// browser origin for the bounded CORS preflight window.
func (h *MasterDirect) IssueOpaqueMedia(ctx context.Context, object store.MediaObject, objectID, binding, sessionID string) (media.OpaqueSourceDetails, map[string]string, int64, error) {
	var empty media.OpaqueSourceDetails
	if h == nil || h.opaqueTree == nil {
		return empty, nil, 0, media.ErrUnavailable
	}
	ctx, err := h.sessions.WithDirectSession(ctx, binding, sessionID)
	if err != nil {
		return empty, nil, 0, err
	}
	details, err := h.media.OpaqueMasterPeerMedia(ctx, h.opaqueTree, object, objectID, "Direct", h.origin)
	if err != nil {
		return empty, nil, 0, err
	}
	claim, err := h.control.VerifyMasterDirectCapability(ctx, details.Token, h.origin, details.SourceObjectID)
	if err != nil || claim.ObjectID != claim.ResourceID || claim.Revision != details.Revision || !h.sessions.CheckDirectSession(claim.SessionID) {
		return empty, nil, 0, media.ErrUnavailable
	}
	now, until := time.Now(), time.Unix(claim.ExpiresAt, 0)
	h.mu.Lock()
	defer h.mu.Unlock()
	for origin, deadline := range h.origins {
		if !deadline.After(now) {
			delete(h.origins, origin)
		}
	}
	if !until.After(now) {
		return empty, nil, 0, media.ErrUnavailable
	}
	if _, exists := h.origins[claim.PublicOrigin]; !exists && len(h.origins) >= maxMasterDirectOrigins {
		return empty, nil, 0, media.ErrUnavailable
	}
	if h.origins[claim.PublicOrigin].Before(until) {
		h.origins[claim.PublicOrigin] = until
	}
	return details, map[string]string{"X-Media-Capability": details.Token}, claim.ExpiresAt, nil
}

func (h *MasterDirect) originAllowed(origin string, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	until, ok := h.origins[origin]
	if ok && !until.After(now) {
		delete(h.origins, origin)
		return false
	}
	return ok
}

func validMasterDirectPreflight(r *http.Request) bool {
	methods, headers := r.Header.Values("Access-Control-Request-Method"), r.Header.Values("Access-Control-Request-Headers")
	if len(methods) != 1 || (methods[0] != "GET" && methods[0] != "HEAD") || len(headers) != 1 || len(headers[0]) > 256 {
		return false
	}
	seen, capability := map[string]bool{}, false
	for _, item := range strings.Split(headers[0], ",") {
		name := strings.ToLower(strings.TrimSpace(item))
		if seen[name] {
			return false
		}
		seen[name] = true
		switch name {
		case "x-media-capability":
			capability = true
		case "range", "if-range", "if-none-match", "if-modified-since":
		default:
			return false
		}
	}
	return capability
}

func (h *MasterDirect) serve(c *gin.Context) {
	if h != nil && h.opaqueTree != nil {
		if c.FullPath() == "/api/v1/media/master-direct-lyric/:resource" {
			h.serveOpaqueLyric(c)
		} else {
			h.serveOpaqueMedia(c)
		}
		return
	}
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
	if len(origins) != 1 || origins[0] == "" {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	c.Header("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
	// Only an origin with an issued, unexpired grant receives CORS on error
	// responses. This lets the browser distinguish a revoked authorization
	// from a network failure without opening CORS to arbitrary origins.
	if c.Request.Method != http.MethodOptions && h.originAllowed(origins[0], time.Now()) {
		c.Header("Access-Control-Allow-Origin", origins[0])
		c.Header("Access-Control-Expose-Headers", "Content-Length, Content-Range, Accept-Ranges, ETag, Last-Modified")
	}
	if c.Request.Method == http.MethodOptions {
		if !validMasterDirectPreflight(c.Request) || !h.originAllowed(origins[0], time.Now()) {
			detail(c, http.StatusForbidden, "Resource access unavailable")
			return
		}
		c.Header("Access-Control-Allow-Origin", origins[0])
		c.Header("Access-Control-Allow-Methods", "GET, HEAD")
		c.Header("Access-Control-Allow-Headers", "X-Media-Capability, Range, If-Range, If-None-Match, If-Modified-Since")
		c.Header("Access-Control-Max-Age", "60")
		c.Status(http.StatusNoContent)
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
	var stream *media.Stream
	var claim node.MasterDirectClaim
	var err error
	if c.FullPath() == "/api/v1/media/master-direct-lyric/:resource" {
		stream, claim, err = h.media.OpenMasterLyricDirect(c.Request.Context(), values[0], h.origin, c.Param("resource"))
	} else {
		stream, claim, err = h.media.OpenMasterDirect(c.Request.Context(), values[0], h.origin, c.Param("resource"))
	}
	if err != nil {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	defer stream.File.Close()
	if origins[0] != claim.PublicOrigin || !h.sessions.CheckDirectSession(claim.SessionID) {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	// Admission is fixed at the start; a selected ingress or policy change
	// does not tear down this read. A bounded write deadline prevents an idle
	// downstream from retaining the resource slot indefinitely.
	controller := http.NewResponseController(c.Writer)
	if err := controller.SetWriteDeadline(time.Now().Add(masterDirectReadDrain)); err != nil {
		detail(c, http.StatusServiceUnavailable, "Resource access unavailable")
		return
	}
	defer controller.SetWriteDeadline(time.Time{})
	c.Header("Access-Control-Allow-Origin", claim.PublicOrigin)
	c.Header("Access-Control-Expose-Headers", "Content-Length, Content-Range, Accept-Ranges, ETag, Last-Modified")
	contentType := mime.TypeByExtension(path.Ext(stream.Path))
	if contentType == "" || stream.Encryption != nil {
		contentType = "application/octet-stream"
	}
	c.Header("Content-Type", contentType)
	http.ServeContent(c.Writer, c.Request, path.Base(stream.Path), stream.Info.ModTime(), stream.File)
}

func (h *MasterDirect) serveOpaqueMedia(c *gin.Context) {
	noStore(c)
	c.Header("X-Content-Type-Options", "nosniff")
	if h.edge == nil || c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery || !masterDirectObject.MatchString(c.Param("resource")) || !strings.EqualFold(c.Request.Host, h.url.Host) {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	identity := h.edge.Resolve(c.Request)
	if c.Request.TLS == nil && !(identity.FromTrustedProxy && h.edge.SecureAdmin(c.Request)) {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	origins := c.Request.Header.Values("Origin")
	if len(origins) != 1 || origins[0] == "" {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	c.Header("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
	if h.originAllowed(origins[0], time.Now()) {
		c.Header("Access-Control-Allow-Origin", origins[0])
		c.Header("Access-Control-Expose-Headers", "Content-Length, Content-Range, Accept-Ranges, ETag")
	}
	if c.Request.Method == http.MethodOptions {
		if !validMasterDirectPreflight(c.Request) || !h.originAllowed(origins[0], time.Now()) {
			detail(c, http.StatusForbidden, "Resource access unavailable")
			return
		}
		c.Header("Access-Control-Allow-Methods", "GET, HEAD")
		c.Header("Access-Control-Allow-Headers", "X-Media-Capability, Range, If-Range, If-None-Match, If-Modified-Since")
		c.Header("Access-Control-Max-Age", "60")
		c.Status(http.StatusNoContent)
		return
	}
	values := c.Request.Header.Values("X-Media-Capability")
	if len(values) != 1 || values[0] == "" || len(values[0]) > 4096 {
		detail(c, http.StatusUnauthorized, "Resource authorization invalid or expired")
		return
	}
	claim, err := h.control.VerifyMasterDirectCapability(c.Request.Context(), values[0], h.origin, c.Param("resource"))
	if err != nil || claim.PublicOrigin != origins[0] || !h.sessions.CheckDirectSession(claim.SessionID) {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	select {
	case h.reads <- struct{}{}:
		defer func() { <-h.reads }()
	default:
		detail(c, http.StatusServiceUnavailable, "Resource access busy")
		return
	}
	grantDeadline := time.Unix(claim.ExpiresAt, 0)
	if !grantDeadline.After(time.Now()) {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	streamDeadline := time.Now().Add(masterDirectReadDrain)
	bounded, cancel := context.WithDeadline(c.Request.Context(), streamDeadline)
	defer cancel()
	controller := http.NewResponseController(c.Writer)
	if controller.SetWriteDeadline(streamDeadline) != nil {
		detail(c, http.StatusServiceUnavailable, "Resource access unavailable")
		return
	}
	defer controller.SetWriteDeadline(time.Time{})
	stream, err := h.media.OpenOpaqueMasterDirectMedia(bounded, h.opaqueTree, h.sessions, values[0], h.origin, c.Param("resource"), func(size int64) bool { return opaqueBrowserCipherRange(c.Request, size) })
	if err != nil {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	defer stream.Close()
	if !h.sessions.CheckDirectSession(claim.SessionID) || !grantDeadline.After(time.Now()) {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	c.Request = c.Request.WithContext(bounded)
	c.Header("Content-Type", "application/octet-stream")
	http.ServeContent(c.Writer, opaqueEmptyRangeRequest(c.Request, stream.Info.Size(), h.nginxMedia), "blob", time.Time{}, stream.Reader)
	if verified, ok := stream.Reader.(interface{ Err() error }); ok && verified.Err() != nil {
		panic(http.ErrAbortHandler)
	}
}
