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
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

// ConfigureOpaqueLyricTree is startup-only and deliberately has no production
// caller until the sealed catalog, all writers and recovery are fenced.
func (h *MasterDirect) ConfigureOpaqueLyricTree(tree *sealedtree.SQLStore) error {
	if h == nil || tree == nil || h.opaqueTree != nil {
		return errors.New("invalid opaque lyric configuration")
	}
	h.opaqueTree = tree
	return nil
}

// IssueOpaqueLyric exposes only a random lyric alias in its URL. The caller owns
// the ingress/tree lease until its buffered source response is committed.
func (h *MasterDirect) IssueOpaqueLyric(ctx context.Context, trackID, lyricID, binding, sessionID string) (string, map[string]string, string, error) {
	if h == nil || h.opaqueTree == nil {
		return "", nil, "", media.ErrUnavailable
	}
	ctx, err := h.sessions.WithDirectSession(ctx, binding, sessionID)
	if err != nil {
		return "", nil, "", err
	}
	source, token, err := h.media.OpaqueMasterLyricDirectSource(ctx, h.opaqueTree, trackID, lyricID, h.origin)
	if err != nil {
		return "", nil, "", err
	}
	u, err := url.Parse(source)
	if err != nil || u.Scheme != "https" || u.Host != h.url.Host || u.RawQuery != "" || u.Fragment != "" {
		return "", nil, "", media.ErrUnavailable
	}
	alias := path.Base(u.Path)
	if !masterDirectObject.MatchString(alias) || u.Path != "/api/v1/media/master-direct-lyric/"+alias {
		return "", nil, "", media.ErrUnavailable
	}
	claim, err := h.control.VerifyMasterDirectCapability(ctx, token, h.origin, alias)
	if err != nil || claim.ObjectID == claim.ResourceID || alias == lyricID || !h.sessions.CheckDirectSession(claim.SessionID) {
		return "", nil, "", media.ErrUnavailable
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
		return "", nil, "", media.ErrUnavailable
	}
	if _, exists := h.origins[claim.PublicOrigin]; !exists && len(h.origins) >= maxMasterDirectOrigins {
		return "", nil, "", media.ErrUnavailable
	}
	if h.origins[claim.PublicOrigin].Before(until) {
		h.origins[claim.PublicOrigin] = until
	}
	return source, map[string]string{"X-Media-Capability": token}, alias, nil
}

func (h *MasterDirect) serveOpaqueLyric(c *gin.Context) {
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
	deadline := time.Unix(claim.ExpiresAt, 0)
	if !deadline.After(time.Now()) {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	bounded, cancel := context.WithDeadline(c.Request.Context(), deadline)
	defer cancel()
	controller := http.NewResponseController(c.Writer)
	if controller.SetWriteDeadline(deadline) != nil {
		detail(c, http.StatusServiceUnavailable, "Resource access unavailable")
		return
	}
	defer controller.SetWriteDeadline(time.Time{})
	stream, checked, err := h.media.OpenOpaqueMasterLyricDirect(bounded, h.opaqueTree, h.sessions, values[0], h.origin, c.Param("resource"))
	if err != nil {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	defer stream.Close()
	if checked.PublicOrigin != origins[0] || checked.ExpiresAt != claim.ExpiresAt || !h.sessions.CheckDirectSession(checked.SessionID) || !deadline.After(time.Now()) {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	c.Request = c.Request.WithContext(bounded)
	c.Header("Content-Type", "application/octet-stream")
	http.ServeContent(c.Writer, c.Request, "blob", time.Time{}, stream.Reader)
	if verified, ok := stream.Reader.(interface{ Err() error }); ok && verified.Err() != nil {
		panic(http.ErrAbortHandler)
	}
}
