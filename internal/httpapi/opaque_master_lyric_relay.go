package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

// ConfigureOpaqueLyricTree is startup-only. Production leaves it uninstalled
// until the sealed catalog and all read, write and recovery fences are ready.
func (h *MasterRelay) ConfigureOpaqueLyricTree(tree *sealedtree.SQLStore) error {
	if h == nil || tree == nil || h.opaqueTree != nil {
		return errors.New("invalid opaque lyric relay configuration")
	}
	h.opaqueTree = tree
	return nil
}

func (h *MasterRelay) IssueOpaqueLyric(ctx context.Context, trackID, lyricID, binding, sessionID string) (string, map[string]string, string, int64, error) {
	if h == nil || h.opaqueTree == nil {
		return "", nil, "", 0, media.ErrUnavailable
	}
	ctx, err := h.sessions.WithDirectSession(ctx, binding, sessionID)
	if err != nil {
		return "", nil, "", 0, err
	}
	source, token, err := h.media.OpaqueMasterLyricRelaySource(ctx, h.opaqueTree, trackID, lyricID)
	if err != nil {
		return "", nil, "", 0, err
	}
	u, err := url.Parse(source)
	assertion, ok := network.AuthenticatedIngressFromContext(ctx)
	if err != nil || !ok || u.Scheme != "https" || u.Scheme+"://"+u.Host != assertion.PublicOrigin || u.RawQuery != "" || u.Fragment != "" {
		return "", nil, "", 0, media.ErrUnavailable
	}
	alias := path.Base(u.Path)
	if !masterRelayID.MatchString(alias) || u.Path != "/api/v1/media/master-relay/"+alias {
		return "", nil, "", 0, media.ErrUnavailable
	}
	claim, err := h.control.VerifyMasterRelayCapability(ctx, token, alias)
	if err != nil || claim.ObjectID == claim.ResourceID || alias == lyricID || !h.sessions.CheckDirectSession(claim.SessionID) || claim.ExpiresAt <= time.Now().Unix() {
		return "", nil, "", 0, media.ErrUnavailable
	}
	return source, map[string]string{"X-Media-Relay": token}, alias, claim.ExpiresAt, nil
}

func (h *MasterRelay) serveOpaqueLyric(c *gin.Context) {
	noStore(c)
	assertion, ok := network.AuthenticatedIngressFromContext(c.Request.Context())
	if !ok || c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery || !masterRelayID.MatchString(c.Param("resource")) {
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
	claim, err := h.control.VerifyMasterRelayCapability(c.Request.Context(), values[0], c.Param("resource"))
	if err != nil || !h.sessions.CheckDirectSession(claim.SessionID) {
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
	ctx, prerequisite, err := h.control.AcquireResourcePrerequisite(bounded)
	if err != nil || prerequisite == nil {
		if prerequisite != nil {
			prerequisite.Release()
		}
		detail(c, http.StatusServiceUnavailable, "Resource access unavailable")
		return
	}
	defer prerequisite.Release()
	stream, checked, err := h.media.OpenOpaqueMasterLyricRelay(ctx, h.opaqueTree, h.sessions, values[0], c.Param("resource"))
	if err != nil {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	defer stream.Close()
	if prerequisite.Check(ctx) != nil || checked.ExpiresAt != claim.ExpiresAt || !h.sessions.CheckDirectSession(checked.SessionID) || !deadline.After(time.Now()) {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	prerequisite.Release()
	c.Request = c.Request.WithContext(ctx)
	c.Header("Content-Type", "application/octet-stream")
	c.Header("X-Content-Type-Options", "nosniff")
	http.ServeContent(c.Writer, c.Request, "blob", time.Time{}, stream.Reader)
	if verified, ok := stream.Reader.(interface{ Err() error }); ok && verified.Err() != nil {
		panic(http.ErrAbortHandler)
	}
}
