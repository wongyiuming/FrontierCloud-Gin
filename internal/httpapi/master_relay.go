package httpapi

import (
	"context"
	"errors"
	"net/http"
	"path"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const masterRelayReadDrain = 30 * time.Minute

var masterRelayID = regexp.MustCompile(`^[a-f0-9]{64}$`)

// MasterRelay admits only Master-owned encrypted resources from the current,
// authenticated ingress. Resource bytes never pass through a generic URL proxy.
type MasterRelay struct {
	media      *media.Service
	control    *node.Service
	sessions   *mediacrypto.Manager
	reads      chan struct{}
	opaqueTree *sealedtree.SQLStore
}

// ConfigureMasterRelay mounts the authenticated peer-only reader at startup.
func (p *Public) ConfigureMasterRelay(router *gin.Engine, control *node.Service) error {
	reader, err := RegisterMasterRelay(router, p.media, control, p.crypto)
	if err != nil {
		return err
	}
	p.masterRelay = reader
	follower, err := registerFollowerRelay(router, p.media, control, p.crypto)
	if err != nil {
		return err
	}
	p.followerRelay = follower
	return nil
}

func RegisterMasterRelay(router *gin.Engine, service *media.Service, control *node.Service, sessions *mediacrypto.Manager) (*MasterRelay, error) {
	if router == nil || service == nil || control == nil || sessions == nil {
		return nil, errors.New("incomplete Master relay configuration")
	}
	h := &MasterRelay{media: service, control: control, sessions: sessions, reads: make(chan struct{}, 4)}
	router.GET("/api/v1/media/master-relay/:resource", h.serve)
	router.HEAD("/api/v1/media/master-relay/:resource", h.serve)
	return h, nil
}

// Issue is called by Master key authorization while the current ingress lease
// is held. The returned bearer belongs only in the X-Media-Relay header.
func (h *MasterRelay) Issue(ctx context.Context, object store.MediaObject, binding, sessionID string) (string, map[string]string, int64, error) {
	if h == nil || h.opaqueTree != nil {
		return "", nil, 0, media.ErrUnavailable
	}
	ctx, err := h.sessions.WithDirectSession(ctx, binding, sessionID)
	if err != nil {
		return "", nil, 0, err
	}
	var source, token string
	if object.Kind == "lyric" {
		source, token, err = h.media.MasterLyricRelaySource(ctx, object)
	} else {
		source, token, err = h.media.MasterRelaySource(ctx, object)
	}
	if err != nil {
		return "", nil, 0, err
	}
	claim, err := h.control.VerifyMasterRelayCapability(ctx, token, object.ID)
	if err != nil {
		return "", nil, 0, err
	}
	return source, map[string]string{"X-Media-Relay": token}, claim.ExpiresAt, nil
}

// IssueOpaqueMedia uses the current peer ingress and the Master Relay policy;
// the caller retains the enclosing ingress/tree admission until commit.
func (h *MasterRelay) IssueOpaqueMedia(ctx context.Context, object store.MediaObject, objectID, binding, sessionID string) (media.OpaqueSourceDetails, map[string]string, int64, error) {
	var empty media.OpaqueSourceDetails
	if h == nil || h.opaqueTree == nil {
		return empty, nil, 0, media.ErrUnavailable
	}
	ctx, err := h.sessions.WithDirectSession(ctx, binding, sessionID)
	if err != nil {
		return empty, nil, 0, err
	}
	details, err := h.media.OpaqueMasterPeerMedia(ctx, h.opaqueTree, object, objectID, "Relay", "")
	if err != nil {
		return empty, nil, 0, err
	}
	claim, err := h.control.VerifyMasterRelayCapability(ctx, details.Token, details.SourceObjectID)
	if err != nil || claim.ResourceID != claim.ObjectID || claim.Revision != details.Revision || !h.sessions.CheckDirectSession(claim.SessionID) {
		return empty, nil, 0, media.ErrUnavailable
	}
	return details, map[string]string{"X-Media-Relay": details.Token}, claim.ExpiresAt, nil
}

func (h *MasterRelay) serve(c *gin.Context) {
	if h != nil && h.opaqueTree != nil {
		values := c.Request.Header.Values("X-Media-Relay")
		if len(values) == 1 {
			claim, err := h.control.VerifyMasterRelayCapability(c.Request.Context(), values[0], c.Param("resource"))
			if err == nil && claim.ResourceID == claim.ObjectID {
				h.serveOpaqueMedia(c)
				return
			}
		}
		h.serveOpaqueLyric(c)
		return
	}
	noStore(c)
	assertion, ok := network.AuthenticatedIngressFromContext(c.Request.Context())
	if !ok || h == nil || c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery || !masterRelayID.MatchString(c.Param("resource")) {
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
	ctx, prerequisite, err := h.control.AcquireResourcePrerequisite(c.Request.Context())
	if err != nil {
		detail(c, http.StatusServiceUnavailable, "Resource access unavailable")
		return
	}
	if prerequisite != nil {
		defer prerequisite.Release()
	}
	c.Request = c.Request.WithContext(ctx)
	stream, claim, err := h.media.OpenMasterRelay(c.Request.Context(), values[0], c.Param("resource"))
	if err != nil {
		stream, claim, err = h.media.OpenMasterLyricRelay(c.Request.Context(), values[0], c.Param("resource"))
	}
	if err != nil {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	defer stream.File.Close()
	if !h.sessions.CheckDirectSession(claim.SessionID) {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	if prerequisite != nil {
		if prerequisite.Check(ctx) != nil {
			detail(c, http.StatusServiceUnavailable, "Resource access unavailable")
			return
		}
		prerequisite.Release()
	}
	controller := http.NewResponseController(c.Writer)
	if err := controller.SetWriteDeadline(time.Now().Add(masterRelayReadDrain)); err != nil {
		detail(c, http.StatusServiceUnavailable, "Resource access unavailable")
		return
	}
	defer controller.SetWriteDeadline(time.Time{})
	c.Header("Content-Type", "application/octet-stream")
	c.Header("X-Content-Type-Options", "nosniff")
	http.ServeContent(c.Writer, c.Request, path.Base(stream.Path), stream.Info.ModTime(), stream.File)
}

func (h *MasterRelay) serveOpaqueMedia(c *gin.Context) {
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
	grantDeadline := time.Unix(claim.ExpiresAt, 0)
	if !grantDeadline.After(time.Now()) {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	streamDeadline := time.Now().Add(masterRelayReadDrain)
	bounded, cancel := context.WithDeadline(c.Request.Context(), streamDeadline)
	defer cancel()
	controller := http.NewResponseController(c.Writer)
	if controller.SetWriteDeadline(streamDeadline) != nil {
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
	stream, err := h.media.OpenOpaqueMasterRelayMedia(ctx, h.opaqueTree, h.sessions, values[0], c.Param("resource"), func(size int64) bool { return opaqueBrowserCipherRange(c.Request, size) })
	if err != nil {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	defer stream.Close()
	if prerequisite.Check(ctx) != nil || !h.sessions.CheckDirectSession(claim.SessionID) || !grantDeadline.After(time.Now()) {
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
