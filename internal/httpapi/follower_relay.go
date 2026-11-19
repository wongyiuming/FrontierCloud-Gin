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
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// FollowerRelay serves authorized native objects over the selected path:
// browser -> authenticated ingress -> Master -> the object's actual owner.
type FollowerRelay struct {
	media    *media.Service
	control  *node.Service
	sessions *mediacrypto.Manager
	reads    chan struct{}
}

func registerFollowerRelay(router *gin.Engine, service *media.Service, control *node.Service, sessions *mediacrypto.Manager) (*FollowerRelay, error) {
	if router == nil || service == nil || control == nil || sessions == nil {
		return nil, errors.New("incomplete follower relay configuration")
	}
	h := &FollowerRelay{media: service, control: control, sessions: sessions, reads: make(chan struct{}, 4)}
	router.GET("/api/v1/media/follower-relay/:resource", h.serve)
	router.HEAD("/api/v1/media/follower-relay/:resource", h.serve)
	return h, nil
}

func (h *FollowerRelay) Issue(ctx context.Context, object store.MediaObject, binding, sessionID string) (string, map[string]string, int64, error) {
	if h == nil {
		return "", nil, 0, media.ErrUnavailable
	}
	ctx, err := h.sessions.WithDirectSession(ctx, binding, sessionID)
	if err != nil {
		return "", nil, 0, err
	}
	source, token, err := h.media.FollowerRelaySource(ctx, object)
	if err != nil {
		return "", nil, 0, err
	}
	claim, err := h.control.VerifyFollowerRelayCapability(ctx, token, object.ID)
	if err != nil {
		return "", nil, 0, err
	}
	return source, map[string]string{"X-Media-Relay": token}, claim.ExpiresAt, nil
}

func (h *FollowerRelay) serve(c *gin.Context) {
	noStore(c)
	assertion, ok := network.AuthenticatedIngressFromContext(c.Request.Context())
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
	ctx, prerequisite, err := h.control.AcquireResourcePrerequisite(c.Request.Context())
	if err != nil {
		detail(c, http.StatusServiceUnavailable, "Resource access unavailable")
		return
	}
	if prerequisite != nil {
		defer prerequisite.Release()
	}
	c.Request = c.Request.WithContext(ctx)
	row, claim, err := h.media.FollowerRelayObject(c.Request.Context(), values[0], c.Param("resource"))
	if err != nil || !h.sessions.CheckDirectSession(claim.SessionID) {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	meta, err := h.media.Encryption(c.Request.Context(), row.ID)
	if err != nil {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	response, err := h.control.OpenFollowerRelayStream(c.Request.Context(), values[0], row, meta, h.sessions, c.Request.Method, c.Request.Header.Get("Range"))
	if errors.Is(err, node.ErrFollowerRelayRange) {
		c.Header("Content-Range", "bytes */"+strconv.FormatInt(row.Bytes, 10))
		detail(c, http.StatusRequestedRangeNotSatisfiable, "Invalid range")
		return
	}
	if err != nil {
		detail(c, http.StatusBadGateway, "Resource access unavailable")
		return
	}
	defer response.Body.Close()
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
