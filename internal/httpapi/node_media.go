package httpapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/logsafe"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// A browser preflight cannot carry the resource bearer. Only an authenticated,
// fresh Master heartbeat may supply its allowed origin; the subsequent read
// still needs the object-bound capability. No request header chooses an origin.
func nodeMediaPreflight(c *gin.Context, observed func(context.Context) (store.PublicIngress, store.Relationship, error)) {
	nodeMediaOriginPreflight(c, func(ctx context.Context, requested string) bool {
		ingress, _, err := observed(ctx)
		return err == nil && ingress.PublicOrigin == requested
	})
}

func nodeMediaOriginPreflight(c *gin.Context, allows func(context.Context, string) bool) {
	noStore(c)
	c.Header("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
	origins := c.Request.Header.Values("Origin")
	if len(origins) != 1 || c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery || !masterRelayID.MatchString(c.Param("object")) || !validMasterDirectPreflight(c.Request) {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	if !allows(c.Request.Context(), origins[0]) {
		detail(c, http.StatusForbidden, "Resource access unavailable")
		return
	}
	c.Header("Access-Control-Allow-Origin", origins[0])
	c.Header("Access-Control-Allow-Methods", "GET, HEAD")
	c.Header("Access-Control-Allow-Headers", "X-Media-Capability, Range, If-Range, If-None-Match, If-Modified-Since")
	c.Header("Access-Control-Max-Age", "60")
	c.Status(http.StatusNoContent)
}

func capabilityInput(c *gin.Context, header string) (string, bool) {
	query := c.Request.URL.Query()["token"]
	headers := c.Request.Header.Values(header)
	if len(query) > 1 || len(headers) > 1 {
		return "", false
	}
	token := ""
	if len(query) == 1 {
		token = query[0]
	}
	if len(headers) == 1 {
		if token != "" && token != headers[0] {
			return "", false
		}
		token = headers[0]
	}
	return token, token != ""
}

type legacyNodeReadGuard interface {
	WithRead(context.Context, string, string, func(context.Context) error) error
	ReadyFor(*node.Service, any) bool
}

func RegisterNodeMedia(router *gin.Engine, settings config.Config, resolver *network.Resolver, control *node.Service, volume *media.Service) {
	registerNodeMedia(router, settings, resolver, control, volume, nil)
}

func registerNodeMediaGuarded(router *gin.Engine, settings config.Config, resolver *network.Resolver, control *node.Service, volume *media.Service, guard legacyNodeReadGuard) error {
	if router == nil || resolver == nil || control == nil || volume == nil || guard == nil || settings.NginxMedia {
		return node.ErrCapability
	}
	registerNodeMedia(router, settings, resolver, control, volume, guard)
	return nil
}

func registerNodeMedia(router *gin.Engine, settings config.Config, resolver *network.Resolver, control *node.Service, volume *media.Service, guard legacyNodeReadGuard) {
	serveLegacy := func(c *gin.Context) {
		if !nodeHTTPS(c, settings, resolver) {
			return
		}
		if c.Request.Method == http.MethodOptions && c.Request.Header.Get("Access-Control-Request-Method") != "" && c.Request.URL.RawQuery == "" && !c.Request.URL.ForceQuery {
			nodeMediaPreflight(c, control.ObservedPublicIngress)
			return
		}
		if challenges := c.Request.Header.Values("X-Fc-Plain-Probe"); len(challenges) != 0 {
			tokens := c.Request.Header.Values("X-Media-Capability")
			if c.Request.Method != http.MethodGet || c.Request.URL.Path != node.NativePlainMediaProbePath || c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery || c.Request.ContentLength > 0 || len(c.Request.TransferEncoding) != 0 || len(challenges) != 1 || !node.ValidIdentifier(challenges[0]) || len(tokens) != 1 || tokens[0] == "" || len(tokens[0]) > 4096 {
				detail(c, http.StatusBadRequest, "Invalid plain media probe")
				return
			}
			relation, err := control.Authenticate(c.Request.Context(), c.Request.Header, c.Request.Method, c.Request.URL.EscapedPath(), nil, false, false)
			if err != nil {
				detail(c, http.StatusUnauthorized, "Invalid relationship authentication")
				return
			}
			signed, err := control.VerifyOwnedPlainMediaProbe(c.Request.Context(), relation, challenges[0], tokens[0])
			if err != nil {
				detail(c, http.StatusServiceUnavailable, "Plain media probe unavailable")
				return
			}
			c.JSON(http.StatusOK, signed)
			return
		}
		token, ok := capabilityInput(c, "X-Media-Capability")
		if !ok {
			detail(c, 401, "Media capability invalid or expired")
			return
		}
		relation, payload, err := control.VerifyOwnedMedia(c.Request.Context(), token, c.Param("object"))
		if err != nil {
			if errors.Is(err, node.ErrCapability) {
				detail(c, 401, "Media capability invalid or expired")
			} else {
				internalError(c, err)
			}
			return
		}
		// v2 retains the existing paired-Master CORS contract. The v3 token's
		// authenticated origin is an explicit part of this particular grant.
		expectedOrigin := relation.Endpoint
		ingressGrant := payload["kind"] == "public-ingress-media-v1" || payload["kind"] == "public-ingress-plain-v1"
		if ingressGrant {
			noStore(c)
			// New browser capabilities travel in a header, never in a URL
			// that an intermediary may record in an error log.
			if len(c.Request.URL.Query()["token"]) != 0 || c.GetHeader("X-Media-Capability") == "" {
				detail(c, 401, "Media capability invalid or expired")
				return
			}
			expectedOrigin, _ = payload["origin"].(string)
		}
		c.Header("Vary", "Origin")
		origins := c.Request.Header.Values("Origin")
		if len(origins) > 1 || len(origins) == 1 && origins[0] != expectedOrigin {
			detail(c, 403, "Unpaired media origin")
			return
		}
		if len(origins) == 1 {
			c.Header("Access-Control-Allow-Origin", origins[0])
			c.Header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Range, If-Range, If-None-Match, If-Modified-Since")
			c.Header("Access-Control-Expose-Headers", "Content-Length, Content-Range, Accept-Ranges, ETag, Last-Modified")
		}
		if c.Request.Method == "OPTIONS" {
			c.Status(200)
			return
		}
		digest, plainGrant := payload["content_sha256"].(string)
		var stream *media.Stream
		var verifiedReader io.ReadSeeker
		var readLease func()
		if ingressGrant && plainGrant {
			stream, verifiedReader, readLease, err = volume.OpenVerifiedOwnedPlain(c.Request.Context(), c.Param("object"), digest)
		} else {
			stream, err = volume.OwnedStream(c.Request.Context(), c.Param("object"))
		}
		if err != nil {
			if ingressGrant && plainGrant && errors.Is(err, store.ErrNodeState) {
				detail(c, 409, "Resource changed since authorization")
			} else if errors.Is(err, os.ErrNotExist) || errors.Is(err, media.ErrPath) {
				detail(c, 404, "Resource not found")
			} else {
				internalError(c, err)
			}
			return
		}
		if readLease != nil {
			defer readLease()
		}
		defer stream.File.Close()
		if ingressGrant {
			if stream.Encryption == nil && !plainGrant || stream.Encryption != nil && plainGrant {
				detail(c, 409, "Resource changed since authorization")
				return
			}
			descriptor, descriptorErr := protocol.IngressMediaDescriptor(stream.Info.Size(), stream.Encryption)
			if descriptorErr != nil || descriptor != payload["descriptor"] {
				detail(c, 409, "Resource changed since authorization")
				return
			}
		}
		if !settings.NginxMedia || ingressGrant && plainGrant {
			logical, _ := payload["g"].(string)
			readCtx, release, err := control.ProtectOwnedRead(c.Request.Context(), relation.ID, logical, stream.ObjectID, "media", func() { _ = stream.File.Close() })
			if err != nil {
				detail(c, 409, "Resource read is fenced by migration or node state")
				return
			}
			defer release()
			c.Request = c.Request.WithContext(readCtx)
		}
		// The standalone HTTPS listener is also the public edge. Browser query
		// capabilities must not expose the metadata formerly hidden by Nginx.
		// Header-based server downloads retain placement proof for MediaRead.
		if !ingressGrant && (settings.DeploymentMode != config.DeploymentStorage || c.GetHeader("X-Media-Capability") != "") {
			for header, key := range map[string]string{"X-Media-Resource-ID": "g", "X-Media-Owner-ID": "o", "X-Media-Parent-Request-ID": "request_id", "X-Audit-Trace-ID": "trace_id"} {
				v, _ := payload[key].(string)
				c.Header(header, v)
			}
			c.Header("X-Media-Object-ID", stream.ObjectID)
		} else {
			c.Header("X-Audit-Trace-ID", "")
		}
		contentType := mime.TypeByExtension(path.Ext(stream.Path))
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		meta := stream.Encryption
		if meta != nil {
			contentType = "application/octet-stream"
			noStore(c)
		}
		c.Header("Content-Type", contentType)
		if settings.NginxMedia && !(ingressGrant && plainGrant) {
			prefix := "/_protected_media/"
			if meta != nil {
				prefix = "/_protected_cipher/"
			}
			c.Header("X-Accel-Redirect", prefix+media.QuotePath(stream.Path))
			c.Status(200)
			return
		}
		reader := io.ReadSeeker(stream.File)
		if verifiedReader != nil {
			reader = verifiedReader
		}
		http.ServeContent(c.Writer, c.Request, path.Base(stream.Path), stream.Info.ModTime(), reader)
		if verified, ok := verifiedReader.(interface{ Err() error }); ok && verified.Err() != nil {
			slog.Warn("verified media read interrupted", "error_type", logsafe.ErrorType(verified.Err()), "request_id", c.GetString("request_id"))
			panic(http.ErrAbortHandler)
		}
	}
	serve := func(c *gin.Context) {
		if guard == nil || c.Request.Method == http.MethodOptions {
			serveLegacy(c)
			return
		}
		noStore(c)
		if !nodeHTTPS(c, settings, resolver) {
			return
		}
		// The old readiness probe does not prove that the read fence is active.
		if len(c.Request.Header.Values("X-Fc-Plain-Probe")) != 0 {
			detail(c, http.StatusServiceUnavailable, "Legacy media probe unavailable")
			return
		}
		token, ok := capabilityInput(c, "X-Media-Capability")
		if !ok {
			detail(c, http.StatusUnauthorized, "Media capability invalid or expired")
			return
		}
		if !guard.ReadyFor(control, volume) {
			detail(c, http.StatusServiceUnavailable, "Resource access unavailable")
			return
		}
		called := false
		err := guard.WithRead(c.Request.Context(), token, c.Param("object"), func(ctx context.Context) error {
			called = true
			c.Request = c.Request.WithContext(ctx)
			serveLegacy(c)
			return nil
		})
		if err != nil && !called {
			detail(c, http.StatusServiceUnavailable, "Resource access unavailable")
		}
	}
	router.GET("/internal/v1/media/:object", serve)
	router.HEAD("/internal/v1/media/:object", serve)
	router.OPTIONS("/internal/v1/media/:object", serve)
	router.POST(node.NativePlainProbePath, func(c *gin.Context) {
		noStore(c)
		if !nodeHTTPS(c, settings, resolver) {
			return
		}
		if c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery {
			detail(c, http.StatusBadRequest, "Invalid control message")
			return
		}
		body, ok := nodeBody(c)
		if !ok || len(body) > 4096 {
			if ok {
				detail(c, http.StatusBadRequest, "Invalid control message")
			}
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
		defer cancel()
		relation, err := control.Authenticate(ctx, c.Request.Header, c.Request.Method, c.Request.URL.EscapedPath(), body, false, false)
		if err != nil {
			detail(c, http.StatusUnauthorized, "Invalid relationship authentication")
			return
		}
		var request struct {
			Challenge string `json:"challenge"`
			Token     string `json:"token"`
		}
		if controlJSON(body, &request) != nil || !node.ValidIdentifier(request.Challenge) || request.Token == "" || len(request.Token) > 4096 {
			detail(c, http.StatusBadRequest, "Invalid control message")
			return
		}
		signed, err := control.VerifyOwnedPlainProbe(ctx, relation, request.Challenge, request.Token)
		if err != nil {
			detail(c, http.StatusServiceUnavailable, "Plain reader probe unavailable")
			return
		}
		c.JSON(http.StatusOK, signed)
	})
	control.ConfigurePlainReadProbe(volume.ProbeVerifiedPlain)
}
