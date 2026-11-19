//go:build linux

package httpapi

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/selectedupload"
)

// registerSelectedOwnerHTTP remains an explicitly installed runtime capability.
// Its caller must already prove encrypted tree/recovery readiness and drain all
// legacy Owner writers. Merely constructing a receiver does not register it.
func registerSelectedOwnerHTTP(router *gin.Engine, settings config.Config, resolver *network.Resolver, service *node.Service, volume any, receiver *node.SelectedDirectReceiver) bool {
	if router == nil || resolver == nil || service == nil || receiver == nil || !receiver.ReadyFor(service, volume) || !settings.TLSEnabled {
		return false
	}
	registerSelectedOwnerRoutes(router, settings, resolver, "/api/v1/node/selected-upload", receiver.AllowsBrowserOrigin, receiver.Receive, receiver.Recover, receiver.Cleanup)
	return true
}

// RegisterRecordingOwnerHTTP installs a separate capability domain for private recording uploads.
func RegisterRecordingOwnerHTTP(router *gin.Engine, settings config.Config, resolver *network.Resolver, service *node.Service, volume any, receiver *node.SelectedDirectReceiver) bool {
	if router == nil || resolver == nil || service == nil || receiver == nil || !receiver.ReadyFor(service, volume) || !settings.TLSEnabled {
		return false
	}
	registerSelectedOwnerRoutes(router, settings, resolver, "/api/v1/node/recording-selected-upload", receiver.AllowsRecordingOrigin, receiver.ReceiveRecording, receiver.RecoverRecording, receiver.CleanupRecording)
	return true
}

type selectedOwnerOperation func(context.Context, string, string, selectedupload.ReadDeadline, io.ReadCloser, time.Duration) (protocol.OpaqueCapacityReceipt, string, error)

func registerSelectedOwnerRoutes(router *gin.Engine, settings config.Config, resolver *network.Resolver, base string, allowsOrigin func(context.Context, string) bool, receive, recover, cleanup selectedOwnerOperation) {
	gate := newSelectedOriginGate(4, 4, 2)
	for _, route := range []struct {
		suffix, method string
		operate        selectedOwnerOperation
	}{
		{"", http.MethodPut, receive},
		{"/recover", http.MethodPost, recover},
		{"/cleanup", http.MethodPost, cleanup},
	} {
		path := base + route.suffix
		method := route.method
		router.OPTIONS(path, func(c *gin.Context) {
			if !nodeHTTPS(c, settings, resolver) {
				return
			}
			if c.Request.URL.RawQuery != "" || len(c.Request.Header.Values("Origin")) != 1 || len(c.Request.Header.Values("Access-Control-Request-Method")) != 1 || c.GetHeader("Access-Control-Request-Method") != method {
				detail(c, 403, "Upload preflight rejected")
				return
			}
			for _, line := range c.Request.Header.Values("Access-Control-Request-Headers") {
				for _, header := range strings.Split(line, ",") {
					h := strings.ToLower(strings.TrimSpace(header))
					if h != "content-type" && h != "x-fc-selected-upload" {
						detail(c, 403, "Upload preflight rejected")
						return
					}
				}
			}
			if !gate.acquire() {
				detail(c, 429, "Upload control busy")
				return
			}
			defer gate.release()
			if !allowsOrigin(c.Request.Context(), c.GetHeader("Origin")) {
				detail(c, 403, "Upload preflight rejected")
				return
			}
			c.Header("Access-Control-Allow-Origin", c.GetHeader("Origin"))
			c.Header("Access-Control-Allow-Methods", method)
			c.Header("Access-Control-Allow-Headers", "Content-Type, X-Fc-Selected-Upload")
			c.Header("Access-Control-Max-Age", "0")
			c.Header("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
			c.Status(http.StatusNoContent)
		})
		router.Handle(method, path, func(c *gin.Context) {
			if !nodeHTTPS(c, settings, resolver) {
				return
			}
			tokens := c.Request.Header.Values("X-Fc-Selected-Upload")
			origins := c.Request.Header.Values("Origin")
			if c.Request.URL.RawQuery != "" || len(tokens) != 1 || len(tokens[0]) == 0 || len(tokens[0]) > 4096 || len(origins) != 1 || origins[0] == "" {
				detail(c, 403, "Upload rejected")
				return
			}
			ctx, cancel := context.WithTimeout(c.Request.Context(), 24*time.Hour)
			defer cancel()
			deadline := http.NewResponseController(c.Writer)
			receipt, signature, err := route.operate(ctx, tokens[0], origins[0], deadline, c.Request.Body, 24*time.Hour)
			if err != nil {
				detail(c, 503, "Upload unavailable")
				return
			}
			c.Header("Access-Control-Allow-Origin", origins[0])
			c.Header("Vary", "Origin")
			c.JSON(200, gin.H{"receipt": receipt, "signature": signature})
		})
	}
}

// RegisterSelectedOwnerHTTP installs the encrypted Direct Owner endpoints
// only for a receiver bound to the exact started service and volume.
func RegisterSelectedOwnerHTTP(router *gin.Engine, settings config.Config, resolver *network.Resolver, service *node.Service, volume any, receiver *node.SelectedDirectReceiver) bool {
	return registerSelectedOwnerHTTP(router, settings, resolver, service, volume, receiver)
}
