//go:build linux

package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
)

// RegisterSelectedRelayOwnerHTTP installs the paired Master-only stream route.
// Node authentication covers the small capability, whose signed size and
// digest cover the stream; no request body is buffered for authentication.
func RegisterSelectedRelayOwnerHTTP(router *gin.Engine, settings config.Config, resolver *network.Resolver, service *node.Service, volume any, receiver *node.SelectedDirectReceiver) bool {
	if router == nil || resolver == nil || service == nil || receiver == nil || !receiver.ReadyFor(service, volume) || !settings.TLSEnabled {
		return false
	}
	base := "/internal/v1/selected-upload/relay"
	for _, suffix := range []string{"", "/recover", "/cleanup"} {
		path := base + suffix
		method := http.MethodPost
		if suffix == "" {
			method = http.MethodPut
		}
		router.Handle(method, path, func(c *gin.Context) {
			if !nodeHTTPS(c, settings, resolver) {
				return
			}
			tokens := c.Request.Header.Values("X-Fc-Selected-Upload")
			if c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery || len(c.Request.Header.Values("Origin")) != 0 || len(tokens) != 1 || len(tokens[0]) == 0 || len(tokens[0]) > 4096 {
				detail(c, http.StatusForbidden, "Upload rejected")
				return
			}
			ctx, cancel := context.WithTimeout(c.Request.Context(), 24*time.Hour)
			defer cancel()
			receipt, signature, err := receiver.Relay(ctx, c.Request.Header, c.Request.Method, c.Request.URL.EscapedPath(), tokens[0], http.NewResponseController(c.Writer), c.Request.Body, 24*time.Hour)
			if err != nil {
				detail(c, http.StatusServiceUnavailable, "Upload unavailable")
				return
			}
			c.JSON(http.StatusOK, gin.H{"receipt": receipt, "signature": signature})
		})
	}
	return true
}
