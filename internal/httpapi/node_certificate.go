package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
)

func RegisterNodeCertificate(router *gin.Engine, settings config.Config, resolver *network.Resolver, control *node.Service) {
	if settings.DeploymentMode != config.DeploymentStorage {
		return
	}
	router.POST("/internal/v1/certificate", func(c *gin.Context) {
		if c.Request.URL.RawQuery != "" {
			detail(c, 400, "Certificate control does not accept query parameters")
			return
		}
		if !nodeHTTPS(c, settings, resolver) {
			return
		}
		body, ok := nodeBody(c)
		if !ok {
			return
		}
		if len(body) > 1024 {
			detail(c, 413, "Certificate request too large")
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		r, e := control.Authenticate(ctx, c.Request.Header, c.Request.Method, c.Request.URL.EscapedPath(), body, false, false)
		if e != nil {
			detail(c, 401, "Invalid relationship authentication")
			return
		}
		var request certificate.Request
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			detail(c, 400, "Invalid certificate operation")
			return
		}
		v, e := control.ReceiveCertificate(ctx, r, request)
		if e != nil {
			detail(c, 409, "Certificate status or download unavailable; inspect automatic TLS readiness")
			return
		}
		c.Header("Cache-Control", "no-store")
		c.JSON(200, v)
	})
}
