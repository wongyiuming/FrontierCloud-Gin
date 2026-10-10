package httpapi

import (
	"errors"
	"mime"
	"net/http"
	"os"
	"path"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
)

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

func RegisterNodeMedia(router *gin.Engine, settings config.Config, resolver *network.Resolver, control *node.Service, volume *media.Service) {
	serve := func(c *gin.Context) {
		if !nodeHTTPS(c, settings, resolver) {
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
		c.Header("Vary", "Origin")
		origins := c.Request.Header.Values("Origin")
		if len(origins) > 1 || len(origins) == 1 && origins[0] != relation.Endpoint {
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
		stream, err := volume.OwnedStream(c.Request.Context(), c.Param("object"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, media.ErrPath) {
				detail(c, 404, "Resource not found")
			} else {
				internalError(c, err)
			}
			return
		}
		defer stream.File.Close()
		// The standalone HTTPS listener is also the public edge. Browser query
		// capabilities must not expose the metadata formerly hidden by Nginx.
		// Header-based server downloads retain placement proof for MediaRead.
		if settings.DeploymentMode != config.DeploymentStorage || c.GetHeader("X-Media-Capability") != "" {
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
		meta, err := volume.Encryption(c.Request.Context(), stream.ObjectID)
		if err != nil {
			internalError(c, err)
			return
		}
		if meta != nil {
			contentType = "application/octet-stream"
			noStore(c)
		}
		c.Header("Content-Type", contentType)
		if settings.NginxMedia {
			prefix := "/_protected_media/"
			if meta != nil {
				prefix = "/_protected_cipher/"
			}
			c.Header("X-Accel-Redirect", prefix+media.QuotePath(stream.Path))
			c.Status(200)
			return
		}
		http.ServeContent(c.Writer, c.Request, path.Base(stream.Path), stream.Info.ModTime(), stream.File)
	}
	router.GET("/internal/v1/media/:object", serve)
	router.HEAD("/internal/v1/media/:object", serve)
	router.OPTIONS("/internal/v1/media/:object", serve)
}
