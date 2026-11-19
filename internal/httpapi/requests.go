package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
)

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
var tracePattern = regexp.MustCompile(`^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$`)

func smallStrictJSON(c *gin.Context, dst any) bool {
	return strictJSON(c, dst, 8192)
}

func strictJSON(c *gin.Context, dst any, maxBytes int64) bool {
	mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return false
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(dst) != nil {
		return false
	}
	var tail any
	return decoder.Decode(&tail) == io.EOF
}

// loggedRoute never persists a client-supplied path or wildcard value. Gin's
// matched route is registration-time text; unmatched paths have one label.
func loggedRoute(c *gin.Context) string {
	if route := c.FullPath(); route != "" {
		return route
	}
	return "/unmatched"
}

func requests(resolver *network.Resolver) gin.HandlerFunc {
	return func(c *gin.Context) {
		started := time.Now()
		identity := resolver.Resolve(c.Request)
		id, err := randomUUID()
		if err != nil {
			detail(c, 500, "Internal server error")
			c.Abort()
			return
		}
		id = strings.ReplaceAll(id, "-", "")
		trace := id
		if supplied := c.GetHeader("X-Request-ID"); identity.FromTrustedProxy && requestIDPattern.MatchString(supplied) {
			id = supplied
		}
		if match := tracePattern.FindStringSubmatch(c.GetHeader("Traceparent")); identity.FromTrustedProxy && match != nil && match[1] != strings.Repeat("0", 32) && match[2] != strings.Repeat("0", 16) {
			trace = match[1]
		}
		c.Set("request_id", id)
		c.Set("trace_id", trace)
		c.Header("X-Request-ID", id)
		c.Header("X-Audit-Trace-ID", trace)
		c.Next()
		if c.Writer.Status() >= 400 || (c.Request.URL.Path != "/health" && c.Request.URL.Path != "/health/live" && c.Request.URL.Path != "/health/ready" && c.Request.URL.Path != "/api/v1/health" && c.Request.URL.Path != "/metrics") {
			slog.Info("request_completed", "method", c.Request.Method, "path", loggedRoute(c), "status", c.Writer.Status(), "duration_ms", float64(time.Since(started).Microseconds())/1000, "client_ip", identity.IP, "request_id", id, "trace_id", trace)
		}
	}
}
