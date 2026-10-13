package httpapi

import (
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/businesstraffic"
)

type businessBody struct {
	io.ReadCloser
	monitor *businesstraffic.Monitor
}

func (b *businessBody) Read(p []byte) (int, error) {
	n, e := b.ReadCloser.Read(p)
	b.monitor.Ingress(n)
	return n, e
}

type businessWriter struct {
	gin.ResponseWriter
	monitor *businesstraffic.Monitor
}

func (w *businessWriter) Write(p []byte) (int, error) {
	n, e := w.ResponseWriter.Write(p)
	w.monitor.Egress(n)
	return n, e
}
func (w *businessWriter) WriteString(p string) (int, error) {
	n, e := w.ResponseWriter.WriteString(p)
	w.monitor.Egress(n)
	return n, e
}

func businessDataRequest(r *http.Request) bool {
	p := r.URL.Path
	if r.Method == "GET" && (p == "/api/v1/media/admin/nodes" || strings.HasPrefix(p, "/api/v1/media/admin/nodes/migrations") || strings.HasPrefix(p, "/api/v1/media/admin/nodes/migration-plans")) {
		return false
	}
	if !strings.HasPrefix(p, "/internal/v1/") {
		return !strings.HasPrefix(p, "/health/") && p != "/health" && p != "/healthz" && p != "/readyz"
	}
	// Relay business reads/uploads reach Storage through internal data routes.
	// Count those bytes too; migration, heartbeat, scans and JSON stat calls are
	// excluded so background transfer cannot hold its own low-traffic gate shut.
	if strings.HasPrefix(p, "/internal/v1/media/") {
		return r.Method == "GET" || r.Method == "HEAD"
	}
	if strings.HasPrefix(p, "/internal/v1/storage/") {
		return r.Method == "PUT"
	}
	return strings.HasPrefix(p, "/internal/v1/recordings/") && (r.Method == "GET" || r.Method == "PUT") && !strings.HasSuffix(p, "/stat")
}

// Counts actual payload bytes incrementally, never declared Content-Length or
// completed-request totals. Streaming playback therefore changes load promptly.
func BusinessTrafficMiddleware(m *businesstraffic.Monitor) gin.HandlerFunc {
	return func(c *gin.Context) {
		if m == nil || !businessDataRequest(c.Request) {
			c.Next()
			return
		}
		if c.Request.Body != nil {
			c.Request.Body = &businessBody{c.Request.Body, m}
		}
		c.Writer = &businessWriter{c.Writer, m}
		c.Next()
	}
}
