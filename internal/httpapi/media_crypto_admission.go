package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// This value is installed only from Master-owned state while its lease is held.
// It is separate from the authenticated peer assertion used for client identity.
type localCryptoIngressKey struct{}

const maxLocalCryptoResponse = 64 << 10

// cryptoAdmissionWriter prevents a session, cookie, or key envelope from being
// exposed until the exact lease that supplied the ingress state commits.
type cryptoAdmissionWriter struct {
	gin.ResponseWriter
	header http.Header
	body   bytes.Buffer
	status int
	size   int
	limit  int
	failed bool
}

func newCryptoAdmissionWriter(w gin.ResponseWriter) *cryptoAdmissionWriter {
	return &cryptoAdmissionWriter{ResponseWriter: w, header: w.Header().Clone(), status: http.StatusOK, size: -1, limit: maxLocalCryptoResponse}
}

func (w *cryptoAdmissionWriter) Header() http.Header { return w.header }
func (w *cryptoAdmissionWriter) Status() int         { return w.status }
func (w *cryptoAdmissionWriter) Size() int           { return w.size }
func (w *cryptoAdmissionWriter) Written() bool       { return w.size >= 0 }

func (w *cryptoAdmissionWriter) WriteHeader(code int) {
	if w.Written() {
		return
	}
	if code < 200 || code > 599 {
		w.failed = true
		return
	}
	w.status = code
}

func (w *cryptoAdmissionWriter) WriteHeaderNow() {
	if !w.Written() {
		w.size = 0
	}
}

func (w *cryptoAdmissionWriter) Write(data []byte) (int, error) {
	w.WriteHeaderNow()
	if w.failed || len(data) > w.limit-w.body.Len() {
		w.failed = true
		return 0, errors.New("crypto admission response exceeds limit")
	}
	n, err := w.body.Write(data)
	w.size += n
	return n, err
}

func (w *cryptoAdmissionWriter) WriteString(value string) (int, error) {
	return w.Write([]byte(value))
}

func (w *cryptoAdmissionWriter) Flush() { w.WriteHeaderNow() }
func (w *cryptoAdmissionWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.failed = true
	return nil, nil, errors.New("crypto admission cannot hijack connection")
}
func (w *cryptoAdmissionWriter) Pusher() http.Pusher { return nil }

func (w *cryptoAdmissionWriter) send() {
	header := w.ResponseWriter.Header()
	for name := range header {
		delete(header, name)
	}
	for name, values := range w.header {
		header[name] = append([]string(nil), values...)
	}
	w.ResponseWriter.WriteHeader(w.status)
	_, _ = w.ResponseWriter.Write(w.body.Bytes())
}

// cryptoIngressAdmission is applied only to the public session, key and revoke
// routes. A verified peer already holds the lease in publicproxy; never acquire
// it again here. Revocation is irreversible, so it commits admission first.
func (p *Public) cryptoIngressAdmission(revoke bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, proxied := network.AuthenticatedIngressFromContext(c.Request.Context()); proxied {
			// Gin's outer recovery catches panics before the verifier can see them.
			// Mark the shared admission failed before propagating the panic.
			defer func() {
				if recovered := recover(); recovered != nil {
					network.AbortPublicAdmission(c.Request.Context())
					panic(recovered)
				}
			}()
			c.Next()
			return
		}
		identity, err := p.media.IdentityState(c.Request.Context())
		if err != nil {
			internalError(c, err)
			c.Abort()
			return
		}
		if identity.Role != "Master" {
			c.Next()
			return
		}
		noStore(c)
		if p.control == nil {
			cryptoError(c, mediacrypto.ErrSession)
			c.Abort()
			return
		}
		ingress, lease, err := p.control.AcquireCurrentIngress(c.Request.Context())
		if err != nil || ingress.NodeID != identity.ID {
			if lease != nil {
				lease.Release()
			}
			cryptoError(c, mediacrypto.ErrSession)
			c.Abort()
			return
		}
		serveCryptoWithIngressLease(c, ingress, lease, revoke)
	}
}

func serveCryptoWithIngressLease(c *gin.Context, ingress store.PublicIngress, lease store.PublicIngressLease, revoke bool) {
	servePublicWithIngressLease(c, ingress, lease, revoke, maxLocalCryptoResponse)
}

func servePublicWithIngressLease(c *gin.Context, ingress store.PublicIngress, lease store.PublicIngressLease, revoke bool, limit int) {
	defer lease.Release()
	originalRequest := c.Request
	ctx := context.WithValue(c.Request.Context(), localCryptoIngressKey{}, cryptoIngress{"ingress", ingress.NodeID, ingress.Generation, ingress.PublicOrigin})
	if revoke {
		if ctx.Err() != nil || lease.Commit() != nil || ctx.Err() != nil {
			noStore(c)
			detail(c, http.StatusServiceUnavailable, "入口授权不可用")
			c.Abort()
			return
		}
		c.Request = c.Request.WithContext(ctx)
		defer func() { c.Request = originalRequest }()
		c.Next()
		return
	}
	ctx, err := store.BindIngressPrerequisite(ctx, lease)
	if err != nil {
		noStore(c)
		detail(c, http.StatusServiceUnavailable, "入口授权不可用")
		c.Abort()
		return
	}
	ctx, admission := network.WithPublicAdmission(ctx)
	defer admission.Abort()
	ctx, err = network.WithLocalPublicIngress(ctx, network.LocalPublicIngress{NodeID: ingress.NodeID, Generation: ingress.Generation, PublicOrigin: ingress.PublicOrigin})
	if err != nil {
		noStore(c)
		detail(c, http.StatusServiceUnavailable, "入口授权不可用")
		c.Abort()
		return
	}
	c.Request = c.Request.WithContext(ctx)
	originalWriter := c.Writer
	buffer := newCryptoAdmissionWriter(originalWriter)
	buffer.limit = limit
	c.Writer = buffer
	defer func() { c.Writer = originalWriter; c.Request = originalRequest }()
	c.Next()
	// The downstream handler may set a cache policy of its own. These
	// admission responses can contain session-bound resource handles.
	noStore(c)
	if buffer.status < 200 || buffer.status >= 300 {
		if admission.Abort() {
			buffer.failed = true
		}
		if !buffer.failed && ctx.Err() == nil && lease.Commit() == nil && ctx.Err() == nil {
			buffer.send()
			return
		}
		c.Writer = originalWriter
		noStore(c)
		detail(c, http.StatusServiceUnavailable, "入口授权不可用")
		c.Abort()
		return
	}
	if buffer.failed || ctx.Err() != nil || lease.Commit() != nil || ctx.Err() != nil || !admission.Commit() {
		c.Writer = originalWriter
		noStore(c)
		detail(c, http.StatusServiceUnavailable, "入口授权不可用")
		c.Abort()
		return
	}
	buffer.send()
}
