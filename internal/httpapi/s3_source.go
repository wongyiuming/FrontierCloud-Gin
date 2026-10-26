package httpapi

import (
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type s3SourceBody struct {
	FilePath string `json:"file_path"`
	ObjectID string `json:"object_id"`
}

const s3SourceGrantWindow = time.Minute
const s3SourceCookieGrants = 256
const s3SourceIPGrants = 1024
const s3SourceGlobalGrants = 4096
const s3SourceAdmissionEntries = 8192

type s3SourceWindow struct {
	count int
	until time.Time
}

// Source grants cover album metadata probes, playback and grant renewal. They
// have their own browser, real-client IP and process budgets; none consumes the
// much smaller ECDH creation allowance. Every counter and its expiry is bounded.
type s3SourceAdmission struct {
	mu      sync.Mutex
	windows map[string]s3SourceWindow
	now     func() time.Time
}

func (a *s3SourceAdmission) allow(ip, binding string) bool {
	if ip == "" || binding == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if a.now != nil {
		now = a.now()
	}
	if a.windows == nil {
		a.windows = make(map[string]s3SourceWindow)
	}
	for key, window := range a.windows {
		if !window.until.After(now) {
			delete(a.windows, key)
		}
	}
	keys := [3]string{"global", "ip:" + ip, "cookie:" + binding}
	limits := [3]int{s3SourceGlobalGrants, s3SourceIPGrants, s3SourceCookieGrants}
	needed := 0
	for i, key := range keys {
		window, exists := a.windows[key]
		if exists && window.count >= limits[i] {
			return false
		}
		if !exists {
			needed++
		}
	}
	if len(a.windows)+needed > s3SourceAdmissionEntries {
		return false
	}
	for _, key := range keys {
		window, exists := a.windows[key]
		if !exists {
			window.until = now.Add(s3SourceGrantWindow)
		}
		window.count++
		a.windows[key] = window
	}
	return true
}

func decodeS3Source(c *gin.Context, body *s3SourceBody) bool {
	noStore(c)
	if c.Request.URL.RawQuery != "" {
		invalid(c, "query", "payload")
		return false
	}
	if !cryptoSameOrigin(c) || !decodeS3(c, body) {
		return false
	}
	if body.FilePath == "" || len(body.FilePath) > 4096 || !utf8.ValidString(body.FilePath) || body.ObjectID == "" || len(body.ObjectID) > 128 || !utf8.ValidString(body.ObjectID) {
		invalid(c, "body", "identity")
		return false
	}
	return true
}

func (p *Public) allowPublicS3Source(c *gin.Context, binding string) bool {
	resolver, err := network.New(p.settings.TrustedProxyNetworks)
	if err != nil {
		s3HTTPError(c, s3media.ErrUnavailable)
		return false
	}
	// Independent from ECDH admission: a plain read never creates a key session.
	// The bounded real-peer window also prevents rotating arbitrary cookie values
	// from turning this public signing endpoint into unbounded control traffic.
	ip := resolver.Resolve(c.Request).IP
	if ip == "" || binding == "" || !p.cryptoSourceLimit.allow(ip, binding) {
		c.Header("Retry-After", "60")
		detail(c, http.StatusTooManyRequests, "媒体读取授权过于频繁，请稍后重试")
		return false
	}
	return true
}

func (p *Public) s3Source(c *gin.Context) {
	if !p.cryptoTransport(c) {
		return
	}
	if !p.s3SourceRole(c) {
		return
	}
	var body s3SourceBody
	if !decodeS3Source(c, &body) {
		return
	}
	binding, err := p.browserBinding(c, true)
	if err != nil {
		s3HTTPError(c, s3media.ErrUnavailable)
		return
	}
	if !p.allowPublicS3Source(c, binding) {
		return
	}
	value, err := p.media.PlaintextSource(c.Request.Context(), body.FilePath, body.ObjectID, false)
	if err != nil {
		s3HTTPError(c, err)
		return
	}
	response, ok := s3SourceJSON(c, body.FilePath, value)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, response)
}

func (a *Admin) s3Source(c *gin.Context) {
	if !a.public.cryptoAvailable(c) {
		return
	}
	if !a.public.s3SourceRole(c) {
		return
	}
	var body s3SourceBody
	if !decodeS3Source(c, &body) {
		return
	}
	if !nodeHTTPS(c, a.settings, a.network) {
		return
	}
	value, err := a.public.media.PlaintextSource(c.Request.Context(), body.FilePath, body.ObjectID, true)
	if err != nil {
		s3HTTPError(c, err)
		return
	}
	response, ok := s3SourceJSON(c, body.FilePath, value)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, response)
}

func (p *Public) s3SourceRole(c *gin.Context) bool {
	role, err := p.media.BusinessRole(c.Request.Context())
	if err != nil || role != "Master" {
		s3HTTPError(c, store.ErrNodeState)
		return false
	}
	return true
}

func browserSourceRequired(c *gin.Context) {
	noStore(c)
	c.JSON(http.StatusConflict, gin.H{"detail": "此媒体需要浏览器读取授权，请从播放器或下载计划打开", "code": "MEDIA_BROWSER_SOURCE_REQUIRED"})
}

func validS3SourceGrant(grant s3store.Grant, head bool) bool {
	u, err := url.Parse(grant.URL)
	if err != nil || len(grant.URL) > 16384 || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	for name, value := range grant.Headers {
		if name != "If-Match" && !(head && name == "X-Amz-Checksum-Mode" && value == "ENABLED") {
			return false
		}
	}
	etag, ok := grant.Headers["If-Match"]
	return ok && len(etag) >= 3 && len(etag) <= 1026 && etag[0] == '"' && etag[len(etag)-1] == '"' && !strings.ContainsAny(etag[1:len(etag)-1], "\"\r\n\x00")
}

func s3SourceJSON(c *gin.Context, name string, value s3media.SourceGrant) (gin.H, bool) {
	noStore(c)
	expires := min(value.GET.ExpiresAt, value.HEAD.ExpiresAt)
	ttl := int64(time.Until(time.Unix(expires, 0)) / time.Second)
	if value.ObjectID == "" || len(value.ObjectID) > 128 || value.SizeBytes < 1 || value.SizeBytes > 10*1024*1024*1024 || ttl < 1 || ttl > 300 || !validS3SourceGrant(value.GET, false) || !validS3SourceGrant(value.HEAD, true) || value.GET.Headers["If-Match"] != value.HEAD.Headers["If-Match"] {
		s3HTTPError(c, s3media.ErrProof)
		return nil, false
	}
	contentType := mime.TypeByExtension(path.Ext(name))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	return gin.H{"transport": "S3", "object_id": value.ObjectID, "size_bytes": value.SizeBytes,
		"source_url": value.GET.URL, "source_headers": value.GET.Headers,
		"source_head_url": value.HEAD.URL, "source_head_headers": value.HEAD.Headers,
		"expires_in": ttl, "expires_at": expires, "content_type": contentType, "filename": path.Base(name)}, true
}
