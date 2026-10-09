package httpapi

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
)

const restrictiveCSP = "default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
const nonceMarker = "{{FRONTIERCLOUD_CSP_NONCE}}"

// Keep the direct Go surface (including storage) protected without Nginx.
func browserSecurity(resolver *network.Resolver) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Security-Policy", restrictiveCSP)
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "same-origin")
		permissions := "camera=(), microphone=(), geolocation=()"
		if c.Request.URL.Path == "/karaoke/" {
			permissions = "camera=(), microphone=(self), geolocation=()"
		}
		c.Header("Permissions-Policy", permissions)
		if resolver.SecureAdmin(c.Request) {
			c.Header("Strict-Transport-Security", "max-age=31536000")
		}
		c.Next()
	}
}

// Only trusted template source is marked, BEFORE inserting escaped user data.
// Never automatically bless script tags in the final rendered response.
func nonceTemplate(content string) string {
	return strings.NewReplacer("<script>", `<script nonce="`+nonceMarker+`">`, "<script ", `<script nonce="`+nonceMarker+`" `).Replace(content)
}

func serveHTML(c *gin.Context, content string, documentation bool) {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		internalError(c, err)
		return
	}
	nonce := base64.RawStdEncoding.EncodeToString(random[:])
	// CSS attributes and JS-driven sizing are required by the player. Do not
	// extend this compatibility exception to scripts, event handlers or eval.
	styles := "style-src 'self' 'unsafe-inline'"
	if documentation {
		styles += " https://cdn.jsdelivr.net"
	}
	policy := "default-src 'self'; script-src 'self' 'nonce-" + nonce + "'; script-src-attr 'none'; " + styles +
		"; connect-src 'self' https:; media-src 'self' blob: https:; img-src 'self' data: blob: https:; font-src 'self' data:; worker-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-src 'none'; frame-ancestors 'none'; form-action 'self'"
	c.Header("Content-Security-Policy", policy)
	noStore(c)
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(strings.ReplaceAll(content, nonceMarker, nonce)))
}
