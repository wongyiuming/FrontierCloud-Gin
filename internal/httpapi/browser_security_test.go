package httpapi

import (
	"encoding/base64"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func assertNoncePolicy(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	policy := w.Header().Get("Content-Security-Policy")
	match := regexp.MustCompile(`script-src 'self' 'nonce-([^']+)'`).FindStringSubmatch(policy)
	if len(match) != 2 {
		t.Fatalf("missing nonce policy: %s", policy)
	}
	raw, err := base64.RawStdEncoding.DecodeString(match[1])
	if err != nil || len(raw) != 32 {
		t.Fatal("nonce must have 256 bits of random entropy")
	}
	for _, directive := range []string{"script-src-attr 'none'", "object-src 'none'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'", "media-src 'self' blob: https:", "connect-src 'self' https:"} {
		if !strings.Contains(policy, directive) {
			t.Fatal("missing directive", directive)
		}
	}
	if strings.Contains(match[0], "unsafe-inline") || strings.Contains(policy, "unsafe-eval") {
		t.Fatal("script execution relaxed")
	}
	for _, tag := range regexp.MustCompile(`<script\b[^>]*>`).FindAllString(w.Body.String(), -1) {
		if !strings.Contains(tag, `nonce="`+match[1]+`"`) {
			t.Fatal("trusted script is not nonced", tag)
		}
	}
	if !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("cacheable nonce HTML")
	}
	return match[1]
}

func TestHTMLNoncePoliciesAreFreshAndPreservePlayer(t *testing.T) {
	router, _, _, _ := publicFixture(t, false)
	seen := map[string]bool{}
	for _, target := range []string{"/api/v1/media", "/api/v1/media", "/api/v1/media/music", "/api/v1/media/music/category?path=music/artist", "/api/v1/media/video/category?path=vido/director", "/api/v1/media/lyrics?track=music/artist/song.mp3", "/karaoke/"} {
		w := request(router, "GET", target, "")
		if w.Code != 200 {
			t.Fatal(target, w.Code, w.Body.String())
		}
		nonce := assertNoncePolicy(t, w)
		if seen[nonce] {
			t.Fatal("nonce reused across responses")
		}
		seen[nonce] = true
		permission := w.Header().Get("Permissions-Policy")
		if strings.Contains(target, "karaoke") != strings.Contains(permission, "microphone=(self)") {
			t.Fatal("incorrect microphone scope", target, permission)
		}
	}
}

func TestNonceAuthorizationIsAddedBeforeUntrustedSubstitution(t *testing.T) {
	// Deliberately unescaped: the helper must not traverse a final response
	// or replace known placeholders and authorize attacker-added tags.
	// Renderers must still escape each context.
	attack := `"</script><script>window.attacker=1</script><script nonce="{{FRONTIERCLOUD_CSP_NONCE}}">window.attacker=2</script>"`
	router := New(pass, pass)
	router.GET("/fixture", func(c *gin.Context) {
		nonce, err := htmlNonce(c)
		if err != nil {
			t.Fatal(err)
		}
		template := nonceTemplate(`<script>const value = {{VALUE}};</script><script src="/static/trusted.js"></script>`, nonce)
		serveHTML(c, strings.ReplaceAll(template, "{{VALUE}}", attack), false)
	})
	w := request(router, "GET", "/fixture", "")
	if !strings.Contains(w.Body.String(), `<script>window.attacker=1</script>`) || !strings.Contains(w.Body.String(), `<script nonce="{{FRONTIERCLOUD_CSP_NONCE}}">window.attacker=2</script>`) {
		t.Fatal("attacker script was authorized")
	}
}

func TestSecurityHeadersCoverErrorsMethodsAndTransport(t *testing.T) {
	router := New(pass, pass)
	for _, test := range []struct {
		method, target string
		status         int
	}{{"GET", "/health", 200}, {"GET", "/missing", 404}, {"TRACE", "/health", 405}, {"OPTIONS", "/health", 405}} {
		w := request(router, test.method, test.target, "")
		if w.Code != test.status || w.Header().Get("Content-Security-Policy") != restrictiveCSP || w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("X-Frame-Options") != "DENY" {
			t.Fatal(test, w.Code, w.Header())
		}
		if w.Header().Get("Strict-Transport-Security") != "" {
			t.Fatal("HSTS sent on plaintext HTTP")
		}
	}
	w := request(router, "GET", "https://secure.test/health", "")
	if w.Header().Get("Strict-Transport-Security") != "max-age=31536000" {
		t.Fatal("direct TLS has no HSTS")
	}
}
