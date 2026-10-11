package httpapi

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

func TestPublicCryptoSessionCreationLimitsCookiesAndTrustedIPWithoutAffectingAdmin(t *testing.T) {
	router, _, _, p := publicFixture(t, false)
	p.settings.TrustedProxyNetworks = nil
	now := time.Unix(1800000000, 0)
	p.cryptoSessionLimit.now = func() time.Time { return now }
	client, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"public_key": base64.StdEncoding.EncodeToString(client.PublicKey().Bytes())})
	a := &Admin{settings: p.settings, public: p}
	router.POST("/admission-admin", func(c *gin.Context) { c.Set("admin_session", admin.Session{Hash: "admission-admin"}); c.Next() }, a.cryptoSession)
	perform := func(target, peer, real string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(body))
		r.TLS = &tls.ConnectionState{}
		r.RemoteAddr = peer + ":12345"
		r.Header.Set("Content-Type", "application/json")
		if real != "" {
			r.Header.Set("X-Real-IP", real)
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	first := perform("/api/v1/media/crypto/session", "198.51.100.10", "", nil)
	if first.Code != 200 {
		t.Fatal(first.Code, first.Body.String())
	}
	var cookie *http.Cookie
	for _, candidate := range first.Result().Cookies() {
		if candidate.Name == mediaCryptoCookie {
			cookie = candidate
		}
	}
	if cookie == nil {
		t.Fatal("public handshake did not establish browser binding")
	}
	var grant mediacrypto.SessionGrant
	if err := json.Unmarshal(first.Body.Bytes(), &grant); err != nil {
		t.Fatal(err)
	}
	for range cryptoSessionCookieCreations - 1 {
		w := perform("/api/v1/media/crypto/session", "198.51.100.10", "", cookie)
		if w.Code != 200 {
			t.Fatal("reasonable multi-tab handshake denied", w.Code, w.Body.String())
		}
	}
	w := perform("/api/v1/media/crypto/session", "198.51.100.11", "", cookie)
	if w.Code != 429 || w.Header().Get("Retry-After") != "60" {
		t.Fatal("cookie limit evaded by IP change", w.Code, w.Header())
	}
	// A rejected creation neither revokes nor renews the first live grant.
	metadata, _ := mediacrypto.NewMetadata(20)
	for range 3 {
		envelope, err := p.crypto.Wrap("browser:"+cookie.Value, grant.SessionID, metadata)
		if err != nil || envelope.ExpiresAt != grant.ExpiresAt {
			t.Fatal("creation limit changed existing authorization", err)
		}
	}
	if w := perform("/admission-admin", "198.51.100.10", "", nil); w.Code != 200 {
		t.Fatal("public limiter affected Admin", w.Code, w.Body.String())
	}
	// Rotating browser cookies and forged proxy headers must share the real peer
	// budget. Each binding remains below its own window and active-session caps.
	for i := cryptoSessionCookieCreations; i < cryptoSessionIPCreations; i++ {
		c := &http.Cookie{Name: mediaCryptoCookie, Value: fmt.Sprintf("%064x", i+1)}
		w := perform("/api/v1/media/crypto/session", "198.51.100.10", fmt.Sprintf("203.0.113.%d", i+1), c)
		if w.Code != 200 {
			t.Fatal("IP window charged rejected attempts or Admin", i, w.Code, w.Body.String())
		}
	}
	w = perform("/api/v1/media/crypto/session", "198.51.100.10", "203.0.113.250", &http.Cookie{Name: mediaCryptoCookie, Value: strings.Repeat("f", 64)})
	if w.Code != 429 {
		t.Fatal("rotating cookies or untrusted header evaded IP limit", w.Code)
	}
	if w := perform("/api/v1/media/crypto/session", "198.51.100.12", "", nil); w.Code != 200 {
		t.Fatal("one IP locked out another", w.Code)
	}
	now = now.Add(cryptoSessionCreationWindow)
	if w := perform("/api/v1/media/crypto/session", "198.51.100.10", "", cookie); w.Code != 200 {
		t.Fatal("expired creation window retained", w.Code, w.Body.String())
	}
}

func TestCryptoSessionAdmissionCacheBoundAndExpiredReclamation(t *testing.T) {
	now := time.Unix(1800000000, 0)
	a := cryptoSessionAdmission{now: func() time.Time { return now }, windows: make(map[string]cryptoCreationWindow)}
	for i := range cryptoSessionAdmissionEntries {
		a.windows[fmt.Sprint(i)] = cryptoCreationWindow{1, now.Add(cryptoSessionCreationWindow)}
	}
	if a.allow("198.51.100.1", "browser:first") || len(a.windows) != cryptoSessionAdmissionEntries {
		t.Fatal("full cache admitted extra entries")
	}
	now = now.Add(cryptoSessionCreationWindow)
	if !a.allow("198.51.100.1", "browser:first") || len(a.windows) != 2 {
		t.Fatal("expired cache did not reclaim capacity", len(a.windows))
	}
}

func TestPublicCryptoSessionAdmissionUsesConfiguredTrustedProxy(t *testing.T) {
	_, _, _, p := publicFixture(t, false)
	p.settings.TrustedProxyNetworks = []string{"10.0.0.0/8"}
	count := 0
	check := func(real string) bool {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/session", nil)
		c.Request.RemoteAddr = "10.1.2.3:12345"
		c.Request.Header.Set("X-Real-IP", real)
		count++
		return p.allowPublicCryptoSession(c, fmt.Sprintf("browser:%064x", count))
	}
	for range cryptoSessionIPCreations {
		if !check("198.51.100.20") {
			t.Fatal("trusted client denied before limit")
		}
	}
	if check("198.51.100.20") {
		t.Fatal("trusted client evaded IP creation limit")
	}
	if !check("198.51.100.21") {
		t.Fatal("different trusted client denied")
	}
}
