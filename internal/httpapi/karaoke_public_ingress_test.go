package httpapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/karaoke"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/publicproxy"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recording"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type karaokeIngressRecorder struct{ *httptest.ResponseRecorder }

func (karaokeIngressRecorder) SetReadDeadline(time.Time) error  { return nil }
func (karaokeIngressRecorder) SetWriteDeadline(time.Time) error { return nil }

func karaokeIngressRoutes(t *testing.T, cache karaoke.Cache) *gin.Engine {
	t.Helper()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	router, db, dir, public, master := clusterFixture(t, "https://master.test", transport, false)
	if _, err := master.Promote(context.Background(), "Master", "https://master.test", 10*store.GiB, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	resolver, err := network.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	accounts := RegisterKaraokeAccounts(router, karaoke.New(db.Karaoke(), db.Nodes(), cache), public, nil, resolver)
	recordingRoot, err := os.OpenRoot(filepath.Join(dir, "recordings"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { recordingRoot.Close() })
	volume, err := recording.New(recordingRoot, db.Recordings(), db.Nodes())
	if err != nil {
		t.Fatal(err)
	}
	manager := recording.NewManager(db.Recordings(), db.Karaoke(), db.Nodes(), db.Pool(), master, volume)
	RegisterKaraokeRecordings(router, accounts, manager, volume)
	return router
}

func karaokeIngressProxy(t *testing.T, router http.Handler, current *relayFixtureCurrent, ingress store.PublicIngress) http.Handler {
	t.Helper()
	edge, err := network.New([]string{"10.23.45.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	var wrapped atomic.Value
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The edge sees HTTPS, but the Master's verifier and Gin see a
		// plaintext hop from the configured proxy network.
		forwarded := r.Clone(r.Context())
		forwarded.TLS = nil
		forwarded.RemoteAddr = "10.23.45.6:1234"
		forwarded.Header.Set("X-Real-IP", "192.0.2.33")
		forwarded.Header.Set("X-Forwarded-Proto", "https")
		wrapped.Load().(http.Handler).ServeHTTP(w, forwarded)
	}))
	t.Cleanup(upstream.Close)
	verifier, err := publicproxy.NewVerifier(publicproxy.VerifierConfig{MasterOrigin: upstream.URL, Authenticator: &relayFixtureAuth{peer: ingress.NodeID, nonces: map[string]bool{}}, Current: current, EdgeResolver: edge})
	if err != nil {
		t.Fatal(err)
	}
	wrapped.Store(verifier.Wrap(router))
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	proxy, err := publicproxy.New(publicproxy.Config{MasterOrigin: upstream.URL, PublicOrigin: ingress.PublicOrigin, RootCAs: roots, Peer: &publicproxy.PeerConfig{NodeID: ingress.NodeID, Generation: ingress.Generation, Signer: relayFixtureSigner{}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proxy.CloseIdleConnections)
	return proxy
}

func TestKaraokeAccountAndRecordingTransportThroughTerminatedIngress(t *testing.T) {
	router := karaokeIngressRoutes(t, nil)
	ingress := store.PublicIngress{NodeID: strings.Repeat("a", 32), PublicOrigin: "https://entry.test", Generation: 9}
	current := &relayFixtureCurrent{value: ingress}
	proxy := karaokeIngressProxy(t, router, current, ingress)
	for _, route := range []struct {
		path string
		want int
	}{
		{"/api/v1/karaoke/account/status", http.StatusOK},
		{"/api/v1/karaoke/account/recordings", http.StatusUnauthorized},
	} {
		r := httptest.NewRequest(http.MethodGet, route.path, nil)
		r.Host, r.TLS = "entry.test", &tls.ConnectionState{}
		w := httptest.NewRecorder()
		proxy.ServeHTTP(karaokeIngressRecorder{w}, r)
		if w.Code != route.want {
			t.Fatalf("authenticated ingress %s: got %d, want %d: %s", route.path, w.Code, route.want, w.Body.String())
		}
		r = httptest.NewRequest(http.MethodGet, "http://master.test"+route.path, nil)
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Real-IP", "192.0.2.33")
		r.Header.Set("X-Fc-Public-Hop", "1")
		w = httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != http.StatusUpgradeRequired {
			t.Fatalf("unverified plaintext %s: got %d", route.path, w.Code)
		}
	}
}

func TestKaraokeAccountThroughAuthenticatedPublicIngress(t *testing.T) {
	raw := os.Getenv("FRONTIERCLOUD_TEST_REDIS_URL")
	if raw == "" {
		t.Skip("disposable Redis not configured")
	}
	opts, err := redis.ParseURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	cache := redis.NewClient(opts)
	defer cache.Close()
	ctx := context.Background()
	router := karaokeIngressRoutes(t, karaoke.NewRedisCache(cache))
	ingress := store.PublicIngress{NodeID: strings.Repeat("a", 32), PublicOrigin: "https://entry.test", Generation: 9}
	current := &relayFixtureCurrent{value: ingress}
	proxy := karaokeIngressProxy(t, router, current, ingress)
	cookies := map[string]*http.Cookie{}
	call := func(method, path, body string, csrf bool) *httptest.ResponseRecorder {
		var reader *strings.Reader
		if body != "" {
			reader = strings.NewReader(body)
		} else {
			reader = strings.NewReader("")
		}
		r := httptest.NewRequest(method, path, reader)
		r.Host, r.RemoteAddr, r.TLS = "entry.test", "192.0.2.178:9876", &tls.ConnectionState{}
		r.Header.Set("Origin", ingress.PublicOrigin)
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		if csrf && cookies["__Host-karaoke_csrf"] != nil {
			r.Header.Set("X-Karaoke-CSRF", cookies["__Host-karaoke_csrf"].Value)
		}
		w := httptest.NewRecorder()
		proxy.ServeHTTP(karaokeIngressRecorder{w}, r)
		for _, cookie := range w.Result().Cookies() {
			if cookie.MaxAge < 0 {
				delete(cookies, cookie.Name)
			} else {
				cookies[cookie.Name] = cookie
			}
		}
		return w
	}
	w := call(http.MethodGet, "/api/v1/karaoke/account/captcha", "", false)
	if anonymous := call(http.MethodGet, "/api/v1/karaoke/account/recordings", "", false); anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous recordings: %d", anonymous.Code)
	}
	var challenge struct{ Challenge, URL string }
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &challenge) != nil || challenge.Challenge == "" {
		t.Fatalf("captcha: %d %s", w.Code, w.Body.String())
	}
	w = call(http.MethodGet, "/api/v1/karaoke/account/captcha/"+challenge.Challenge, "", false)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<svg") {
		t.Fatalf("captcha image: %d", w.Code)
	}
	answer, err := cache.Get(ctx, "karaoke:captcha:"+challenge.Challenge+":image").Result()
	if err != nil {
		t.Fatal(err)
	}
	const fixtureName, fixturePassword = "ingress_fixture", "Fixture@123"
	if _, _, err := karaoke.NormalizeUsername(fixtureName); err != nil {
		t.Fatal("invalid fixture username", err)
	}
	if err := karaoke.ValidatePassword(fixturePassword); err != nil {
		t.Fatal("invalid fixture password", err)
	}
	body, _ := json.Marshal(gin.H{"username": fixtureName, "password": fixturePassword, "challenge": challenge.Challenge, "captcha": answer})
	w = call(http.MethodPost, "/api/v1/karaoke/account/register", string(body), false)
	if w.Code != http.StatusOK || cookies["__Host-karaoke_session"] == nil || cookies["__Host-karaoke_csrf"] == nil {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	w = call(http.MethodGet, "/api/v1/karaoke/account/status", "", false)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"authenticated":true`) {
		t.Fatalf("status: %d %s", w.Code, w.Body.String())
	}
	w = call(http.MethodGet, "/api/v1/karaoke/account/recordings", "", false)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"items"`) {
		t.Fatalf("authenticated recordings: %d %s", w.Code, w.Body.String())
	}
	if w = call(http.MethodPost, "/api/v1/karaoke/account/logout", "{}", false); w.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF: %d", w.Code)
	}
	if w = call(http.MethodPost, "/api/v1/karaoke/account/logout", "{}", true); w.Code != http.StatusOK || len(cookies) != 0 {
		t.Fatalf("logout: %d cookies %d", w.Code, len(cookies))
	}
	ingress.Generation++
	current.set(ingress)
	if w = call(http.MethodGet, "/api/v1/karaoke/account/status", "", false); w.Code != http.StatusForbidden {
		t.Fatalf("stale ingress: %d", w.Code)
	}
}
