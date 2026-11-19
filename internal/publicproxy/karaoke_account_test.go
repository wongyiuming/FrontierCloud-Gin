package publicproxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestKaraokeAccountProxyAuthenticatesAndFiltersCredentials(t *testing.T) {
	var wrapped atomic.Value
	server := httptest.NewTLSServer(http.StripPrefix(EdgePrefix, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped.Load().(http.Handler).ServeHTTP(w, r)
	})))
	defer server.Close()
	v, _, current := fixtureVerifier(t, server.URL)
	var calls atomic.Int32
	wrapped.Store(v.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("X-Karaoke-CSRF") != "csrf-proof" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "__Host-karaoke_session=session; __Host-karaoke_csrf=csrf" {
			t.Errorf("incorrect forwarded credential boundary: %v", r.Header)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"password":"fixture-only"}` {
			t.Errorf("unexpected request body: %q", body)
		}
		http.SetCookie(w, &http.Cookie{Name: "__Host-karaoke_session", Value: "next", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		http.SetCookie(w, &http.Cookie{Name: "__Host-karaoke_csrf", Value: "nextcsrf", Path: "/", Secure: true, SameSite: http.SameSiteLaxMode})
		http.SetCookie(w, &http.Cookie{Name: "admin", Value: "secret", Path: "/", Secure: true})
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})))
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	h, err := New(Config{MasterOrigin: server.URL, PublicOrigin: "https://entry.example", RootCAs: roots, MasterEdge: true, Peer: &PeerConfig{NodeID: testPeerID, Generation: 9, Signer: fixtureSigner{}}})
	if err != nil {
		t.Fatal(err)
	}
	defer h.CloseIdleConnections()
	request := func() *http.Request {
		r := incoming(http.MethodPost, "/api/v1/karaoke/account/login", strings.NewReader(`{"password":"fixture-only"}`))
		r.TLS = &tls.ConnectionState{}
		r.RemoteAddr = "192.0.2.10:1234"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://entry.example")
		r.Header.Set("X-Karaoke-CSRF", "csrf-proof")
		r.Header.Set("Cookie", "admin=must-not-forward; __Host-karaoke_session=session; __Host-karaoke_csrf=csrf")
		r.Header.Set("Authorization", "Bearer must-not-forward")
		return r
	}
	w := newRecorder()
	h.ServeHTTP(w, request())
	if w.Code != http.StatusOK || len(w.Result().Cookies()) != 2 || w.Header().Get("Cache-Control") != "private, no-store" || calls.Load() != 1 {
		t.Fatalf("account response: status %d cookies %v calls %d", w.Code, w.Result().Cookies(), calls.Load())
	}
	duplicate := request()
	duplicate.Header.Set("Cookie", "__Host-karaoke_session=a; __Host-karaoke_session=b")
	w = newRecorder()
	h.ServeHTTP(w, duplicate)
	if w.Code != http.StatusBadRequest || calls.Load() != 1 {
		t.Fatalf("duplicate credential accepted: %d calls %d", w.Code, calls.Load())
	}
	current.set(store.PublicIngress{NodeID: testPeerID, PublicOrigin: "https://entry.example", Generation: 10}, nil)
	w = newRecorder()
	h.ServeHTTP(w, request())
	if w.Code != http.StatusForbidden || calls.Load() != 1 {
		t.Fatalf("stale ingress invoked account mutation: %d calls %d", w.Code, calls.Load())
	}
}

func TestKaraokeCaptchaPathAndSignedAccountHeaders(t *testing.T) {
	good := "/api/v1/karaoke/account/captcha/" + strings.Repeat("a", 32)
	if !Eligible(incoming(http.MethodGet, good, nil)) {
		t.Fatal("valid captcha image excluded")
	}
	for _, path := range []string{good + "/other", "/api/v1/karaoke/account/captcha/" + strings.Repeat("A", 32), "/api/v1/karaoke/account/captcha/admin", "/api/v1/karaoke/account/recordings/anything", "/api/v1/media/admin/users"} {
		if Eligible(incoming(http.MethodGet, path, nil)) {
			t.Fatalf("unreviewed account route eligible: %s", path)
		}
	}
	const master = "https://master.example"
	v, _, _ := fixtureVerifier(t, master)
	r := signedFixtureFor(t, master, http.MethodPost, "/api/v1/karaoke/account/login")
	r.Header.Set("X-Karaoke-CSRF", "tampered-after-signing")
	w := httptest.NewRecorder()
	v.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("tampered request reached account") })).ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("unsigned account CSRF header accepted: %d", w.Code)
	}
}
