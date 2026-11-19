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

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestPageProxyPreservesCSPAndRejectsStaleIngress(t *testing.T) {
	var wrapped atomic.Value
	server := httptest.NewTLSServer(http.StripPrefix(EdgePrefix, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if site := r.Header.Get("Sec-Fetch-Site"); site == "same-site" || site == "cross-site" {
			if r.Header.Get(fetchModeHeader) != "navigate" || r.Header.Get(fetchDestHeader) != "document" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
				t.Error("cross-origin document metadata or credentials changed at the edge")
			}
		} else if r.Header.Get(fetchModeHeader) != "" || r.Header.Get(fetchDestHeader) != "" {
			t.Error("ordinary requests should retain their original proof format")
		}
		wrapped.Load().(http.Handler).ServeHTTP(w, r)
	})))
	defer server.Close()
	v, _, current := fixtureVerifier(t, server.URL)
	var calls atomic.Int32
	wrapped.Store(v.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/api/v1/media", http.StatusTemporaryRedirect)
			return
		}
		if r.URL.Path == "/media-crypto-sw.js" {
			w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'")
			w.Header().Set("Service-Worker-Allowed", "/")
			_, _ = io.WriteString(w, "worker")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "script-src 'nonce-test'")
		w.Header().Set("X-Frame-Options", "DENY")
		_, _ = io.WriteString(w, `<script nonce="test">ok()</script>`)
	})))
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	h, err := New(Config{MasterOrigin: server.URL, PublicOrigin: "https://entry.example", RootCAs: roots, MasterEdge: true, Peer: &PeerConfig{NodeID: testPeerID, Generation: 9, Signer: fixtureSigner{}}})
	if err != nil {
		t.Fatal(err)
	}
	defer h.CloseIdleConnections()
	const category = "/api/v1/media/music/category?path=music%2Fartist"
	request := func(method, path string, headers http.Header) *testResponseRecorder {
		r := incoming(method, path, nil)
		r.Header = headers.Clone()
		r.TLS = &tls.ConnectionState{}
		r.RemoteAddr = "192.0.2.10:1234"
		w := newRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := request(http.MethodGet, category, nil)
	if w.Code != http.StatusOK || w.Header().Get("Content-Security-Policy") != "script-src 'nonce-test'" || w.Header().Get("X-Frame-Options") != "DENY" || !strings.Contains(w.Body.String(), `nonce="test"`) || w.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("page forwarding: %d %v %q", w.Code, w.Header(), w.Body.String())
	}
	document := func(site string) http.Header {
		headers := make(http.Header)
		headers.Set("Sec-Fetch-Site", site)
		headers.Set(fetchModeHeader, "navigate")
		headers.Set(fetchDestHeader, "document")
		return headers
	}
	for _, site := range []string{"none", "same-site", "cross-site"} {
		headers := document(site)
		headers.Set("Cookie", "__Host-karaoke_session=browser")
		headers.Set("Authorization", "Bearer ignored")
		w := request(http.MethodGet, category, headers)
		if w.Code != http.StatusOK || w.Header().Get("Content-Security-Policy") != "script-src 'nonce-test'" {
			t.Fatalf("document navigation %s: status=%d headers=%v", site, w.Code, w.Header())
		}
	}
	root := request(http.MethodGet, "/", document("cross-site"))
	if root.Code != http.StatusTemporaryRedirect || root.Header().Get("Location") != "/api/v1/media" {
		t.Fatalf("cross-origin root navigation: status=%d headers=%v", root.Code, root.Header())
	}
	for _, tc := range []struct {
		name, method, path string
		change             func(http.Header)
	}{
		{"iframe", http.MethodGet, category, func(h http.Header) { h.Set(fetchDestHeader, "iframe") }},
		{"cors fetch", http.MethodGet, category, func(h http.Header) { h.Set(fetchModeHeader, "cors") }},
		{"missing mode", http.MethodGet, category, func(h http.Header) { h.Del(fetchModeHeader) }},
		{"duplicate destination", http.MethodGet, category, func(h http.Header) { h.Add(fetchDestHeader, "document") }},
		{"origin present", http.MethodGet, category, func(h http.Header) { h.Set("Origin", "https://entry.example") }},
		{"catalog API", http.MethodGet, "/api/v1/media/catalog/media", nil},
		{"account status", http.MethodGet, "/api/v1/karaoke/account/status", nil},
		{"worker asset", http.MethodGet, "/media-crypto-sw.js", nil},
		{"cache refresh", http.MethodGet, "/api/v1/media/refresh", nil},
		{"crypto POST", http.MethodPost, "/api/v1/media/crypto/session", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := document("same-site")
			if tc.change != nil {
				tc.change(headers)
			}
			before := calls.Load()
			if w := request(tc.method, tc.path, headers); w.Code != http.StatusForbidden || calls.Load() != before {
				t.Fatalf("unexpected cross-origin request: status=%d calls=%d", w.Code, calls.Load()-before)
			}
		})
	}
	for _, name := range []string{fetchModeHeader, fetchDestHeader} {
		headers := document("same-site")
		hash := browserHash(headers)
		headers.Del(name)
		if browserHash(headers) == hash {
			t.Fatalf("document proof did not bind %s", name)
		}
	}
	workerReq := incoming(http.MethodGet, "/media-crypto-sw.js", nil)
	workerReq.TLS = &tls.ConnectionState{}
	workerReq.RemoteAddr = "192.0.2.10:1234"
	worker := newRecorder()
	h.ServeHTTP(worker, workerReq)
	if worker.Code != http.StatusOK || worker.Body.String() != "worker" || worker.Header().Get("Service-Worker-Allowed") != "/" {
		t.Fatalf("authenticated worker forwarding: %d %v", worker.Code, worker.Header())
	}
	current.set(store.PublicIngress{NodeID: testPeerID, PublicOrigin: "https://entry.example", Generation: 10}, nil)
	if stale := request(http.MethodGet, category, document("same-site")); stale.Code != http.StatusForbidden || calls.Load() != 6 {
		t.Fatalf("stale ingress served a page: %d, calls %d", stale.Code, calls.Load())
	}
}

func TestVerifierAcceptsOnlyConfiguredHTTPSProxyEdge(t *testing.T) {
	const master = "https://master.example"
	resolver, err := network.New([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	v, _, _ := fixtureVerifier(t, master)
	v.edge = resolver
	for _, tc := range []struct {
		peer, scheme string
		want         int
	}{
		{"10.1.2.3:1234", "https", http.StatusOK},
		{"10.1.2.3:1234", "http", http.StatusForbidden},
		{"192.0.2.4:1234", "https", http.StatusForbidden},
	} {
		r := signedFixtureFor(t, master, http.MethodGet, "/api/v1/media")
		r.TLS = nil
		r.RemoteAddr = tc.peer
		r.Header.Set("X-Real-IP", "192.0.2.10")
		r.Header.Set("X-Forwarded-Proto", tc.scheme)
		w := httptest.NewRecorder()
		v.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })).ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("peer %s scheme %s: %d", tc.peer, tc.scheme, w.Code)
		}
	}
}

func TestPageProxyRejectsMissingOrAmbiguousCSP(t *testing.T) {
	for _, policies := range [][]string{nil, {"script-src 'self'", "script-src 'none'"}} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, policy := range policies {
				w.Header().Add("Content-Security-Policy", policy)
			}
			_, _ = io.WriteString(w, "page")
		}))
		h := testProxy(t, server)
		w := invoke(h, http.MethodGet, "/api/v1/media", "")
		if w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), "page") {
			t.Fatalf("invalid CSP accepted: %d %q", w.Code, w.Body.String())
		}
		server.Close()
	}
}

func TestPublicAssetsAreExactAndWorkerRetainsScope(t *testing.T) {
	for _, path := range []string{"/static/js/admin.js", "/static/media/admin.html", "/static/js/media-crypto.js", "/static/js/../admin.js", "/static/js/%70layer.js"} {
		if _, ok := match(incoming(http.MethodGet, path, nil)); ok {
			t.Fatalf("private or noncanonical asset accepted: %s", path)
		}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "" {
			t.Error("conditional request forwarded")
		}
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'")
		w.Header().Set("Service-Worker-Allowed", "/")
		_, _ = io.WriteString(w, "worker")
	}))
	defer server.Close()
	h := testProxy(t, server)
	r := incoming(http.MethodGet, "/media-crypto-sw.js", nil)
	r.Header.Set("If-None-Match", `"old"`)
	w := newRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Body.String() != "worker" || w.Header().Get("Service-Worker-Allowed") != "/" || w.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("worker response: %d %v %q", w.Code, w.Header(), w.Body.String())
	}
}

func TestKaraokePageAndAssetsUseAuthenticatedIngress(t *testing.T) {
	const logoVersion = "0123456789abcdef"
	var wrapped atomic.Value
	server := httptest.NewTLSServer(http.StripPrefix(EdgePrefix, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped.Load().(http.Handler).ServeHTTP(w, r)
	})))
	defer server.Close()
	v, _, current := fixtureVerifier(t, server.URL)
	var calls atomic.Int32
	wrapped.Store(v.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/karaoke/" {
			w.Header().Set("Content-Security-Policy", "script-src 'nonce-test'")
		}
		if strings.HasPrefix(r.URL.Path, brandLogoPrefix) {
			if r.URL.Query().Get("v") != logoVersion {
				http.Redirect(w, r, r.URL.Path+"?v="+logoVersion, http.StatusTemporaryRedirect)
				return
			}
			w.Header().Set("Content-Type", "image/webp")
		}
		_, _ = io.WriteString(w, r.URL.Path)
	})))
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	h, err := New(Config{MasterOrigin: server.URL, PublicOrigin: "https://entry.example", RootCAs: roots, MasterEdge: true, Peer: &PeerConfig{NodeID: testPeerID, Generation: 9, Signer: fixtureSigner{}}})
	if err != nil {
		t.Fatal(err)
	}
	defer h.CloseIdleConnections()
	paths := []string{
		"/karaoke/", "/static/css/karaoke.css", "/static/css/lyrics-window.css",
		"/static/js/karaoke.js", "/static/js/karaoke-audio-quality.js", "/static/js/karaoke-ui.js", "/static/js/upload-sha256.js",
		"/static/js/lyrics-window.js", "/static/js/network-observation.js", brandLogoPrefix + "entertainment", brandLogoPrefix + "music", brandLogoPrefix + "media",
	}
	request := func(path string) *testResponseRecorder {
		r := incoming(http.MethodGet, path, nil)
		r.TLS = &tls.ConnectionState{}
		r.RemoteAddr = "192.0.2.10:1234"
		w := newRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, path := range paths {
		w := request(path)
		if strings.HasPrefix(path, brandLogoPrefix) {
			location := w.Header().Get("Location")
			if w.Code != http.StatusTemporaryRedirect || location != path+"?v="+logoVersion {
				t.Fatalf("%s: unexpected logo redirect: %d %q", path, w.Code, location)
			}
			w = request(location)
			if w.Header().Get("Content-Type") != "image/webp" {
				t.Fatalf("%s: unexpected logo content type: %v", path, w.Header())
			}
		}
		if w.Code != http.StatusOK || w.Body.String() != path {
			t.Fatalf("%s: %d %q", path, w.Code, w.Body.String())
		}
		if path == "/karaoke/" && w.Header().Get("Content-Security-Policy") != "script-src 'nonce-test'" {
			t.Fatalf("karaoke page CSP: %v", w.Header())
		}
	}
	for _, path := range []string{"/karaoke/admin", "/api/v1/media/brand/logo/unknown", "/static/js/karaoke-admin.js"} {
		if Eligible(incoming(http.MethodGet, path, nil)) {
			t.Fatalf("unreviewed path eligible: %s", path)
		}
	}
	if Eligible(incoming(http.MethodPost, "/karaoke/", nil)) {
		t.Fatal("page accepted a mutation")
	}
	current.set(store.PublicIngress{NodeID: testPeerID, PublicOrigin: "https://entry.example", Generation: 10}, nil)
	r := incoming(http.MethodGet, "/karaoke/", nil)
	r.TLS = &tls.ConnectionState{}
	r.RemoteAddr = "192.0.2.10:1234"
	w := newRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || calls.Load() != int32(len(paths)+3) {
		t.Fatalf("stale ingress reached karaoke handler: status %d calls %d", w.Code, calls.Load())
	}
}

func TestWorkerRejectsPartialResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Service-Worker-Allowed", "/")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = io.WriteString(w, "incomplete")
	}))
	defer server.Close()
	h := testProxy(t, server)
	w := invoke(h, http.MethodGet, "/media-crypto-sw.js", "")
	if w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), "incomplete") {
		t.Fatalf("partial worker exposed: %d %q", w.Code, w.Body.String())
	}
}
