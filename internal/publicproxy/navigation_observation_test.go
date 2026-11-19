package publicproxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestNavigationAndObservationAcrossSignedTLSEdge(t *testing.T) {
	var wrapped atomic.Value
	server := httptest.NewTLSServer(http.StripPrefix(EdgePrefix, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped.Load().(http.Handler).ServeHTTP(w, r)
	})))
	defer server.Close()
	v, _, current := fixtureVerifier(t, server.URL)
	var calls atomic.Int32
	wrapped.Store(v.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/api/v1/media", http.StatusTemporaryRedirect)
		case "/api/v1/media/refresh":
			w.Header().Set("Clear-Site-Data", `"cache"`)
			http.Redirect(w, r, "/api/v1/media?ui=0123456789abcdef0123456789abcdef", http.StatusSeeOther)
		case "/api/v1/media/network-observation":
			identity, ok := network.AuthenticatedIngressFromContext(r.Context())
			if !ok || identity.ClientIP != "192.0.2.10" || r.Header.Get("X-Forwarded-For") != "" {
				t.Errorf("incorrect signed client identity: %#v", identity)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	})))
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	h, err := New(Config{MasterOrigin: server.URL, PublicOrigin: "https://entry.example", RootCAs: roots, MasterEdge: true, Peer: &PeerConfig{NodeID: testPeerID, Generation: 9, Signer: fixtureSigner{}}})
	if err != nil {
		t.Fatal(err)
	}
	defer h.CloseIdleConnections()
	request := func(method, path, body string) *testResponseRecorder {
		req := incoming(method, path, strings.NewReader(body))
		req.TLS = &tls.ConnectionState{}
		req.RemoteAddr = "192.0.2.10:1234"
		req.Header.Set("Origin", "https://entry.example")
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		w := newRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	root := request(http.MethodGet, "/", "")
	if root.Code != http.StatusTemporaryRedirect || root.Header().Get("Location") != "/api/v1/media" {
		t.Fatalf("root navigation: %d %v", root.Code, root.Header())
	}
	refresh := request(http.MethodGet, "/api/v1/media/refresh", "")
	if refresh.Code != http.StatusSeeOther || refresh.Header().Get("Location") != "/api/v1/media?ui=0123456789abcdef0123456789abcdef" || refresh.Header().Get("Clear-Site-Data") != `"cache"` {
		t.Fatalf("refresh: %d %v", refresh.Code, refresh.Header())
	}
	if w := request(http.MethodPost, "/api/v1/media/network-observation", `{"addresses":[]}`); w.Code != http.StatusNoContent {
		t.Fatalf("observation: %d", w.Code)
	}
	if w := request(http.MethodPost, "/api/v1/media/network-observation", strings.Repeat("x", 16<<10)); w.Code != http.StatusNoContent {
		t.Fatalf("16 KiB observation rejected by signed Master verifier: %d", w.Code)
	}
	if w := request(http.MethodPost, "/api/v1/media/network-observation", strings.Repeat("x", (16<<10)+1)); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize observation accepted: %d", w.Code)
	}
	if w := request(http.MethodPost, "/api/v1/media/crypto/session", strings.Repeat("x", maxRequestBody+1)); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("unrelated route body limit widened: %d", w.Code)
	}
	current.set(store.PublicIngress{NodeID: testPeerID, PublicOrigin: "https://entry.example", Generation: 10}, nil)
	if w := request(http.MethodGet, "/", ""); w.Code != http.StatusForbidden || calls.Load() != 4 {
		t.Fatalf("stale ingress accepted: %d, calls=%d", w.Code, calls.Load())
	}
}

func TestNavigationRedirectsAreExactAndSameOrigin(t *testing.T) {
	const refreshTarget = "/api/v1/media?ui=0123456789abcdef0123456789abcdef"
	const logoPath = brandLogoPrefix + "music"
	const logoTarget = logoPath + "?v=0123456789abcdef"
	for _, tc := range []struct {
		name, path, location, clear string
		upstream, want              int
	}{
		{"root", "/", "/api/v1/media", "", 307, 307},
		{"refresh", "/api/v1/media/refresh", refreshTarget, `"cache"`, 303, 303},
		{"root external", "/", "https://evil.example/api/v1/media", "", 307, 502},
		{"root scheme relative", "/", "//evil.example/api/v1/media", "", 307, 502},
		{"root unexpected status", "/", "/api/v1/media", "", 302, 502},
		{"refresh external", "/api/v1/media/refresh", "https://evil.example/", `"cache"`, 303, 502},
		{"refresh different path", "/api/v1/media/refresh", "/api/v1/media/admin?ui=0123456789abcdef0123456789abcdef", `"cache"`, 303, 502},
		{"refresh extra query", "/api/v1/media/refresh", refreshTarget + "&other=1", `"cache"`, 303, 502},
		{"refresh bad clear directive", "/api/v1/media/refresh", refreshTarget, `"cookies"`, 303, 502},
		{"refresh missing clear directive", "/api/v1/media/refresh", refreshTarget, "", 303, 502},
		{"refresh unexpected success", "/api/v1/media/refresh", "", "", 200, 502},
		{"root upstream error", "/", "", "", 503, 503},
		{"logo", logoPath, logoTarget, "", 307, 307},
		{"logo external", logoPath, "https://evil.example" + logoTarget, "", 307, 502},
		{"logo different kind", logoPath, brandLogoPrefix + "media?v=0123456789abcdef", "", 307, 502},
		{"logo extra query", logoPath, logoTarget + "&next=1", "", 307, 502},
		{"logo bad version", logoPath, logoPath + "?v=0123456789abcdeF", "", 307, 502},
		{"logo unexpected status", logoPath, logoTarget, "", 302, 502},
		{"other asset redirect", "/static/js/player.js", logoTarget, "", 307, 502},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.location != "" {
					w.Header().Set("Location", tc.location)
				}
				if tc.clear != "" {
					w.Header().Set("Clear-Site-Data", tc.clear)
				}
				w.WriteHeader(tc.upstream)
			}))
			defer server.Close()
			h := testProxy(t, server)
			w := invoke(h, http.MethodGet, tc.path, "")
			if w.Code != tc.want {
				t.Fatalf("status %d, want %d", w.Code, tc.want)
			}
			if tc.want == 303 || tc.want == 307 {
				if w.Header().Get("Location") != tc.location || w.Header().Get("Clear-Site-Data") != tc.clear {
					t.Fatalf("navigation headers: %v", w.Header())
				}
			} else if w.Header().Get("Location") != "" || w.Header().Get("Clear-Site-Data") != "" {
				t.Fatalf("unsafe navigation headers escaped: %v", w.Header())
			}
		})
	}
	for _, path := range []string{"/?x=1", "/api/v1/media/refresh?x=1", "/api/v1/media/refresh?"} {
		if _, ok := match(incoming(http.MethodGet, path, nil)); ok {
			t.Fatalf("accepted navigation query %q", path)
		}
	}
}

func TestNavigationRejectsAmbiguousHeaders(t *testing.T) {
	root := &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: http.Header{}}
	root.Header.Add("Location", "/api/v1/media")
	root.Header.Add("Location", "https://evil.example/")
	if validNavigationResponse("/", root) {
		t.Fatal("duplicate locations accepted")
	}
	const logoPath = brandLogoPrefix + "music"
	logo := &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: http.Header{}}
	logo.Header.Add("Location", logoPath+"?v=0123456789abcdef")
	logo.Header.Add("Location", logoPath+"?v=fedcba9876543210")
	if validNavigationResponse(logoPath, logo) {
		t.Fatal("duplicate logo locations accepted")
	}
	refresh := &http.Response{StatusCode: http.StatusSeeOther, Header: http.Header{}}
	refresh.Header.Set("Location", "/api/v1/media?ui=0123456789abcdef0123456789abcdef")
	refresh.Header.Add("Clear-Site-Data", `"cache"`)
	refresh.Header.Add("Clear-Site-Data", `"cookies"`)
	if validNavigationResponse("/api/v1/media/refresh", refresh) {
		t.Fatal("duplicate clear-site-data directives accepted")
	}
}

func TestObservationUsesSignedClientAndCommitsBeforeWriting(t *testing.T) {
	const master = "https://master.example"
	for _, failCommit := range []bool{false, true} {
		v, _, current := fixtureVerifier(t, master)
		if failCommit {
			current.commitErr = errors.New("disconnected")
		}
		called := false
		req := signedFixtureFor(t, master, http.MethodPost, "/api/v1/media/network-observation")
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		req.Header.Set("X-Real-IP", "127.0.0.1")
		w := newRecorder()
		v.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			ctx, ok := network.AuthenticatedIngressFromContext(r.Context())
			if !ok || ctx.ClientIP != "192.0.2.10" || r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Real-IP") != "" {
				t.Errorf("untrusted observation identity: %#v headers=%v", ctx, r.Header)
			}
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(w, req)
		if failCommit && (called || w.Code != http.StatusServiceUnavailable) || !failCommit && (!called || w.Code != http.StatusNoContent) {
			t.Fatalf("commit failure=%t called=%t status=%d", failCommit, called, w.Code)
		}
	}
}

func TestObservationBodyIsBoundedBeforeForwarding(t *testing.T) {
	called := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	h := testProxy(t, server)
	for _, unknownLength := range []bool{false, true} {
		req := incoming(http.MethodPost, "/api/v1/media/network-observation", strings.NewReader(strings.Repeat("x", (16<<10)+1)))
		if unknownLength {
			req.ContentLength = -1
		}
		w := newRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusRequestEntityTooLarge || called {
			t.Fatalf("unknown-length=%t status=%d forwarded=%t", unknownLength, w.Code, called)
		}
	}
}
