package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
)

func TestAdminManagementLogin(t *testing.T) {
	router, db, dir, public := publicFixture(t, false)
	settings := public.settings
	settings.TLSEnabled = true
	settings.AdminOrigin = "https://master.example:8443"
	settings.TrustedProxyNetworks = []string{"172.18.0.0/16"}
	settings.PublicIngressTrustedProxyNetworks = []string{"172.18.0.2/32"}
	settings.SecretsDirectory = filepath.Join(dir, "secrets")
	const key = "management-test-admin-key"
	if err := os.WriteFile(filepath.Join(settings.SecretsDirectory, "admin_key"), []byte(key), 0600); err != nil {
		t.Fatal(err)
	}
	identity, err := node.Initialize(context.Background(), db.Nodes(), settings.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := admin.New(settings, &handoffCache{sessions: map[string]map[string]string{}}, db.Admin())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RegisterAdmin(router, settings, auth, public, identity); err != nil {
		t.Fatal(err)
	}
	const adminPage = "/api/v1/media/admin/"
	const elevate = adminPage + "elevate"
	newRequest := func(path string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, settings.AdminOrigin+path, nil)
		r.RemoteAddr = "192.0.2.5:1234"
		r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9")
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		return r
	}
	call := func(r *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	proxy := func(r *http.Request, addr string) {
		r.TLS = nil
		r.RemoteAddr = addr
		r.Header.Set("X-Real-IP", "192.0.2.5")
		r.Header.Set("X-Forwarded-Proto", "https")
	}
	for _, path := range []string{strings.TrimSuffix(adminPage, "/"), adminPage} {
		r := newRequest(path)
		proxy(r, "172.18.0.2:1234")
		w := call(r)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != adminLoginPath || len(w.Result().Cookies()) != 0 {
			t.Fatalf("Admin navigation: %d %v", w.Code, w.Header())
		}
	}
	for _, path := range []string{adminPage + "status", adminPage} {
		r := newRequest(path)
		if path == adminPage {
			r.Header.Set("Sec-Fetch-Mode", "cors")
		}
		w := call(r)
		if w.Code != http.StatusUnauthorized || w.Header().Get("Location") != "" || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
			t.Fatalf("non-navigation auth contract: %d %v", w.Code, w.Header())
		}
	}

	for _, useProxy := range []bool{false, true} {
		r := newRequest(adminLoginPath)
		if useProxy {
			proxy(r, "172.18.0.2:1234")
		}
		w := call(r)
		body := w.Body.String()
		if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") || w.Header().Get("Referrer-Policy") != "no-referrer" || len(w.Result().Cookies()) != 0 ||
			!strings.Contains(body, `method="post" action="`+elevate+`"`) || !strings.Contains(body, `name="token" type="password"`) || strings.Contains(body, key) {
			t.Fatalf("management login response: %d, proxy=%v", w.Code, useProxy)
		}
		_, noncePart, found := strings.Cut(w.Header().Get("Content-Security-Policy"), "'nonce-")
		nonce, _, _ := strings.Cut(noncePart, "'")
		if !found || nonce == "" || !strings.Contains(body, `<script nonce="`+nonce+`">`) {
			t.Fatal("login script is not covered by the response CSP nonce")
		}
	}
	peer, err := network.WithAuthenticatedIngress(context.Background(), network.AuthenticatedIngress{
		NodeID: identity.ID, Generation: 1, PublicOrigin: "https://ingress.example", ClientIP: "192.0.2.5",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(*http.Request) *http.Request
	}{
		{"different host", func(r *http.Request) *http.Request { r.Host = "public.example:8443"; return r }},
		{"missing mapped port", func(r *http.Request) *http.Request { r.Host = "master.example"; return r }},
		{"plain loopback", func(r *http.Request) *http.Request { r.TLS = nil; r.RemoteAddr = "127.0.0.1:1234"; return r }},
		{"forged proxy headers", func(r *http.Request) *http.Request { proxy(r, "192.0.2.5:1234"); return r }},
		{"ordinary proxy trust", func(r *http.Request) *http.Request { proxy(r, "172.18.0.3:1234"); return r }},
		{"authenticated ingress", func(r *http.Request) *http.Request { return r.WithContext(peer) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, path := range []string{adminLoginPath, adminPage} {
				w := call(test.edit(newRequest(path)))
				if w.Code < 400 || w.Header().Get("Location") != "" || len(w.Result().Cookies()) != 0 || strings.Contains(w.Body.String(), `name="token"`) {
					t.Fatalf("outside management boundary: %d", w.Code)
				}
			}
		})
	}

	form := url.Values{"token": {key}}
	post := httptest.NewRequest(http.MethodPost, settings.AdminOrigin+elevate, strings.NewReader(form.Encode()))
	proxy(post, "172.18.0.2:1234")
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", settings.AdminOrigin)
	w := call(post)
	if w.Code != http.StatusOK {
		t.Fatalf("existing elevate login: %d", w.Code)
	}
	r := newRequest(adminPage)
	proxy(r, "172.18.0.2:1234")
	var sessionCookie bool
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == settings.AdminCookieName() {
			sessionCookie = cookie.HttpOnly && cookie.Secure && cookie.Domain == ""
		}
		r.AddCookie(cookie)
	}
	if !sessionCookie {
		t.Fatal("existing elevate did not issue a secure management session")
	}
	if w := call(r); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "节点管理") {
		t.Fatalf("authenticated AdminGUI navigation: %d", w.Code)
	}
}
