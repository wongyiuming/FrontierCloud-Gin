package httpapi

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestAuthenticatedMasterAdminReadsCiphertextAfterPublicIngressChanges(t *testing.T) {
	router, db, dir, public, path := cryptoLeaseFixture(t, true)
	settings := public.settings
	settings.TLSEnabled = true
	settings.AdminOrigin = cryptoLeaseOrigin
	settings.SecretsDirectory = filepath.Join(dir, "secrets")
	const key = "admin-ingress-independence-test-key"
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
	if _, err = RegisterAdmin(router, settings, auth, public, identity); err != nil {
		t.Fatal(err)
	}
	routing := selectedIngressRepository{NodeRepository: db.Nodes(), PublicRoutingRepository: db.Nodes().(store.PublicRoutingRepository), selected: store.PublicIngress{NodeID: strings.Repeat("a", 32), PublicOrigin: "https://entry.test", Generation: 9}}
	public.media.ConfigureCluster(routing, db.Pool(), public.control)
	request := func(method, target, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, cryptoLeaseOrigin+target, strings.NewReader(body))
		r.TLS = &tls.ConnectionState{}
		if method == http.MethodPost {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if method == http.MethodGet {
			r.Header.Set("Range", "bytes=0-3")
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	target := "/api/v1/media/admin/crypto/bytes?" + url.Values{"file_path": {path}}.Encode()
	if w := request(http.MethodGet, target, "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous admin read: %d", w.Code)
	}
	w := request(http.MethodPost, "/api/v1/media/admin/elevate", url.Values{"token": {key}}.Encode(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("admin login: %d %s", w.Code, w.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == settings.AdminCookieName() {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("admin session missing")
	}
	w = request(http.MethodGet, target, "", cookie)
	if w.Code != http.StatusPartialContent || w.Body.Len() != 4 || w.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("authenticated admin ciphertext read: %d %v %q", w.Code, w.Header(), w.Body.String())
	}
	w = request(http.MethodGet, "/api/v1/media/stream?"+url.Values{"file_path": {path}}.Encode(), "", nil)
	if w.Code < 400 || w.Header().Get("Location") != "" || w.Header().Get("X-Accel-Redirect") != "" {
		t.Fatalf("old public ingress admitted: %d %v", w.Code, w.Header())
	}
}
