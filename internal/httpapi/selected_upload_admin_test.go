package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

type selectedAdminTestCache struct {
	mu       sync.Mutex
	sessions map[string]map[string]string
}

func (c *selectedAdminTestCache) ReserveAttempt(context.Context, string, int) (int64, error) {
	return 1, nil
}
func (c *selectedAdminTestCache) Delete(_ context.Context, k string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.sessions, k)
	return nil
}
func (c *selectedAdminTestCache) TakeTemporary(context.Context, string) (string, error) {
	return "", nil
}
func (c *selectedAdminTestCache) PutTemporary(context.Context, string, string, int) (bool, error) {
	return false, nil
}
func (c *selectedAdminTestCache) SaveSession(_ context.Context, k string, v map[string]string, _ int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessions[k] = v
	return nil
}
func (c *selectedAdminTestCache) Session(_ context.Context, k string) (map[string]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessions[k], nil
}
func (c *selectedAdminTestCache) Refresh(_ context.Context, k string, _ int) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessions[k] != nil, nil
}
func (c *selectedAdminTestCache) RotationLock(context.Context, string, int) (bool, error) {
	return false, nil
}
func (c *selectedAdminTestCache) RotationUnlock(context.Context, string) error { return nil }
func (c *selectedAdminTestCache) ReplaceSessions(context.Context, string, string, int) error {
	return nil
}

func TestSelectedAdminRoutesRequireRealSessionAndClosedGate(t *testing.T) {
	router, db, dir, public := publicFixture(t, false)
	settings := public.settings
	settings.TLSEnabled = true
	settings.AdminOrigin = "https://master.test"
	settings.SecretsDirectory = filepath.Join(dir, "secrets")
	key := "selected-admin-fixture-key"
	if err := os.WriteFile(filepath.Join(settings.SecretsDirectory, "admin_key"), []byte(key), 0600); err != nil {
		t.Fatal(err)
	}
	identity, err := node.Initialize(context.Background(), db.Nodes(), settings.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := admin.New(settings, &selectedAdminTestCache{sessions: map[string]map[string]string{}}, db.Admin())
	if err != nil {
		t.Fatal(err)
	}
	handler, err := RegisterAdmin(router, settings, auth, public, identity)
	if err != nil {
		t.Fatal(err)
	}
	if err = handler.ConfigureSelectedUploadRuntime(nil); err == nil {
		t.Fatal("nil runtime installed")
	}
	public.opaqueTree = &sealedtree.SQLStore{}
	login, err := auth.Login(context.Background(), key, admin.RequestInfo{IP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	perform := func(route, body string, cookie, csrf bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://master.test/api/v1/media/admin"+route, strings.NewReader(body))
		r.Header.Set("Origin", "https://master.test")
		if cookie {
			r.AddCookie(&http.Cookie{Name: settings.AdminCookieName(), Value: login.Cookie})
		}
		if csrf {
			r.AddCookie(&http.Cookie{Name: settings.CSRFCookieName(), Value: login.CSRF})
			r.Header.Set("X-CSRF-Token", login.CSRF)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	if w := perform("/upload/selected/prepare", "", false, false); w.Code != http.StatusUnauthorized {
		t.Fatal("unauthenticated selected route", w.Code)
	}
	if w := perform("/upload/selected/prepare", "", true, false); w.Code != http.StatusForbidden {
		t.Fatal("missing CSRF accepted", w.Code)
	}
	if w := perform("/upload/selected/prepare", "", true, true); w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("missing gate not closed", w.Code, w.Header())
	}
	for _, request := range []struct{ route, body string }{
		{"/directory-priority", `{"path":"music/album","value":8}`},
		{"/media-priority", `{"media_path":"music/album/example.mp3","value":8}`},
		{"/hide", `{"paths":["music/album"],"hidden":true}`},
	} {
		if w := perform(request.route, request.body, true, false); w.Code != http.StatusForbidden {
			t.Fatal("sealed mutation accepted without CSRF", request.route, w.Code)
		}
		if w := perform(request.route, request.body, true, true); w.Code != http.StatusServiceUnavailable {
			t.Fatal("sealed mutation bypassed unavailable runtime", request.route, w.Code)
		}
	}
	if w := perform("/directory/rename", `{"path":"music/album","new_name":"renamed"}`, true, false); w.Code != http.StatusForbidden {
		t.Fatal("rename accepted without CSRF", w.Code)
	}
	if w := perform("/directory/rename", `{"path":"music/album","new_name":"renamed"}`, true, true); w.Code != http.StatusServiceUnavailable {
		t.Fatal("rename bypassed unavailable tree runtime", w.Code)
	}
	get := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "https://master.test"+path, nil)
		r.AddCookie(&http.Cookie{Name: settings.AdminCookieName(), Value: login.Cookie})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	if w := get("/api/v1/media/admin/storage-pool"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"selected_upload":true`) {
		t.Fatal("encrypted tree did not advertise the selected protocol", w.Code, w.Body.String())
	}
	if w := get("/api/v1/media/admin/lyrics/catalog"); w.Code != http.StatusServiceUnavailable {
		t.Fatal("tree lyric catalog bypassed unavailable runtime", w.Code)
	}
	if w := get("/api/v1/media/admin"); w.Code != http.StatusOK {
		t.Fatal("admin page not served", w.Code)
	} else {
		page := w.Body.String()
		hash := strings.Index(page, "upload-sha256.js?v=")
		upload := strings.Index(page, "admin-upload-integrity.js?v=")
		if hash < 0 || upload <= hash {
			t.Fatal("checksum asset is missing or is loaded after its consumer")
		}
	}
}
