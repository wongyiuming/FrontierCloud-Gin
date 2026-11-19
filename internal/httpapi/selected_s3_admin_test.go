package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

func TestSelectedS3HTTPRequiresRealSessionAndConfiguredGate(t *testing.T) {
	router, db, dir, public := publicFixture(t, false)
	settings := public.settings
	settings.TLSEnabled, settings.AdminOrigin = true, "https://master.test"
	settings.SecretsDirectory = filepath.Join(dir, "secrets")
	key := "selected-s3-fixture-key"
	if err := os.WriteFile(filepath.Join(settings.SecretsDirectory, "admin_key"), []byte(key), 0600); err != nil {
		t.Fatal(err)
	}
	identity, err := node.Initialize(context.Background(), db.Nodes(), settings.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Database().Exec(`UPDATE node_identity SET role='Master',endpoint='https://master.test' WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	public.media.ConfigureCluster(db.Nodes(), db.Pool(), nil)
	auth, err := admin.New(settings, &selectedAdminTestCache{sessions: map[string]map[string]string{}}, db.Admin())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = RegisterAdmin(router, settings, auth, public, identity); err != nil {
		t.Fatal(err)
	}
	public.opaqueTree = &sealedtree.SQLStore{}
	login, err := auth.Login(context.Background(), key, admin.RequestInfo{IP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, suffix string, cookie, csrf bool) int {
		r := httptest.NewRequest(method, "https://master.test/api/v1/media/admin/upload/s3/"+strings.Repeat("a", 32)+suffix, strings.NewReader("{}"))
		r.Header.Set("Origin", "https://master.test")
		r.Header.Set("Content-Type", "application/json")
		if cookie {
			r.AddCookie(&http.Cookie{Name: settings.AdminCookieName(), Value: login.Cookie})
		}
		if csrf {
			r.AddCookie(&http.Cookie{Name: settings.CSRFCookieName(), Value: login.CSRF})
			r.Header.Set("X-CSRF-Token", login.CSRF)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w.Code
	}
	if got := call("GET", "", false, false); got != http.StatusUnauthorized {
		t.Fatal("unauthenticated status", got)
	}
	if got := call("POST", "/begin", true, false); got != http.StatusForbidden {
		t.Fatal("missing CSRF", got)
	}
	if got := call("POST", "/begin", true, true); got != http.StatusServiceUnavailable {
		t.Fatal("missing S3 runtime gate", got)
	}
}
