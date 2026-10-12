package httpapi

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/noderetirement"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

type retirementAdminFixture struct {
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
	failure bool
}

func (f *retirementAdminFixture) Check(ctx context.Context, member, relationship string) (noderetirement.Report, error) {
	f.calls.Add(1)
	report := noderetirement.Report{MemberID: member, PreflightOnly: true, ObservationComplete: true}
	if f.entered != nil {
		close(f.entered)
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		case <-f.release:
		}
	}
	if f.failure {
		return report, errors.New("private internal credential must never reach HTTP response")
	}
	return report, nil
}
func TestAdminRetirementRedisAuthenticationCSRFBoundsAndBusy(t *testing.T) {
	redisURL := os.Getenv("FRONTIERCLOUD_TEST_REDIS_URL")
	if redisURL == "" {
		t.Skip("requires isolated Redis")
	}
	opts, e := redis.ParseURL(redisURL)
	if e != nil {
		t.Fatal(e)
	}
	client := redis.NewClient(opts)
	defer client.Close()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	router, db, dir, public, _ := clusterFixture(t, "https://retirement.test", transport, true)
	cfg := public.settings
	cfg.TLSEnabled = true
	cfg.SecretsDirectory = filepath.Join(dir, "secrets")
	key := "retirement-admin-test-key"
	if e = os.WriteFile(filepath.Join(cfg.SecretsDirectory, "admin_key"), []byte(key), 0600); e != nil {
		t.Fatal(e)
	}
	identity, e := node.Initialize(context.Background(), db.Nodes(), cfg.SecretsDirectory)
	if e != nil {
		t.Fatal(e)
	}
	auth, e := admin.New(cfg, admin.NewRedisCache(client), db.Admin())
	if e != nil {
		t.Fatal(e)
	}
	a, e := RegisterAdmin(router, cfg, auth, public, identity)
	if e != nil {
		t.Fatal(e)
	}
	checker := &retirementAdminFixture{}
	RegisterAdminRetirement(router, a, checker)
	cookies := map[string]*http.Cookie{}
	perform := func(method, path, body string, csrf bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "https://retirement.test/api/v1/media/admin"+path, strings.NewReader(body))
		req.TLS = &tls.ConnectionState{}
		req.Header.Set("Content-Type", "application/json")
		if path == "/elevate" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		if csrf && cookies[cfg.CSRFCookieName()] != nil {
			req.Header.Set("X-CSRF-Token", cookies[cfg.CSRFCookieName()].Value)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	path := "/nodes/" + strings.Repeat("1", 32) + "/retire/check"
	body := `{"member_id":"` + strings.Repeat("2", 32) + `"}`
	if w := perform("POST", path, body, false); w.Code != 401 {
		t.Fatal("anonymous check", w.Code)
	}
	login := perform("POST", "/elevate", "token="+url.QueryEscape(key), false)
	if login.Code != 200 {
		t.Fatal("login", login.Code)
	}
	for _, cookie := range login.Result().Cookies() {
		cookies[cookie.Name] = cookie
	}
	if w := perform("POST", path, body, false); w.Code != 403 {
		t.Fatal("missing CSRF", w.Code)
	}
	for _, bad := range []string{`{"member_id":"../../secrets"}`, body + ` {}`, strings.TrimSuffix(body, "}") + `,"force":true}`} {
		if w := perform("POST", path, bad, true); w.Code != 422 {
			t.Fatal("invalid input", w.Code, w.Body.String())
		}
	}
	if checker.calls.Load() != 0 {
		t.Fatal("invalid request invoked observation")
	}
	if w := perform("POST", path, body, true); w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), `"preflight_only":true`) {
		t.Fatal("check report", w.Code, w.Body.String())
	}
	checker.failure = true
	if w := perform("POST", path, body, true); w.Code != 409 || strings.Contains(w.Body.String(), "credential") || !strings.Contains(w.Body.String(), `"observation_complete":false`) {
		t.Fatal("unsafe incomplete error", w.Code, w.Body.String())
	}
	checker.failure = false
	checker.entered = make(chan struct{})
	checker.release = make(chan struct{})
	finished := make(chan *httptest.ResponseRecorder, 1)
	go func() { finished <- perform("POST", path, body, true) }()
	<-checker.entered
	if w := perform("POST", path, body, true); w.Code != 429 {
		t.Fatal("parallel unbounded scan", w.Code, w.Body.String())
	}
	close(checker.release)
	if w := <-finished; w.Code != 200 {
		t.Fatal("first scan", w.Code)
	}
	checker.entered = nil
	checker.release = nil
	if w := perform("POST", path, body, true); w.Code != 200 {
		t.Fatal("slot leaked", w.Code)
	}
	if w := perform("POST", strings.TrimSuffix(path, "check")+"apply", body, true); w.Code != 404 {
		t.Fatal("unexpected retire apply", w.Code)
	}
}
