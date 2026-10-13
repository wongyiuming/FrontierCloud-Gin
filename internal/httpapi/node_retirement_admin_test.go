package httpapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/noderetirement"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
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
	calls      atomic.Int32
	applyCalls atomic.Int32
	entered    chan struct{}
	release    chan struct{}
	failure    bool
}

func (f *retirementAdminFixture) Apply(ctx context.Context, member, relationship string, audit store.NodeAudit) (store.RetirementFence, error) {
	if _, bounded := ctx.Deadline(); bounded {
		return store.RetirementFence{}, errors.New("retirement apply inherited a fixed server deadline")
	}
	f.applyCalls.Add(1)
	if audit.Actor == "" {
		return store.RetirementFence{}, errors.New("missing actor")
	}
	result := store.RetirementFence{MemberID: member, RelationshipID: relationship, FencedAt: 1, CompletedAt: 1}
	if f.failure {
		result.CompletedAt = 0
		return result, errors.New("private internal credential must never reach HTTP response")
	}
	return result, nil
}

func (f *retirementAdminFixture) Check(ctx context.Context, member, relationship string) (noderetirement.Report, error) {
	if _, bounded := ctx.Deadline(); bounded {
		return noderetirement.Report{}, errors.New("retirement check inherited a fixed server deadline")
	}
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
	RegisterAdminMigrations(router, a, db.Pool().(store.MigrationAdminRepository))
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
	applyPath := strings.TrimSuffix(path, "check") + "apply"
	applyBody := strings.TrimSuffix(body, "}") + `,"confirm_member_id":"` + strings.Repeat("2", 32) + `"}`
	if w := perform("POST", applyPath, applyBody, false); w.Code != 401 {
		t.Fatal("anonymous apply", w.Code)
	}
	if w := perform("GET", "/nodes/migrations", "", false); w.Code != 401 {
		t.Fatal("anonymous migration listing", w.Code)
	}
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
	if w := perform("POST", applyPath, applyBody, false); w.Code != 403 {
		t.Fatal("apply missing CSRF", w.Code)
	}
	for _, bad := range []string{body, applyBody + ` {}`, strings.TrimSuffix(applyBody, "}") + `,"force":true}`, strings.Replace(applyBody, `"confirm_member_id":"2`, `"confirm_member_id":"3`, 1)} {
		if w := perform("POST", applyPath, bad, true); w.Code != 422 {
			t.Fatal("invalid apply confirmation", w.Code, w.Body.String())
		}
	}
	if checker.applyCalls.Load() != 0 {
		t.Fatal("invalid request invoked apply")
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
	if _, e = db.Nodes().PromoteIdentity(context.Background(), store.NodePromotion{Role: "Master", Endpoint: "https://retirement.test", Allocation: store.GiB, PhysicalFree: 10 * store.GiB}, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	taskID := strings.Repeat("f", 32)
	source := strings.Repeat("3", 32)
	target := strings.Repeat("4", 32)
	if _, e = db.Database().Exec("INSERT INTO migration_tasks(task_id,master_id,source_id,target_id,source_relationship,target_relationship,plan_sha256,plan,state,revision,object_count,total_bytes,created_at,updated_at) VALUES (?,?,?,?,?,?,?,'{}','queued',1,0,0,1,1)", taskID, identity.ID, source, target, strings.Repeat("5", 32), strings.Repeat("6", 32), strings.Repeat("7", 64)); e != nil {
		t.Fatal(e)
	}
	migrationPath := "/nodes/migrations/" + taskID
	if w := perform("GET", "/nodes/migrations", "", false); w.Code != 200 {
		t.Fatal("migration task listing", w.Code, w.Body.String())
	}
	if w := perform("GET", migrationPath, "", false); w.Code != 200 || !strings.Contains(w.Body.String(), `"retirement_ready":false`) {
		t.Fatal("migration status", w.Code, w.Body.String())
	}
	payload, _ := json.Marshal(map[string]any{"action": "pause", "revision": 1, "confirm_source_id": source, "confirm_target_id": target})
	if w := perform("POST", migrationPath+"/control", string(payload), false); w.Code != 403 {
		t.Fatal("migration control missing CSRF", w.Code)
	}
	if w := perform("POST", migrationPath+"/control", string(payload), true); w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"paused"`) {
		t.Fatal("migration pause", w.Code, w.Body.String())
	}
	if w := perform("POST", migrationPath+"/control", string(payload), true); w.Code != 409 {
		t.Fatal("stale migration revision", w.Code)
	}
	wrong, _ := json.Marshal(map[string]any{"action": "cancel", "revision": 2, "confirm_source_id": target, "confirm_target_id": source})
	if w := perform("POST", migrationPath+"/control", string(wrong), true); w.Code != 409 {
		t.Fatal("wrong node confirmation", w.Code)
	}
	bad := strings.TrimSuffix(string(payload), "}") + `,"force":true}`
	if w := perform("POST", migrationPath+"/control", bad, true); w.Code != 422 {
		t.Fatal("unknown migration field", w.Code)
	}
	checker.failure = true
	if w := perform("POST", applyPath, applyBody, true); w.Code != 409 || strings.Contains(w.Body.String(), "credential") || !strings.Contains(w.Body.String(), `"retirement_incomplete"`) {
		t.Fatal("unsafe incomplete apply", w.Code, w.Body.String())
	}
	if w := perform("POST", path, body, true); w.Code != 409 || strings.Contains(w.Body.String(), "credential") || !strings.Contains(w.Body.String(), `"observation_complete":false`) {
		t.Fatal("unsafe incomplete error", w.Code, w.Body.String())
	}
	checker.failure = false
	checker.entered = make(chan struct{})
	checker.release = make(chan struct{})
	finished := make(chan *httptest.ResponseRecorder, 1)
	go func() { finished <- perform("POST", path, body, true) }()
	<-checker.entered
	if w := perform("POST", applyPath, applyBody, true); w.Code != 429 {
		t.Fatal("apply overlapped independent scan", w.Code)
	}
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
	if w := perform("POST", applyPath, applyBody, true); w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("confirmed apply failed", w.Code, w.Body.String())
	}
}
