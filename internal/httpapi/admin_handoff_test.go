package httpapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type handoffCache struct {
	mu       sync.Mutex
	sessions map[string]map[string]string
}

func (c *handoffCache) ReserveAttempt(context.Context, string, int) (int64, error) { return 1, nil }
func (c *handoffCache) Delete(_ context.Context, key string) error {
	c.mu.Lock()
	delete(c.sessions, key)
	c.mu.Unlock()
	return nil
}
func (c *handoffCache) TakeTemporary(context.Context, string) (string, error) { return "", nil }
func (c *handoffCache) PutTemporary(context.Context, string, string, int) (bool, error) {
	return false, errors.New("unsupported")
}
func (c *handoffCache) SaveSession(_ context.Context, key string, value map[string]string, _ int) error {
	c.mu.Lock()
	c.sessions[key] = value
	c.mu.Unlock()
	return nil
}
func (c *handoffCache) Session(_ context.Context, key string) (map[string]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessions[key], nil
}
func (c *handoffCache) Refresh(context.Context, string, int) (bool, error)         { return true, nil }
func (c *handoffCache) RotationLock(context.Context, string, int) (bool, error)    { return false, nil }
func (c *handoffCache) RotationUnlock(context.Context, string) error               { return nil }
func (c *handoffCache) ReplaceSessions(context.Context, string, string, int) error { return nil }

func TestHandoffHTTPDirectManagementAndAuthenticatedIngress(t *testing.T) {
	router, db, dir, public, _ := cryptoLeaseFixture(t, true)
	settings := public.settings
	settings.TLSEnabled = true
	settings.AdminOrigin = cryptoLeaseOrigin
	settings.SecretsDirectory = filepath.Join(dir, "secrets")
	const key = "handoff-test-admin-key"
	if err := os.WriteFile(filepath.Join(settings.SecretsDirectory, "admin_key"), []byte(key), 0600); err != nil {
		t.Fatal(err)
	}
	identity, err := node.Initialize(context.Background(), db.Nodes(), settings.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	cache := &handoffCache{sessions: map[string]map[string]string{}}
	auth, err := admin.New(settings, cache, db.Admin())
	if err != nil {
		t.Fatal(err)
	}
	adminHTTP, err := RegisterAdmin(router, settings, auth, public, identity)
	if err != nil {
		t.Fatal(err)
	}
	makeRequest := func(method, target, body string) *http.Request {
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		r.TLS = &tls.ConnectionState{}
		r.RemoteAddr = "192.0.2.5:1234"
		return r
	}
	for _, request := range []*http.Request{
		makeRequest("GET", "https://wrong.example/api/v1/media/admin/handoff/start", ""),
		func() *http.Request {
			r := makeRequest("GET", cryptoLeaseOrigin+"/api/v1/media/admin/handoff/start", "")
			r.TLS = nil
			r.Header.Set("X-Forwarded-Proto", "https")
			return r
		}(),
		func() *http.Request {
			r := makeRequest("GET", cryptoLeaseOrigin+"/api/v1/media/admin/handoff/start", "")
			r.TLS = nil
			r.RemoteAddr = "172.18.0.3:1234" // General proxy trust must not grant handoff trust.
			r.Header.Set("X-Real-IP", "192.0.2.5")
			r.Header.Set("X-Forwarded-Proto", "https")
			return r
		}(),
	} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, request)
		if w.Code < 400 || len(w.Result().Cookies()) != 0 {
			t.Fatalf("untrusted management request admitted: %d", w.Code)
		}
	}
	start := func() (*http.Cookie, string) {
		t.Helper()
		w := httptest.NewRecorder()
		router.ServeHTTP(w, makeRequest("GET", cryptoLeaseOrigin+"/api/v1/media/admin/handoff/start", ""))
		if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") || !strings.Contains(w.Body.String(), "event.origin !== publicOrigin") || !strings.Contains(w.Header().Get("Content-Security-Policy"), "nonce-") {
			t.Fatalf("start: %d %v %s", w.Code, w.Header(), w.Body.String())
		}
		var cookie *http.Cookie
		for _, item := range w.Result().Cookies() {
			if item.Name == handoffCookieName {
				cookie = item
			}
		}
		if cookie == nil || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteStrictMode {
			t.Fatalf("bad flow cookie: %+v", cookie)
		}
		match := regexp.MustCompile(`const challenge = "([A-Za-z0-9_-]{43})";`).FindStringSubmatch(w.Body.String())
		if len(match) != 2 {
			t.Fatal("challenge missing")
		}
		return cookie, match[1]
	}
	master, err := db.Nodes().ReadIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	verified := network.AuthenticatedIngress{NodeID: master.ID, Generation: 1, PublicOrigin: cryptoLeaseOrigin, ClientIP: "192.0.2.5"}
	authorize := func(challenge string, assertion bool) (*httptest.ResponseRecorder, *network.PublicAdmission) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"challenge": challenge, "key": key})
		r := makeRequest("POST", cryptoLeaseOrigin+"/api/v1/media/admin-handoff/authorize", string(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", cryptoLeaseOrigin)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		ctx := r.Context()
		if assertion {
			ctx, err = network.WithAuthenticatedIngress(ctx, verified)
			if err != nil {
				t.Fatal(err)
			}
		}
		ctx, admission := network.WithPublicAdmission(ctx)
		r = r.WithContext(ctx)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w, admission
	}
	redeem := func(ticket string, cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"ticket": ticket})
		r := makeRequest("POST", cryptoLeaseOrigin+"/api/v1/media/admin/handoff/redeem", string(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	cookie, challenge := start()
	if w, admission := authorize(challenge, false); w.Code != http.StatusForbidden {
		admission.Abort()
		t.Fatalf("unverified ingress: %d", w.Code)
	} else {
		admission.Abort()
	}
	w, admission := authorize(challenge, true)
	if w.Code != http.StatusOK || len(w.Result().Cookies()) != 0 {
		admission.Abort()
		t.Fatalf("authorize: %d %s", w.Code, w.Body.String())
	}
	var result struct {
		Ticket string `json:"ticket"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.Ticket == "" {
		t.Fatal("missing ticket", err)
	}
	if !admission.Commit() {
		t.Fatal("admission failed")
	}
	if wrong := redeem(result.Ticket, cookie, "https://evil.test"); wrong.Code != http.StatusForbidden {
		t.Fatalf("forged origin: %d", wrong.Code)
	}
	if wrong := redeem(result.Ticket, nil, cryptoLeaseOrigin); wrong.Code != http.StatusForbidden {
		t.Fatalf("missing cookie: %d", wrong.Code)
	}
	w = redeem(result.Ticket, cookie, cryptoLeaseOrigin)
	if w.Code != http.StatusOK {
		t.Fatalf("redeem: %d %s", w.Code, w.Body.String())
	}
	var session bool
	for _, item := range w.Result().Cookies() {
		if item.Name == settings.AdminCookieName() && item.HttpOnly && item.Secure {
			session = true
		}
	}
	if !session {
		t.Fatal("management session missing")
	}
	if w = redeem(result.Ticket, cookie, cryptoLeaseOrigin); w.Code != http.StatusForbidden {
		t.Fatalf("replay accepted: %d", w.Code)
	}
	// The ticket must be consumed while the selection fence is held. If the
	// fence commit fails, its unexposed session must be removed from cache.
	cache.mu.Lock()
	beforeFault := len(cache.sessions)
	cache.mu.Unlock()
	cookie, challenge = start()
	w, admission = authorize(challenge, true)
	if w.Code != http.StatusOK || !admission.Commit() {
		t.Fatal("fault fixture authorization failed")
	}
	result.Ticket = ""
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	binding := admin.HandoffBinding{AdminOrigin: cryptoLeaseOrigin, PublicOrigin: cryptoLeaseOrigin, IngressID: master.ID, Generation: 1}
	lease := &cryptoFaultLease{err: errors.New("selection commit failed")}
	lease.onCommit = func() {
		if _, e := auth.RedeemHandoff(context.Background(), binding, result.Ticket, cookie.Value); e == nil {
			t.Error("ticket was not consumed before the selection fence committed")
		}
	}
	faultResponse := httptest.NewRecorder()
	faultContext, _ := gin.CreateTestContext(faultResponse)
	faultContext.Request = makeRequest("POST", cryptoLeaseOrigin+"/api/v1/media/admin/handoff/redeem", "")
	adminHTTP.redeemHandoffWithLease(faultContext, binding, lease, result.Ticket, cookie.Value)
	cache.mu.Lock()
	afterFault := len(cache.sessions)
	cache.mu.Unlock()
	if faultResponse.Code != http.StatusServiceUnavailable || len(faultResponse.Result().Cookies()) != 0 || lease.commits != 1 || afterFault != beforeFault {
		t.Fatalf("failed admission leaked session: status=%d cookies=%v sessions=%d/%d", faultResponse.Code, faultResponse.Result().Cookies(), afterFault, beforeFault)
	}
	// An uncommitted peer response cancels its ticket and provisional session.
	cookie, challenge = start()
	w, admission = authorize(challenge, true)
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	result.Ticket = ""
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if !admission.Abort() {
		t.Fatal("missing rollback")
	}
	if w = redeem(result.Ticket, cookie, cryptoLeaseOrigin); w.Code != http.StatusForbidden {
		t.Fatalf("aborted ticket redeemed: %d", w.Code)
	}
	// An entry selection invalidates a pending handoff before the Master-domain
	// browser receives a session, even when the public origin stays the same.
	cookie, challenge = start()
	w, admission = authorize(challenge, true)
	if w.Code != http.StatusOK || !admission.Commit() {
		t.Fatal("pending handoff failed", w.Code, w.Body.String())
	}
	result.Ticket = ""
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	repository := db.Nodes().(store.PublicRoutingRepository)
	if _, err := repository.CommitMasterPublicIngress(context.Background(), cryptoLeaseOrigin, 1, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if w = redeem(result.Ticket, cookie, cryptoLeaseOrigin); w.Code != http.StatusForbidden {
		t.Fatalf("stale entry redeemed: %d", w.Code)
	}
}
