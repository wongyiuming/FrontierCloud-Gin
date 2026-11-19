package publicproxy

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
)

func TestHandoffProxyStripsCookiesAndOtherAdminRoutes(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/media/admin-handoff/authorize" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Errorf("unexpected handoff forwarding: %s %v", r.URL.Path, r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		http.SetCookie(w, &http.Cookie{Name: "admin", Value: "secret", Path: "/", Secure: true})
		_, _ = io.WriteString(w, `{"ticket":"short-lived"}`)
	}))
	defer server.Close()
	h := testProxy(t, server)
	r := incoming(http.MethodPost, "/api/v1/media/admin-handoff/authorize", strings.NewReader(`{"challenge":"test","key":"test"}`))
	r.Header.Set("Cookie", "admin=secret; frontiercloud_browser_crypto=private")
	r.Header.Set("Authorization", "Bearer private")
	w := newRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("handoff response: %d %v", w.Code, w.Header())
	}
	for _, path := range []string{"/api/v1/media/admin/elevate", "/api/v1/media/admin/handoff/start", "/api/v1/media/admin/handoff/redeem"} {
		if _, ok := match(incoming(http.MethodPost, path, nil)); ok {
			t.Fatalf("admin route exposed: %s", path)
		}
	}
}

func TestHandoffVerifierDiscardsTicketOnLeaseFailure(t *testing.T) {
	const master = "https://master.example"
	v, _, current := fixtureVerifier(t, master)
	current.commitErr = errors.New("lease failed")
	var cancelled atomic.Int32
	handler := v.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		present, registered := network.RegisterPublicAdmissionAbort(r.Context(), func() { cancelled.Add(1) })
		if !present || !registered {
			t.Error("handoff cancellation unavailable")
		}
		_, _ = io.WriteString(w, "ticket-secret")
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, signedFixtureFor(t, master, http.MethodPost, "/api/v1/media/admin-handoff/authorize"))
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "ticket-secret") || cancelled.Load() != 1 {
		t.Fatalf("uncommitted ticket exposed: %d %q, cancelled %d", w.Code, w.Body.String(), cancelled.Load())
	}
}
