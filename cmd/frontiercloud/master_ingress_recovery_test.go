package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
)

func TestIngressRecoveryWrapperRestrictsOriginAndRoutes(t *testing.T) {
	recovery := &ingressRecoveryRuntime{}
	recovery.active.Store(true)
	edge, err := network.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	h := wrapRecoveryControl(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++; w.WriteHeader(http.StatusNoContent) }), recovery, "https://admin.test", edge)
	call := func(method, target, origin string, secure bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, nil)
		if secure {
			r.TLS = &tls.ConnectionState{}
		} else {
			r.TLS = nil
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, x := range []struct {
		method, target, origin string
		secure                 bool
	}{
		{"GET", "https://admin.test/api/v1/media/catalog/media", "", true},
		{"GET", "https://other.test/api/v1/media/admin/ingress-recovery", "", true},
		{"GET", "http://admin.test/api/v1/media/admin/ingress-recovery", "", false},
		{"GET", "https://admin.test/api/v1/media/admin/ingress-recovery?x=1", "", true},
		{"POST", "https://admin.test/api/v1/media/admin/ingress-recovery/restore", "https://other.test", true},
		{"POST", "https://admin.test/api/v1/media/admin/ingress-recovery/restore", "", true},
	} {
		if w := call(x.method, x.target, x.origin, x.secure); w.Code == http.StatusNoContent {
			t.Fatalf("recovery allowed %s %s", x.method, x.target)
		}
	}
	if calls != 0 {
		t.Fatal("blocked request reached handler", calls)
	}
	if w := call("GET", "https://admin.test/api/v1/media/admin/ingress-recovery", "", true); w.Code != http.StatusNoContent {
		t.Fatal("recovery page blocked", w.Code)
	}
	if w := call("POST", "https://admin.test/api/v1/media/admin/ingress-recovery/restore", "https://admin.test", true); w.Code != http.StatusNoContent {
		t.Fatal("same-origin recovery blocked", w.Code)
	}
	recovery.active.Store(false)
	if w := call("GET", "https://other.test/api/v1/media/catalog/media", "", true); w.Code != http.StatusNoContent {
		t.Fatal("normal serving not published", w.Code)
	}
}
