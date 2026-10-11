package certmanager

import (
	"context"
	"net/http"
	"net/http/httptest"
	syncatomic "sync/atomic"
	"testing"
	"time"
)

func TestIngressWaitsForControllerRouteAndNeverFollowsRedirect(t *testing.T) {
	var requests syncatomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "business.fixture.test" || r.URL.Path != "/.well-known/acme-challenge/frontiercloud-readiness" {
			t.Error("ingress probe lost domain or restricted route")
		}
		if requests.Add(1) > 1 {
			w.Header().Set("X-FrontierCloud-ACME", "ready")
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := awaitIngress(ctx, server.URL+"/.well-known/acme-challenge/frontiercloud-readiness", "business.fixture.test"); err != nil || requests.Load() < 2 {
		t.Fatal("accepted a missing controller route", err)
	}
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, server.URL, http.StatusFound) }))
	defer redirect.Close()
	before := requests.Load()
	short, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stop()
	if awaitIngress(short, redirect.URL, "business.fixture.test") == nil || requests.Load() != before {
		t.Fatal("bootstrap accepted or followed a redirect")
	}
}
