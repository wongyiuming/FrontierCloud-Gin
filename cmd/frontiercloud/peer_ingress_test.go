package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
)

func TestPeerIngressIsDormantWithoutAuthenticatedObservation(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	p := newPeerIngressHTTP(next, nil, config.Config{})
	defer p.Close()
	for _, path := range []string{"/api/v1/media", "/api/v1/media/catalog/media", "/media-crypto-sw.js", "/static/js/player.js"} {
		w := httptest.NewRecorder()
		p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusServiceUnavailable || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("unconfigured public route %s: %d %v", path, w.Code, w.Header())
		}
	}
	for _, path := range []string{"/internal/v1/heartbeat", "/internal/v1/media/object", "/api/v1/media/admin", "/static/js/admin.js"} {
		w := httptest.NewRecorder()
		p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusNoContent {
			t.Fatalf("non-public route intercepted %s: %d", path, w.Code)
		}
	}
	for i := 0; i < cap(p.lookups); i++ {
		p.lookups <- struct{}{}
	}
	if _, err := p.prepare(context.Background()); err == nil {
		t.Fatal("unbounded ingress lookups")
	}
}

func TestPeerCandidateProbeRequiresTLSAndFixedPath(t *testing.T) {
	var verified atomic.Int32
	peer := newPeerIngressHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("candidate probe bypassed peer wrapper") }), nil, config.Config{})
	peer.candidateVerify = func(_ context.Context, host string, h http.Header, body []byte) (node.Envelope, error) {
		verified.Add(1)
		if host != "candidate.test" || h.Get("X-Node-Signature") != "fixture" || string(body) != "{}" {
			return node.Envelope{}, errors.New("rejected")
		}
		return node.Envelope{Payload: map[string]any{"challenge": "fixture"}, Signature: "fixture"}, nil
	}
	call := func(method, target, body string, secure, signed bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://candidate.test"+target, strings.NewReader(body))
		if !secure {
			r.TLS = nil
			r.Header.Set("X-Forwarded-Proto", "https")
		}
		if signed {
			r.Header.Set("X-Node-Signature", "fixture")
		}
		w := httptest.NewRecorder()
		peer.ServeHTTP(w, r)
		return w
	}
	if w := call(http.MethodPost, node.IngressCandidatePublicPath, "{}", true, true); w.Code != http.StatusOK {
		t.Fatal("candidate listener probe", w.Code)
	}
	for _, tc := range []struct {
		method, path, body string
		secure, signed     bool
	}{
		{http.MethodPost, node.IngressCandidatePublicPath, "{}", false, true},
		{http.MethodGet, node.IngressCandidatePublicPath, "{}", true, true},
		{http.MethodPost, node.IngressCandidatePublicPath + "?x=1", "{}", true, true},
		{http.MethodPost, node.IngressCandidatePublicPath, strings.Repeat("x", 1025), true, true},
		{http.MethodPost, node.IngressCandidatePublicPath, "{}", true, false},
	} {
		if w := call(tc.method, tc.path, tc.body, tc.secure, tc.signed); w.Code == http.StatusOK {
			t.Fatal("unsafe public probe accepted", tc.method, tc.path)
		}
	}
	if verified.Load() != 2 {
		t.Fatal("unexpected verification count", verified.Load())
	}
}
