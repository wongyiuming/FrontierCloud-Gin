package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
)

func TestPeerIngressNavigationRequiresActiveSelection(t *testing.T) {
	for _, path := range []string{"/", "/api/v1/media/refresh"} {
		t.Run(path, func(t *testing.T) {
			fallback := false
			h := newPeerIngressHTTP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fallback = true
				w.WriteHeader(http.StatusNoContent)
			}), nil, config.Config{})
			defer h.Close()
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
			if fallback || w.Code != http.StatusServiceUnavailable {
				t.Fatalf("navigation bypassed selection: fallback=%t status=%d", fallback, w.Code)
			}
		})
	}
}
