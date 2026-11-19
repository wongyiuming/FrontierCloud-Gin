package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestNodeMediaPreflightUsesAuthenticatedObservation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const origin = "https://entry.example"
	observed := func(context.Context) (store.PublicIngress, store.Relationship, error) {
		return store.PublicIngress{PublicOrigin: origin}, store.Relationship{}, nil
	}
	request := func(target, requestOrigin, method, headers string, observation func(context.Context) (store.PublicIngress, store.Relationship, error)) *httptest.ResponseRecorder {
		router := gin.New()
		router.OPTIONS("/internal/v1/media/:object", func(c *gin.Context) { nodeMediaPreflight(c, observation) })
		r := httptest.NewRequest(http.MethodOptions, target, nil)
		r.Header.Set("Origin", requestOrigin)
		r.Header.Set("Access-Control-Request-Method", method)
		r.Header.Set("Access-Control-Request-Headers", headers)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	target := "https://owner.example/internal/v1/media/" + strings.Repeat("a", 64)
	w := request(target, origin, "GET", "range, x-media-capability", observed)
	if w.Code != http.StatusNoContent || w.Header().Get("Access-Control-Allow-Origin") != origin || !strings.Contains(w.Header().Get("Access-Control-Allow-Headers"), "X-Media-Capability") {
		t.Fatalf("valid preflight rejected: %d %v", w.Code, w.Header())
	}
	for _, tc := range []struct{ target, origin, method, headers string }{
		{target, "https://other.example", "GET", "x-media-capability"},
		{target + "?token=secret", origin, "GET", "x-media-capability"},
		{target, origin, "POST", "x-media-capability"},
		{target, origin, "GET", "x-media-capability, authorization"},
		{target, origin, "GET", "range"},
		{"https://owner.example/internal/v1/media/not-an-object", origin, "GET", "x-media-capability"},
	} {
		w = request(tc.target, tc.origin, tc.method, tc.headers, observed)
		if w.Code != http.StatusForbidden || w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("invalid preflight allowed: %+v: %d %v", tc, w.Code, w.Header())
		}
	}
	missing := func(context.Context) (store.PublicIngress, store.Relationship, error) {
		return store.PublicIngress{}, store.Relationship{}, errors.New("observation absent or expired")
	}
	w = request(target, origin, "GET", "x-media-capability", missing)
	if w.Code != http.StatusForbidden || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("missing observation allowed: %d %v", w.Code, w.Header())
	}
}
