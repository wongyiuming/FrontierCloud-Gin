package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
)

// The actual runtime constructor must not expose a partially installed
// encrypted-tree data plane while its startup prerequisite is unavailable.
// This test deliberately does not claim that activation itself is complete.
func TestRuntimeStartupLeavesOpaqueIngressUnavailableWithoutPrerequisite(t *testing.T) {
	for _, mode := range []string{config.DeploymentBusiness, config.DeploymentStorage} {
		t.Run(mode, func(t *testing.T) {
			router, control := nativeHTTPFixtureModeAndControl(t, mode)
			if control.IngressSelectionConfigured() || control.IngressSelectionAvailable(context.Background()) {
				t.Fatal("runtime enabled ingress selection without its prerequisite")
			}
			blocked := map[string]bool{
				"/api/v1/media/master-local/:resource":                false,
				"/api/v1/media/master-local-lyric/:resource":          false,
				"/api/v1/media/opaque-local-follower-relay/:resource": false,
				"/api/v1/media/opaque-follower-relay/:resource":       false,
				"/internal/v1/opaque-media/:object":                   false,
			}
			for _, route := range router.Routes() {
				if _, ok := blocked[route.Path]; ok {
					t.Fatalf("runtime exposed a partially installed opaque route: %s %s", route.Method, route.Path)
				}
			}
			for i, endpoint := range []string{"/api/v1/media/master-local/", "/api/v1/media/master-local-lyric/", "/api/v1/media/opaque-local-follower-relay/", "/api/v1/media/opaque-follower-relay/", "/internal/v1/opaque-media/"} {
				response := httptest.NewRecorder()
				request := httptest.NewRequest(http.MethodGet, endpoint+strings.Repeat("a", 64), nil)
				request.RemoteAddr = fmt.Sprintf("192.0.2.%d:4321", i+1)
				router.ServeHTTP(response, request)
				if response.Code != http.StatusNotFound {
					t.Fatalf("unavailable route %q returned %d", endpoint, response.Code)
				}
			}
		})
	}
}
