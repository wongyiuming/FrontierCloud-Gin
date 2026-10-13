package release

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestProductionRegistryClientReturnsValidatedBlobRedirectWithoutCredentialForwarding(t *testing.T) {
	r := NewRegistryClient()
	defer r.Close()
	var hosts []string
	r.Client.Transport = registryTransport(func(req *http.Request) (*http.Response, error) {
		hosts = append(hosts, req.URL.Host)
		if req.URL.Host == "ghcr.io" {
			if req.Header.Get("Authorization") != "Bearer fixture-token" {
				t.Fatal("initial scoped registry token missing")
			}
			response := registryReply(307, "", false)
			response.Header.Set("Location", "https://pkg-containers.githubusercontent.com/config")
			return response, nil
		}
		if req.URL.Host != "pkg-containers.githubusercontent.com" || req.Header.Get("Authorization") != "" {
			t.Fatal("untrusted redirect or forwarded registry credential")
		}
		return registryReply(200, `{"verified":"actual-config-bytes"}`, false), nil
	})
	token := "fixture-token"
	body, _, e := r.imageRead(context.Background(), "/v2/wongyiuming/frontiercloud-gin-web", "/blobs/sha256:"+strings.Repeat("a", 64), &token)
	if e != nil || string(body) != `{"verified":"actual-config-bytes"}` || len(hosts) != 2 {
		t.Fatal("production redirect policy prevented allowed blob verification", e, hosts)
	}
}

func TestProductionRegistryClientDoesNotFollowForeignBlobRedirect(t *testing.T) {
	r := NewRegistryClient()
	defer r.Close()
	requests := 0
	r.Client.Transport = registryTransport(func(*http.Request) (*http.Response, error) {
		requests++
		response := registryReply(307, "", false)
		response.Header.Set("Location", "https://foreign.invalid/config")
		return response, nil
	})
	token := "fixture-token"
	if _, _, e := r.imageRead(context.Background(), "/v2/wongyiuming/frontiercloud-gin-web", "/blobs/sha256:"+strings.Repeat("a", 64), &token); !errors.Is(e, ErrImageIntegrity) || requests != 1 {
		t.Fatal("foreign redirect was followed", e, requests)
	}
}
