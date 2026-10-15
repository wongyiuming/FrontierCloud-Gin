package release

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestImageReadsPreserveCancellationAcrossRegistryTokenAndRedirect(t *testing.T) {
	for _, phase := range []string{"registry", "token", "authenticated", "redirect"} {
		for _, body := range []bool{false, true} {
			for _, kind := range []string{"cancel", "context-timeout", "client-timeout"} {
				t.Run(fmt.Sprintf("%s/body=%t/%s", phase, body, kind), func(t *testing.T) {
					started := make(chan struct{})
					server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						if body {
							fmt.Fprint(w, "{")
							w.(http.Flusher).Flush()
						}
						close(started)
						<-req.Context().Done()
					}))
					defer server.Close()
					endpoint, _ := url.Parse(server.URL)
					r := NewRegistryClient()
					defer r.Close()
					transport := server.Client().Transport
					r.Client.Transport = registryTransport(func(req *http.Request) (*http.Response, error) {
						if phase == "token" || phase == "authenticated" {
							if strings.HasPrefix(req.URL.Path, "/token") {
								if phase == "authenticated" {
									return registryReply(200, `{"token":"fixture-token"}`, false), nil
								}
							} else if req.Header.Get("Authorization") == "" {
								return registryReply(401, `{}`, false), nil
							}
						}
						if phase == "redirect" && req.URL.Host == "ghcr.io" {
							response := registryReply(307, "", false)
							response.Header.Set("Location", "https://pkg-containers.githubusercontent.com/fixture?token=must-not-escape")
							return response, nil
						}
						local := req.Clone(req.Context())
						local.URL.Scheme, local.URL.Host = endpoint.Scheme, endpoint.Host
						return transport.RoundTrip(local)
					})
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					want := context.DeadlineExceeded
					if kind == "cancel" {
						want = context.Canceled
						go func() { <-started; cancel() }()
					} else if kind == "client-timeout" {
						r.Client.Timeout = 100 * time.Millisecond
					} else {
						ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
						defer cancel()
					}
					suffix := "/manifests/" + strings.Repeat("a", 40)
					if phase == "redirect" {
						suffix = "/blobs/sha256:" + strings.Repeat("a", 64)
					}
					token := ""
					_, _, err := r.imageRead(ctx, "/v2/wongyiuming/frontiercloud-gin-web", suffix, &token)
					if !errors.Is(err, want) || strings.Contains(err.Error(), "must-not-escape") {
						t.Fatal("registry cause lost or private URL exposed", err)
					}
				})
			}
		}
	}
}
