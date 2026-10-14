package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHostReleaseCredentialsReachAuthenticatedRequest(t *testing.T) {
	for _, token := range []string{"", "host-only-test-token"} {
		t.Run(token, func(t *testing.T) {
			t.Setenv("GITHUB_API_TOKEN", token)
			seen := make(chan string, 1)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Header.Get("Authorization")
				w.WriteHeader(http.StatusForbidden)
			}))
			defer server.Close()
			transport := server.Client().Transport.(*http.Transport).Clone()
			transport.TLSClientConfig.ServerName = server.Listener.Addr().(*net.TCPAddr).IP.String()
			transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}
			previous := http.DefaultTransport
			http.DefaultTransport = transport
			t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
			verifier, err := hostReleaseVerifier()
			if err != nil {
				t.Fatal(err)
			}
			_, _ = verifier.Status(context.Background(), true)
			expected := ""
			if token != "" {
				expected = "Bearer " + token
			}
			select {
			case actual := <-seen:
				if actual != expected {
					t.Fatal("host API credential was not correctly applied")
				}
			default:
				t.Fatal("release verification did not reach the isolated HTTP server")
			}
		})
	}
}

func TestHostReleaseCredentialsRejectInvalidValuesWithoutEcho(t *testing.T) {
	for _, token := range []string{"private\ncredential", strings.Repeat("x", 4097)} {
		t.Setenv("GITHUB_API_TOKEN", token)
		_, err := hostReleaseVerifier()
		if err == nil || strings.Contains(err.Error(), token) {
			t.Fatal("invalid host credential must fail without echoing its contents")
		}
	}
}
