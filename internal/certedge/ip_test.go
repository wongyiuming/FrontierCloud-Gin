package certedge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIPCertificateBootstrapAndVerifiedServing(t *testing.T) {
	for _, host := range []string{"124.220.156.46", "2606:4700:4700::1111"} {
		t.Run(host, func(t *testing.T) {
			e := edgeFixture(t)
			e.Host = host
			if err := e.Initialize(); err != nil {
				t.Fatal(err)
			}
			bootstrap, _ := os.ReadFile(e.config)
			serverName := host
			if strings.Contains(host, ":") {
				serverName = "[" + host + "]"
			}
			if !strings.Contains(string(bootstrap), "server_name "+serverName+";") || strings.Contains(string(bootstrap), "listen 443") || strings.Contains(string(bootstrap), "business_api") {
				t.Fatal("IP bootstrap bypassed fail-closed policy")
			}
			generation := strings.Repeat("a", 32)
			publishFixture(t, e, generation, host, time.Now().Add(time.Hour))
			pair, err := tls.LoadX509KeyPair(filepath.Join(e.published, generation, "fullchain.pem"), filepath.Join(e.published, generation, "privkey.pem"))
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				if hello.ServerName != "" {
					t.Error("IP probe sent SNI", hello.ServerName)
				}
				return nil, nil
			}}
			server.StartTLS()
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err = e.readyAt(ctx, server.Listener.Addr().String()); err != nil {
				t.Fatal("IP SAN not verified", err)
			}
			e.roots = x509.NewCertPool()
			if err = e.readyAt(ctx, server.Listener.Addr().String()); err == nil {
				t.Fatal("IP bypassed CA trust")
			}
		})
	}
}

func TestIPCertificateRejectsMismatchedSAN(t *testing.T) {
	e := edgeFixture(t)
	e.Host = "124.220.156.46"
	publishFixture(t, e, strings.Repeat("b", 32), "124.220.156.47", time.Now().Add(time.Hour))
	if _, err := e.generation(); err == nil {
		t.Fatal("wrong IP SAN accepted")
	}
}

func TestIPServerNameUsesCanonicalHTTPHostAndPreservesDefaultServer(t *testing.T) {
	body := []byte("server { server_name [2606:4700:4700:0:0:0:0:1111]; }\nserver { server_name _; }\n")
	want := "server { server_name [2606:4700:4700::1111]; }\nserver { server_name _; }\n"
	got := canonicalServerNames(body, "2606:4700:4700::1111")
	if string(got) != want || string(canonicalServerNames(got, "2606:4700:4700::1111")) != want {
		t.Fatal("IP host canonicalization is not stable", string(got))
	}
	if string(canonicalServerNames(body, "business.example.test")) != string(body) {
		t.Fatal("DNS server names changed")
	}
}
