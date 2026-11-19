package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/httpapi"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/publicproxy"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/security"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	storeSQLite "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

func TestMasterIngressSignedIPPolicyPersistsAcrossGeneration(t *testing.T) {
	const clientIP, edgeIP, forgedIP = "192.0.2.10", "192.0.2.77", "198.51.100.99"
	ctx := context.Background()
	root := t.TempDir()
	settings, err := config.LoadFrom(func(key string) string {
		if key == "DATA_ROOT" {
			return root
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	db, err := storeSQLite.Open(filepath.Join(root, "policy.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	policies, err := security.New(settings, db.Security())
	if err != nil {
		t.Fatal(err)
	}
	defer policies.Close()
	resolver, err := network.New([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	ready := func(context.Context) error { return nil }
	router := httpapi.NewWithResolver(ready, ready, resolver, httpapi.SecurityMiddleware(policies, resolver))
	router.GET("/api/v1/media", func(c *gin.Context) { c.String(http.StatusOK, resolver.Resolve(c.Request).IP) })
	control := &edgeFixture{nonces: map[string]bool{}}
	control.generation.Store(9)
	edge := masterIngressEdge(router, control, resolver)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Model the headers Nginx sets after authentic TLS termination.
		r.TLS, r.RemoteAddr = nil, "10.1.2.3:1234"
		r.Header.Set("X-Real-IP", edgeIP)
		r.Header.Set("X-Forwarded-Proto", "https")
		edge.ServeHTTP(w, r)
	}))
	defer upstream.Close()
	control.master = upstream.URL
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	makeProxy := func(generation int64) http.Handler {
		t.Helper()
		proxy, err := publicproxy.New(publicproxy.Config{
			MasterOrigin: upstream.URL, PublicOrigin: "https://entry.example", RootCAs: roots, MasterEdge: true,
			Peer: &publicproxy.PeerConfig{NodeID: edgePeer, Generation: generation, Signer: edgeSigner{}},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(proxy.CloseIdleConnections)
		return proxy
	}
	request := func(handler http.Handler, ip string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/media", nil)
		r.Host, r.TLS, r.RemoteAddr = "entry.example", &tls.ConnectionState{}, ip+":1234"
		r.Header.Set("X-Real-IP", forgedIP)
		r.Header.Set("X-Forwarded-For", forgedIP)
		w := edgeRecorder{httptest.NewRecorder()}
		handler.ServeHTTP(w, r)
		return w.ResponseRecorder
	}
	policy := func(ip, action string) {
		t.Helper()
		if _, _, err := policies.Policy(ctx, ip, action, "ingress fixture", store.AdminAudit{}); err != nil {
			t.Fatal(err)
		}
	}
	check := func(proxy http.Handler, ip string, status int, body string) {
		t.Helper()
		w := request(proxy, ip)
		if w.Code != status || !strings.Contains(w.Body.String(), body) {
			t.Fatalf("IP %s: got %d %q, want %d with %q", ip, w.Code, w.Body.String(), status, body)
		}
	}
	first := makeProxy(9)
	policy(edgeIP, "permanent_ban")
	policy(forgedIP, "permanent_ban")
	check(first, clientIP, http.StatusOK, clientIP)
	policy(clientIP, "permanent_ban")
	check(first, clientIP, http.StatusForbidden, "Request blocked by API security policy")
	check(first, "192.0.2.11", http.StatusOK, "192.0.2.11")
	policy(clientIP, "whitelist")
	check(first, clientIP, http.StatusOK, clientIP)
	control.generation.Store(10)
	check(first, clientIP, http.StatusForbidden, "")
	second := makeProxy(10)
	check(second, clientIP, http.StatusOK, clientIP)
	check(second, forgedIP, http.StatusForbidden, "Request blocked by API security policy")
	policy(clientIP, "whitelist_remove")
	policy(clientIP, "permanent_ban")
	check(second, clientIP, http.StatusForbidden, "Request blocked by API security policy")
}
