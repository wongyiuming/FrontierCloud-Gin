package httpapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/observation"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/publicproxy"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestRealObservationThroughSignedTLSPublicIngress(t *testing.T) {
	raw := os.Getenv("FRONTIERCLOUD_TEST_REDIS_URL")
	if raw == "" {
		t.Skip("disposable Redis not configured")
	}
	opts, err := redis.ParseURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	cache := redis.NewClient(opts)
	t.Cleanup(func() { cache.Close() })
	ctx := context.Background()
	for _, ip := range []string{"192.0.2.178", "192.0.2.179", "192.0.2.180", "192.0.2.181"} {
		key := "webrtc:observation:" + ip
		if err := cache.Del(ctx, key).Err(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cache.Del(context.Background(), key) })
	}
	router, db, _, _ := publicFixture(t, false)
	resolver, err := network.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	RegisterObservations(router, &Admin{}, observation.New(db.Observations(), cache, 30), resolver)
	ingress := store.PublicIngress{NodeID: strings.Repeat("a", 32), PublicOrigin: "https://entry.test", Generation: 9}
	current := &relayFixtureCurrent{value: ingress}
	var wrapped atomic.Value
	serve := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { wrapped.Load().(http.Handler).ServeHTTP(w, r) })
	origin := os.Getenv("FRONTIERCLOUD_TEST_NGINX_ORIGIN")
	nginxMode := origin != ""
	roots := x509.NewCertPool()
	if nginxMode {
		pem, err := os.ReadFile(os.Getenv("FRONTIERCLOUD_TEST_NGINX_CA"))
		if err != nil || !roots.AppendCertsFromPEM(pem) {
			t.Fatal("fixture nginx CA unavailable", err)
		}
		listener, err := net.Listen("tcp", ":18080")
		if err != nil {
			t.Fatal(err)
		}
		server := &http.Server{Handler: http.StripPrefix(publicproxy.EdgePrefix, serve)}
		go server.Serve(listener)
		defer server.Close()
	} else {
		upstream := httptest.NewTLSServer(serve)
		defer upstream.Close()
		origin = upstream.URL
		roots.AddCert(upstream.Certificate())
	}
	var edgeResolver *network.Resolver
	if nginxMode {
		// Fixture traffic is confined to its disposable internal Docker network.
		edgeResolver, err = network.New([]string{"0.0.0.0/0", "::/0"})
		if err != nil {
			t.Fatal(err)
		}
	}
	verifier, err := publicproxy.NewVerifier(publicproxy.VerifierConfig{MasterOrigin: origin, Authenticator: &relayFixtureAuth{peer: ingress.NodeID, nonces: map[string]bool{}}, Current: current, EdgeResolver: edgeResolver})
	if err != nil {
		t.Fatal(err)
	}
	wrapped.Store(verifier.Wrap(router))
	proxy, err := publicproxy.New(publicproxy.Config{MasterOrigin: origin, PublicOrigin: ingress.PublicOrigin, RootCAs: roots, MasterEdge: nginxMode, Peer: &publicproxy.PeerConfig{NodeID: ingress.NodeID, Generation: ingress.Generation, Signer: relayFixtureSigner{}}})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.CloseIdleConnections()
	request := func(ip, body string, unknown bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/media/network-observation", strings.NewReader(body))
		r.Host, r.RemoteAddr, r.TLS = "entry.test", ip+":1234", &tls.ConnectionState{}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", ingress.PublicOrigin)
		r.Header.Set("X-Forwarded-For", "198.51.100.99")
		if unknown {
			r.ContentLength = -1
		}
		w := httptest.NewRecorder()
		proxy.ServeHTTP(karaokeIngressRecorder{w}, r)
		return w
	}
	body := `{"addresses":["192.0.2.178"]}`
	if w := request("192.0.2.178", body, false); w.Code != http.StatusOK {
		t.Fatalf("record: %d %s", w.Code, w.Body.String())
	}
	if w := request("192.0.2.178", body, false); w.Code != http.StatusTooManyRequests {
		t.Fatalf("redis rate limit: %d", w.Code)
	}
	result, err := db.Observations().Observations(ctx, store.ObservationFilter{PublicIP: "192.0.2.178", MatchMode: "exact", View: "pairs", Page: 1, PageSize: 10})
	if err != nil || result.Total != 1 || len(result.Items) != 1 || result.Items[0].ClientIP != "192.0.2.178" || result.Items[0].MatchingCount != 1 {
		t.Fatalf("signed client identity: %+v %v", result, err)
	}
	spoofed, err := db.Observations().Observations(ctx, store.ObservationFilter{PublicIP: "198.51.100.99", MatchMode: "exact", View: "pairs", Page: 1, PageSize: 10})
	if err != nil || spoofed.Total != 0 {
		t.Fatalf("forged client recorded: %+v %v", spoofed, err)
	}
	valid := `{"failure":"timeout"}`
	exact := valid + strings.Repeat(" ", (16<<10)-len(valid))
	if w := request("192.0.2.179", exact, false); w.Code != http.StatusOK {
		t.Fatalf("16 KiB body: %d %s", w.Code, w.Body.String())
	}
	for _, unknown := range []bool{false, true} {
		if w := request("192.0.2.180", exact+" ", unknown); w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("oversized body unknown=%v: %d", unknown, w.Code)
		}
	}
	if nginxMode {
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
		defer client.CloseIdleConnections()
		for _, tc := range []struct {
			path  string
			bytes int
		}{
			{"/api/v1/media/network-observation", (16 << 10) + 1},
			{"/api/v1/media/crypto/session", (8 << 10) + 1},
		} {
			req, err := http.NewRequest(http.MethodPost, origin+publicproxy.EdgePrefix+tc.path, strings.NewReader(strings.Repeat("x", tc.bytes)))
			if err != nil {
				t.Fatal(err)
			}
			req.Host = "entry.test"
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusRequestEntityTooLarge {
				t.Fatalf("nginx %s limit: %d", tc.path, resp.StatusCode)
			}
		}
	}
	current.set(store.PublicIngress{NodeID: ingress.NodeID, PublicOrigin: ingress.PublicOrigin, Generation: ingress.Generation + 1})
	if w := request("192.0.2.181", body, false); w.Code != http.StatusForbidden {
		t.Fatalf("stale ingress: %d", w.Code)
	}
}
