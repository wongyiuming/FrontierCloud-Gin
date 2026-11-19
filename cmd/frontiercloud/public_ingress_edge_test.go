package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/publicproxy"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const edgePeer = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const edgeRelation = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

var edgeCredential = protocol.Encode(bytes.Repeat([]byte{7}, 48))

type edgeLease struct{}

func (edgeLease) Commit() error { return nil }
func (edgeLease) Release()      {}

type edgeFixture struct {
	master     string
	generation atomic.Int64
	mu         sync.Mutex
	nonces     map[string]bool
}

func (f *edgeFixture) IdentityState(context.Context) (store.NodeIdentity, error) {
	return store.NodeIdentity{Role: "Master", Endpoint: f.master}, nil
}
func (f *edgeFixture) AcquireCurrentIngress(context.Context) (store.PublicIngress, store.PublicIngressLease, error) {
	return store.PublicIngress{NodeID: edgePeer, Generation: f.generation.Load(), PublicOrigin: "https://entry.example"}, edgeLease{}, nil
}
func (f *edgeFixture) Authenticate(_ context.Context, h http.Header, method, path string, body []byte, pending, revoked bool) (store.Relationship, error) {
	if pending || revoked {
		return store.Relationship{}, errors.New("unsafe flags")
	}
	headers := map[string]string{}
	for _, name := range []string{"X-Node-Relationship", "X-Node-Time", "X-Node-Nonce", "X-Node-Signature"} {
		headers[name] = h.Get(name)
	}
	nonce, err := protocol.VerifyAuth(edgeCredential, headers, method, path, body, time.Now().Unix())
	if err != nil || headers["X-Node-Relationship"] != edgeRelation {
		return store.Relationship{}, errors.New("invalid signature")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.nonces[nonce] {
		return store.Relationship{}, errors.New("replay")
	}
	f.nonces[nonce] = true
	return store.Relationship{PeerID: edgePeer, Direction: "downstream", State: "active", Protocol: protocol.Version}, nil
}

type edgeSigner struct{}

type candidateEdgeFixture struct {
	*edgeFixture
	calls atomic.Int32
}

func (f *candidateEdgeFixture) VerifyCandidateEdge(_ context.Context, h http.Header, body []byte) (node.Envelope, error) {
	f.calls.Add(1)
	if h.Get("X-Node-Signature") != "fixture" || string(body) != "{}" {
		return node.Envelope{}, errors.New("rejected")
	}
	return node.Envelope{Payload: map[string]any{"challenge": "fixture"}, Signature: "fixture"}, nil
}

func TestCandidateProbeRemainsOnTrustedFixedEdge(t *testing.T) {
	fixture := &candidateEdgeFixture{edgeFixture: &edgeFixture{master: "https://master.test", nonces: map[string]bool{}}}
	resolver, err := network.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	edge := masterIngressEdge(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("candidate probe reached business") }), fixture, resolver)
	call := func(method, path, body string, secure bool, signed bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if secure {
			r.TLS = &tls.ConnectionState{}
		}
		if signed {
			r.Header.Set("X-Node-Signature", "fixture")
		}
		w := httptest.NewRecorder()
		edge.ServeHTTP(w, r)
		return w
	}
	if w := call(http.MethodPost, node.IngressCandidateEdgePath, "{}", true, true); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "fixture") {
		t.Fatal("candidate probe", w.Code)
	}
	for _, input := range []struct {
		method, path, body string
		tls, signed        bool
	}{
		{http.MethodPost, node.IngressCandidateEdgePath, "{}", false, true},
		{http.MethodGet, node.IngressCandidateEdgePath, "{}", true, true},
		{http.MethodPost, node.IngressCandidateEdgePath + "?x=1", "{}", true, true},
		{http.MethodPost, node.IngressCandidateEdgePath, strings.Repeat("x", 1025), true, true},
		{http.MethodPost, node.IngressCandidateEdgePath, "{}", true, false},
	} {
		if w := call(input.method, input.path, input.body, input.tls, input.signed); w.Code == http.StatusOK {
			t.Fatal("unsafe candidate probe accepted", input.method, input.path)
		}
	}
	if fixture.calls.Load() != 2 {
		t.Fatal("unexpected probe verification calls", fixture.calls.Load())
	}
}

func TestMasterIngressProbeOnlyNeverServesBusiness(t *testing.T) {
	fixture := &candidateEdgeFixture{edgeFixture: &edgeFixture{master: "https://master.test", nonces: map[string]bool{}}}
	resolver, err := network.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(masterIngressProbeOnly(fixture, resolver))
	defer server.Close()
	for _, route := range []string{"/", "/api/v1/media/crypto/key", publicproxy.EdgePrefix + "/api/v1/media/catalog/media", node.IngressCandidateEdgePath + "/extra"} {
		resp, err := server.Client().Get(server.URL + route)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("bootstrap served %s: %d", route, resp.StatusCode)
		}
	}
	req, err := http.NewRequest(http.MethodPost, server.URL+node.IngressCandidateEdgePath, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Node-Signature", "fixture")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || fixture.calls.Load() != 1 {
		t.Fatalf("candidate bootstrap probe: %d calls=%d", resp.StatusCode, fixture.calls.Load())
	}
}

func (edgeSigner) SignPublicIngress(_ context.Context, _ string, body []byte) (http.Header, error) {
	values, err := protocol.AuthHeaders(edgeCredential, edgeRelation, http.MethodPost, publicproxy.ProofDomain, body, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	headers := http.Header{}
	for name, value := range values {
		headers.Set(name, value)
	}
	return headers, nil
}
func (edgeSigner) DialPublicIngress(ctx context.Context, networkName, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, networkName, address)
}

type edgeRecorder struct{ *httptest.ResponseRecorder }

func (w edgeRecorder) SetReadDeadline(time.Time) error  { return nil }
func (w edgeRecorder) SetWriteDeadline(time.Time) error { return nil }

// Exercises the actual runtime wrapper, real TLS and node HMAC, with a small
// edge fixture modelling only the HTTPS assertion normally made by Nginx.
func TestMasterIngressEdgeSignedRoundTripAndTrustedProxyBoundary(t *testing.T) {
	fixture := &edgeFixture{nonces: map[string]bool{}}
	fixture.generation.Store(9)
	var calls atomic.Int32
	var mode atomic.Int32
	resolver, err := network.New([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	business := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertion, ok := network.AuthenticatedIngressFromContext(r.Context())
		if !ok || assertion.NodeID != edgePeer || assertion.ClientIP != "192.0.2.10" {
			t.Error("business received no verified client")
		}
		calls.Add(1)
		w.Header().Set("Content-Security-Policy", "script-src 'nonce-test'")
		_, _ = io.WriteString(w, `<script nonce="test">ok()</script>`)
	})
	edge := masterIngressEdge(business, fixture, resolver)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TLS termination is local to the fixture; the internal hop is HTTP.
		r.TLS = nil
		r.RemoteAddr = "10.1.2.3:1234"
		r.Header.Set("X-Real-IP", "192.0.2.77")
		r.Header.Set("X-Forwarded-Proto", "https")
		if mode.Load() == 1 {
			r.RemoteAddr = "192.0.2.50:1234"
		}
		if mode.Load() == 2 {
			r.Header.Set("X-Forwarded-Proto", "http")
		}
		edge.ServeHTTP(w, r)
	}))
	defer server.Close()
	fixture.master = server.URL
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	proxy, err := publicproxy.New(publicproxy.Config{MasterOrigin: server.URL, PublicOrigin: "https://entry.example", RootCAs: roots, MasterEdge: true, Peer: &publicproxy.PeerConfig{NodeID: edgePeer, Generation: 9, Signer: edgeSigner{}}})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.CloseIdleConnections()
	request := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/media", nil)
		r.Host = "entry.example"
		r.TLS = &tls.ConnectionState{}
		r.RemoteAddr = "192.0.2.10:1234"
		w := edgeRecorder{httptest.NewRecorder()}
		proxy.ServeHTTP(w, r)
		return w.ResponseRecorder
	}
	w := request()
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `nonce="test"`) || w.Header().Get("Content-Security-Policy") != "script-src 'nonce-test'" {
		t.Fatalf("signed roundtrip %d %v %q", w.Code, w.Header(), w.Body.String())
	}
	for _, bad := range []int32{1, 2} {
		mode.Store(bad)
		if w := request(); w.Code != http.StatusForbidden {
			t.Fatalf("untrusted edge %d: %d", bad, w.Code)
		}
	}
	mode.Store(0)
	fixture.generation.Store(10)
	if w := request(); w.Code != http.StatusForbidden || calls.Load() != 1 {
		t.Fatalf("stale generation: %d, business calls %d", w.Code, calls.Load())
	}
}

type edgeCatalogPrepare func(*http.Request) (publicproxy.PreparedCatalog, error)

func (f edgeCatalogPrepare) PrepareCatalog(r *http.Request) (publicproxy.PreparedCatalog, error) {
	return f(r)
}

type edgeCatalogPrerequisite struct{}

func (edgeCatalogPrerequisite) Check(context.Context) error { return nil }

type edgeCatalogControl struct {
	*edgeFixture
	reject atomic.Bool
}

func (f *edgeCatalogControl) AcquireCatalogIngress(ctx context.Context, rel store.Relationship, expected store.PublicIngress, check func(context.Context, store.IngressPrerequisite) error) (store.PublicIngress, store.PublicIngressLease, error) {
	if f.reject.Load() || rel.PeerID != edgePeer || check(ctx, edgeCatalogPrerequisite{}) != nil {
		return store.PublicIngress{}, nil, errors.New("catalog scope rejected")
	}
	current, lease, err := f.AcquireCurrentIngress(ctx)
	if err != nil || current != expected {
		return store.PublicIngress{}, nil, errors.New("ingress changed")
	}
	return current, lease, nil
}

// The real edge wrapper must route authenticated catalog reads through the
// supplied preparer and final fence, never expose an uncommitted response.
func TestMasterIngressEdgeUsesInjectedCatalogPreparer(t *testing.T) {
	base := &edgeFixture{nonces: map[string]bool{}}
	base.generation.Store(9)
	control := &edgeCatalogControl{edgeFixture: base}
	resolver, err := network.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	var prepared, checked, released, business atomic.Int32
	preparer := edgeCatalogPrepare(func(r *http.Request) (publicproxy.PreparedCatalog, error) {
		if _, ok := network.AuthenticatedIngressFromContext(r.Context()); !ok || r.URL.Path != "/api/v1/media/catalog/media" {
			return publicproxy.PreparedCatalog{}, errors.New("unauthenticated catalog")
		}
		prepared.Add(1)
		return publicproxy.PreparedCatalog{Body: []byte(`{"items":["private"]}`), Release: func() { released.Add(1) }, CheckScope: func(ctx context.Context, p store.IngressPrerequisite) error {
			checked.Add(1)
			return p.Check(ctx)
		}}, nil
	})
	edge := masterIngressEdgeWithCatalogPreparer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { business.Add(1) }), control, resolver, preparer)
	server := httptest.NewTLSServer(edge)
	defer server.Close()
	base.master = server.URL
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	proxy, err := publicproxy.New(publicproxy.Config{MasterOrigin: server.URL, PublicOrigin: "https://entry.example", RootCAs: roots, MasterEdge: true, Peer: &publicproxy.PeerConfig{NodeID: edgePeer, Generation: 9, Signer: edgeSigner{}}})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.CloseIdleConnections()
	request := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/media/catalog/media?path=music", nil)
		r.Host, r.TLS, r.RemoteAddr = "entry.example", &tls.ConnectionState{}, "192.0.2.10:1234"
		w := edgeRecorder{httptest.NewRecorder()}
		proxy.ServeHTTP(w, r)
		return w.ResponseRecorder
	}
	if w := request(); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"private"`) || w.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("catalog response: %d %v %q", w.Code, w.Header(), w.Body.String())
	}
	control.reject.Store(true)
	if w := request(); w.Code == http.StatusOK || strings.Contains(w.Body.String(), `"private"`) {
		t.Fatalf("rejected catalog exposed: %d %q", w.Code, w.Body.String())
	}
	if prepared.Load() != 2 || checked.Load() != 1 || released.Load() != 2 || business.Load() != 0 {
		t.Fatalf("unexpected calls: prepare=%d check=%d release=%d business=%d", prepared.Load(), checked.Load(), released.Load(), business.Load())
	}
}

func TestMasterIngressEdgeRejectsPreparerWithoutCatalogFence(t *testing.T) {
	control := &edgeFixture{master: "https://master.example", nonces: map[string]bool{}}
	resolver, err := network.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	preparer := edgeCatalogPrepare(func(*http.Request) (publicproxy.PreparedCatalog, error) {
		t.Fatal("unfenced preparer ran")
		return publicproxy.PreparedCatalog{}, nil
	})
	edge := masterIngressEdgeWithCatalogPreparer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unfenced business handler ran")
	}), control, resolver, preparer)
	r := httptest.NewRequest(http.MethodGet, publicproxy.EdgePrefix+"/api/v1/media/catalog/media", nil)
	r.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()
	edge.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing catalog fence: got %d", w.Code)
	}
}
