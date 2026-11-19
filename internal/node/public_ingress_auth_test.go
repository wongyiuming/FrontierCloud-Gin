package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/publicproxy"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// The relation store fixture enforces atomic nonce reservation, like the real
// NodeRepository. Service.Authenticate itself remains the real implementation.
type publicIngressRepo struct {
	store.NodeRepository
	row      store.NodeIdentity
	relation store.Relationship
	mu       sync.Mutex
	nonces   map[string]bool
}

func (r *publicIngressRepo) InitializeIdentity(_ context.Context, row store.NodeIdentity) (store.NodeIdentity, error) {
	r.row = row
	return row, nil
}
func (r *publicIngressRepo) ReadIdentity(context.Context) (store.NodeIdentity, error) {
	if r.row.ID == "" {
		return store.NodeIdentity{}, sql.ErrNoRows
	}
	return r.row, nil
}
func (r *publicIngressRepo) Relationship(_ context.Context, id string) (store.Relationship, error) {
	if id != r.relation.ID {
		return store.Relationship{}, store.ErrNodeState
	}
	return r.relation, nil
}
func (r *publicIngressRepo) ReserveNodeNonce(_ context.Context, id, nonce, credential string, _ int64, pending, revoked bool) (store.Relationship, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if id != r.relation.ID || credential != r.relation.Credential || r.relation.State != "active" || pending || revoked || r.nonces[nonce] {
		return store.Relationship{}, store.ErrNodeState
	}
	if r.nonces == nil {
		r.nonces = map[string]bool{}
	}
	r.nonces[nonce] = true
	return r.relation, nil
}

func ingressTestService(t *testing.T, role string) (*Service, *publicIngressRepo) {
	t.Helper()
	repo := &publicIngressRepo{}
	identity, err := Initialize(context.Background(), repo, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repo.row.Role = role
	return NewService(repo, identity, nil), repo
}

func TestPublicIngressSignerUsesPairedCredentialAndMasterAuthentication(t *testing.T) {
	ctx := context.Background()
	follower, fr := ingressTestService(t, "Follower")
	master, mr := ingressTestService(t, "Master")
	credential := protocol.Encode(bytes.Repeat([]byte{9}, 48))
	masterSeal, err := master.identity.vault.Seal(credential)
	if err != nil {
		t.Fatal(err)
	}
	followerSeal, err := follower.identity.vault.Seal(credential)
	if err != nil {
		t.Fatal(err)
	}
	relationship := strings.Repeat("a", 32)
	fr.relation = store.Relationship{ID: relationship, PeerID: mr.row.ID, Endpoint: "https://master.example", Credential: followerSeal, Direction: "upstream", State: "active", Protocol: protocol.Version}
	mr.relation = store.Relationship{ID: relationship, PeerID: fr.row.ID, Endpoint: "https://entry.example", Credential: masterSeal, Direction: "downstream", State: "active", Protocol: protocol.Version}
	proof := publicproxy.SigningProof{Version: 1, IngressID: fr.row.ID, Generation: 3, PublicOrigin: "https://entry.example", MasterOrigin: "https://master.example", ClientIP: "192.0.2.10", Method: http.MethodPost, RequestURI: "/api/v1/media/crypto/key?x=1", BodyHash: strings.Repeat("1", 64), BrowserHeaderHash: strings.Repeat("2", 64)}
	raw, _ := json.Marshal(proof)
	signer, err := follower.NewPublicIngressSigner(relationship)
	if err != nil {
		t.Fatal(err)
	}
	headers, err := signer.SignPublicIngress(ctx, "https://master.example", raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(headers.Get("X-Node-Signature"), credential) || len(headers) != 4 {
		t.Fatal("credential or unexpected header exposed")
	}
	relation, err := master.Authenticate(ctx, headers, http.MethodPost, publicproxy.ProofDomain, raw, false, false)
	if err != nil || relation.PeerID != fr.row.ID {
		t.Fatalf("real node authentication failed: %v", err)
	}
	if _, err = master.Authenticate(ctx, headers, http.MethodPost, publicproxy.ProofDomain, raw, false, false); err == nil {
		t.Fatal("replayed nonce accepted")
	}
	fresh, err := signer.SignPublicIngress(ctx, "https://master.example", raw)
	if err != nil {
		t.Fatal(err)
	}
	changed := append([]byte(nil), raw...)
	changed[len(changed)-3] ^= 1
	if _, err = master.Authenticate(ctx, fresh, http.MethodPost, publicproxy.ProofDomain, changed, false, false); err == nil {
		t.Fatal("modified proof authenticated")
	}
	stale, err := protocol.AuthHeaders(credential, relationship, http.MethodPost, publicproxy.ProofDomain, raw, time.Now().Unix()-61)
	if err != nil {
		t.Fatal(err)
	}
	oldHeaders := http.Header{}
	for k, v := range stale {
		oldHeaders.Set(k, v)
	}
	if _, err = master.Authenticate(ctx, oldHeaders, http.MethodPost, publicproxy.ProofDomain, raw, false, false); err == nil {
		t.Fatal("expired proof authenticated")
	}
	if _, err = signer.SignPublicIngress(ctx, "https://other.example", raw); err == nil {
		t.Fatal("different target signed")
	}
	altered := proof
	altered.IngressID = strings.Repeat("b", 32)
	bad, _ := json.Marshal(altered)
	if _, err = signer.SignPublicIngress(ctx, "https://master.example", bad); err == nil {
		t.Fatal("another node identity signed")
	}
	if _, err = signer.SignPublicIngress(ctx, "https://master.example", []byte(`{"invalid":true}`)); err == nil {
		t.Fatal("arbitrary signing oracle")
	}
	fr.relation.State = "revoked"
	if _, err = signer.SignPublicIngress(ctx, "https://master.example", raw); err == nil {
		t.Fatal("revoked relationship signed")
	}
	fr.relation.State = "active"
	fr.relation.Direction = "downstream"
	if _, err = signer.SignPublicIngress(ctx, "https://master.example", raw); err == nil {
		t.Fatal("wrong relationship direction signed")
	}
	fr.relation.Direction = "upstream"
	fr.row.Role = "Master"
	if _, err = signer.SignPublicIngress(ctx, "https://master.example", raw); err == nil {
		t.Fatal("Master impersonated follower ingress")
	}
}

func TestPublicIngressSignerRejectsUnconfiguredService(t *testing.T) {
	var service *Service
	if _, err := service.NewPublicIngressSigner(strings.Repeat("a", 32)); err == nil {
		t.Fatal("nil service accepted")
	}
	if _, err := (&Service{}).NewPublicIngressSigner("bad"); err == nil {
		t.Fatal("invalid configuration accepted")
	}
	var signer *PublicIngressSigner
	if _, err := signer.SignPublicIngress(context.Background(), "https://master.example", nil); err == nil {
		t.Fatal("nil signer accepted")
	}
}

// Test-only dialer targets the local fixture; the real signer uses safeDial.
type localIngressSigner struct {
	*PublicIngressSigner
	fixtureAddress string
}

func (s localIngressSigner) DialPublicIngress(ctx context.Context, network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, s.fixtureAddress)
}

type localRecorder struct{ *httptest.ResponseRecorder }

func (*localRecorder) SetReadDeadline(time.Time) error  { return nil }
func (*localRecorder) SetWriteDeadline(time.Time) error { return nil }

type testIngressState struct {
	mu    sync.RWMutex
	value store.PublicIngress
}

type testIngressLease struct {
	once    sync.Once
	release func()
}

func (l *testIngressLease) Commit() error { l.Release(); return nil }
func (l *testIngressLease) Release()      { l.once.Do(l.release) }

func (s *testIngressState) AcquireCurrentIngress(context.Context) (store.PublicIngress, store.PublicIngressLease, error) {
	s.mu.RLock()
	return s.value, &testIngressLease{release: s.mu.RUnlock}, nil
}
func (s *testIngressState) set(v store.PublicIngress) { s.mu.Lock(); defer s.mu.Unlock(); s.value = v }

func ingressFixtureCertificate(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"master.example"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}, cert
}

func TestPublicIngressProtocolRealNodeServicesOverTLS(t *testing.T) {
	follower, fr := ingressTestService(t, "Follower")
	master, mr := ingressTestService(t, "Master")
	credential := protocol.Encode(bytes.Repeat([]byte{5}, 48))
	masterSeal, err := master.identity.vault.Seal(credential)
	if err != nil {
		t.Fatal(err)
	}
	followerSeal, err := follower.identity.vault.Seal(credential)
	if err != nil {
		t.Fatal(err)
	}
	certificate, trust := ingressFixtureCertificate(t)
	var handler atomic.Value
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.Load().(http.Handler).ServeHTTP(w, r) }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	defer server.Close()
	actual, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	masterOrigin := "https://master.example:" + actual.Port()
	relationID := strings.Repeat("a", 32)
	fr.relation = store.Relationship{ID: relationID, PeerID: mr.row.ID, Endpoint: masterOrigin, Credential: followerSeal, Direction: "upstream", State: "active", Protocol: protocol.Version}
	mr.relation = store.Relationship{ID: relationID, PeerID: fr.row.ID, Endpoint: "https://entry.example", Credential: masterSeal, Direction: "downstream", State: "active", Protocol: protocol.Version}
	state := &testIngressState{value: store.PublicIngress{NodeID: fr.row.ID, Generation: 4, PublicOrigin: "https://entry.example"}}
	verifier, err := publicproxy.NewVerifier(publicproxy.VerifierConfig{MasterOrigin: masterOrigin, Authenticator: master, Current: state})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	handler.Store(verifier.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		resolver, _ := network.New([]string{"127.0.0.0/8", "192.0.2.0/24"})
		identity := resolver.Resolve(r)
		if identity.IP != "192.0.2.8" || identity.PeerIP != "127.0.0.1" || !identity.FromAuthenticatedIngress || identity.TrustedHeaderMissing || r.Header.Get("X-Node-Signature") != "" {
			t.Error("unverified source context reached handler")
		}
		_, _ = w.Write([]byte("verified"))
	})))
	signer, err := follower.NewPublicIngressSigner(relationID)
	if err != nil {
		t.Fatal(err)
	}
	if connection, err := signer.DialPublicIngress(context.Background(), "tcp", "other.example:443"); err == nil {
		connection.Close()
		t.Fatal("node dialer accepted an unrelated target")
	}
	originalEndpoint := fr.relation.Endpoint
	fr.relation.Endpoint = "https://127.0.0.1:" + actual.Port()
	if connection, err := signer.DialPublicIngress(context.Background(), "tcp", "127.0.0.1:"+actual.Port()); err == nil {
		connection.Close()
		t.Fatal("node dialer accepted a loopback endpoint")
	}
	fr.relation.Endpoint = originalEndpoint
	roots := x509.NewCertPool()
	roots.AddCert(trust)
	proxy, err := publicproxy.New(publicproxy.Config{MasterOrigin: masterOrigin, PublicOrigin: "https://entry.example", RootCAs: roots, Peer: &publicproxy.PeerConfig{NodeID: fr.row.ID, Generation: 4, Signer: localIngressSigner{PublicIngressSigner: signer, fixtureAddress: actual.Host}}})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.CloseIdleConnections()
	run := func() *localRecorder {
		req := httptest.NewRequest(http.MethodPost, "https://entry.example/api/v1/media/crypto/key", strings.NewReader(`{}`))
		// Incoming server requests use origin-form targets.
		req.URL.Scheme = ""
		req.URL.Host = ""
		req.RemoteAddr = "192.0.2.8:1234"
		req.Header.Set("X-Real-IP", "127.0.0.1")
		w := &localRecorder{httptest.NewRecorder()}
		proxy.ServeHTTP(w, req)
		return w
	}
	if w := run(); w.Code != 200 || w.Body.String() != "verified" || calls.Load() != 1 {
		t.Fatalf("node-to-node TLS request: %d %q calls=%d", w.Code, w.Body.String(), calls.Load())
	}
	state.set(store.PublicIngress{NodeID: fr.row.ID, Generation: 5, PublicOrigin: "https://entry.example"})
	if w := run(); w.Code != 403 || calls.Load() != 1 {
		t.Fatalf("stale ingress accepted: %d", w.Code)
	}
	fr.relation.State = "revoked"
	if w := run(); w.Code != 503 || calls.Load() != 1 {
		t.Fatalf("revoked signer accepted: %d", w.Code)
	}
}
