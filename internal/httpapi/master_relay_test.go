package httpapi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/publicproxy"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const relayFixtureRelation = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

var relayFixtureCredential = protocol.Encode(bytes.Repeat([]byte{7}, 48))

type relayFixtureSigner struct{}

func (relayFixtureSigner) SignPublicIngress(_ context.Context, _ string, raw []byte) (http.Header, error) {
	values, err := protocol.AuthHeaders(relayFixtureCredential, relayFixtureRelation, http.MethodPost, publicproxy.ProofDomain, raw, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	for key, value := range values {
		h.Set(key, value)
	}
	return h, nil
}
func (relayFixtureSigner) DialPublicIngress(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

type relayFixtureAuth struct {
	peer   string
	mu     sync.Mutex
	nonces map[string]bool
}

func (a *relayFixtureAuth) Authenticate(_ context.Context, h http.Header, method, route string, raw []byte, pending, revoked bool) (store.Relationship, error) {
	if pending || revoked {
		return store.Relationship{}, errors.New("invalid flags")
	}
	values := map[string]string{}
	for _, key := range []string{"X-Node-Relationship", "X-Node-Time", "X-Node-Nonce", "X-Node-Signature"} {
		values[key] = h.Get(key)
	}
	nonce, err := protocol.VerifyAuth(relayFixtureCredential, values, method, route, raw, time.Now().Unix())
	if err != nil || values["X-Node-Relationship"] != relayFixtureRelation {
		return store.Relationship{}, errors.New("invalid proof")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.nonces[nonce] {
		return store.Relationship{}, errors.New("replay")
	}
	a.nonces[nonce] = true
	return store.Relationship{PeerID: a.peer, Direction: "downstream", State: "active", Protocol: protocol.Version}, nil
}

type relayFixtureLease struct{}

func (relayFixtureLease) Commit() error { return nil }
func (relayFixtureLease) Release()      {}

func (r *masterDirectHTTPRouting) EnablePeerIngress() {}
func (r *masterDirectHTTPRouting) CommitPeerPublicIngress(context.Context, store.PeerIngressEvidence, int64, store.NodeAudit) (store.PublicIngress, error) {
	return store.PublicIngress{}, store.ErrNodeState
}

type relayTreeFixture struct {
	active    atomic.Int64
	failFinal atomic.Bool
}
type relayTreeLease struct {
	fixture  *relayTreeFixture
	checks   atomic.Int64
	released atomic.Bool
}

func (l *relayTreeLease) Check(ctx context.Context) error {
	if ctx.Err() != nil || l.released.Load() || l.fixture.failFinal.Load() && l.checks.Add(1) >= 2 {
		return errors.New("tree fence unavailable")
	}
	return nil
}
func (l *relayTreeLease) Release() {
	if l.released.CompareAndSwap(false, true) {
		l.fixture.active.Add(-1)
	}
}
func (f *relayTreeFixture) acquire(context.Context) (node.IngressPrerequisiteLease, error) {
	f.active.Add(1)
	return &relayTreeLease{fixture: f}, nil
}

type relayFixtureCurrent struct {
	mu    sync.RWMutex
	value store.PublicIngress
}

func (s *relayFixtureCurrent) AcquireCurrentIngress(context.Context) (store.PublicIngress, store.PublicIngressLease, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.value, relayFixtureLease{}, nil
}
func (s *relayFixtureCurrent) set(value store.PublicIngress) {
	s.mu.Lock()
	s.value = value
	s.mu.Unlock()
}

func TestMasterRelayEncryptedRangeThroughAuthenticatedPeer(t *testing.T) {
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	_, db, dir, public, original := clusterFixture(t, "https://master.test", transport, false)
	plain := []byte("relay ciphertext identity")
	meta, err := mediacrypto.NewMetadata(int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	key, err := public.crypto.FileKey(meta)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := meta.ChunkNonce(0)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := aead.Seal(nil, nonce, plain, meta.ChunkAAD(0))
	stage, err := public.media.Stage(ctx, bytes.NewReader(ciphertext), int64(len(ciphertext)))
	if err != nil {
		t.Fatal(err)
	}
	name, err := public.media.PublishEncrypted(ctx, stage, "relay.mp3", "music/artist", "", false, 255, store.AdminAudit{}, &meta)
	stage.Close()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := original.Promote(ctx, "Master", "https://master.test", 10*store.GiB, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := db.Pool().Resources(ctx, name, true)
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	row := rows[0]
	ingress := store.PublicIngress{NodeID: strings.Repeat("a", 32), PublicOrigin: "https://entry.test", Generation: 5}
	routing := &masterDirectHTTPRouting{selectedIngressRepository: selectedIngressRepository{NodeRepository: db.Nodes(), PublicRoutingRepository: db.Nodes().(store.PublicRoutingRepository), selected: ingress}, policy: store.NativeTransportPolicy{MemberID: identity.ID, ConfiguredTransport: "Relay", AppliedTransport: "Relay", State: "applied", Revision: 2}}
	localIdentity, err := node.Initialize(ctx, db.Nodes(), filepath.Join(dir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	control := node.NewService(routing, localIdentity, transport)
	prepareMasterHTTPPolicy(t, control)
	treeFence := &relayTreeFixture{}
	if err := control.ConfigureIngressSelectionReadiness(ctx, treeFence.acquire); err != nil {
		t.Fatal(err)
	}
	public.media.ConfigureCluster(routing, db.Pool(), control)
	masterRouter := gin.New()
	reader, err := RegisterMasterRelay(masterRouter, public.media, control, public.crypto)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := network.WithAuthenticatedIngress(ctx, network.AuthenticatedIngress{NodeID: ingress.NodeID, PublicOrigin: ingress.PublicOrigin, Generation: ingress.Generation, ClientIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	admitted, admission := network.WithPublicAdmission(verified)
	defer admission.Abort()
	client, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := "browser:v2:" + strings.Repeat("c", 64)
	session, err := public.crypto.NewSession(binding, base64.StdEncoding.EncodeToString(client.PublicKey().Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	object, err := public.media.CryptoObject(admitted, row.Path, row.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	source, headers, expiry, err := reader.Issue(admitted, object, binding, session.SessionID)
	if err != nil || source != ingress.PublicOrigin+"/api/v1/media/master-relay/"+row.ID || strings.Contains(source, "?") || headers["X-Media-Relay"] == "" || expiry > session.ExpiresAt {
		t.Fatal("relay grant", source, expiry, err)
	}
	if _, err := control.VerifyMasterDirectCapability(ctx, headers["X-Media-Relay"], ingress.PublicOrigin, row.ID); err == nil {
		t.Fatal("Relay capability accepted as Direct")
	}
	local := store.PublicIngress{NodeID: identity.ID, PublicOrigin: "https://master.test", Generation: ingress.Generation + 1}
	routing.selected = local
	localCtx, err := network.WithAuthenticatedIngress(ctx, network.AuthenticatedIngress{NodeID: local.NodeID, PublicOrigin: local.PublicOrigin, Generation: local.Generation, ClientIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	localCtx, localAdmission := network.WithPublicAdmission(localCtx)
	defer localAdmission.Abort()
	if _, _, _, err := reader.Issue(localCtx, object, binding, session.SessionID); err == nil {
		t.Fatal("ingress-local object looped through Master relay")
	}
	routing.selected = ingress

	var wrapped atomic.Value
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { wrapped.Load().(http.Handler).ServeHTTP(w, r) }))
	defer server.Close()
	current := &relayFixtureCurrent{value: ingress}
	verifier, err := publicproxy.NewVerifier(publicproxy.VerifierConfig{MasterOrigin: server.URL, Authenticator: &relayFixtureAuth{peer: ingress.NodeID, nonces: map[string]bool{}}, Current: current})
	if err != nil {
		t.Fatal(err)
	}
	wrapped.Store(verifier.Wrap(masterRouter))
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	peer, err := publicproxy.New(publicproxy.Config{MasterOrigin: server.URL, PublicOrigin: ingress.PublicOrigin, RootCAs: roots, Peer: &publicproxy.PeerConfig{NodeID: ingress.NodeID, Generation: ingress.Generation, Signer: relayFixtureSigner{}}})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.CloseIdleConnections()
	request := func(method, target, token, rangeValue string) *httptest.ResponseRecorder {
		u, err := url.Parse(target)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(method, u.RequestURI(), nil)
		r.Host = u.Host
		r.TLS = &tls.ConnectionState{}
		r.RemoteAddr = "192.0.2.1:1234"
		if token != "" {
			r.Header.Set("X-Media-Relay", token)
		}
		if rangeValue != "" {
			r.Header.Set("Range", rangeValue)
		}
		w := httptest.NewRecorder()
		peer.ServeHTTP(masterDirectRecorder{w}, r)
		return w
	}
	w := request(http.MethodGet, source, headers["X-Media-Relay"], "bytes=1-3")
	if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), ciphertext[1:4]) || w.Header().Get("Content-Range") == "" || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("relay range: %d %v %q", w.Code, w.Header(), w.Body.Bytes())
	}
	if treeFence.active.Load() != 0 {
		t.Fatal("relay retained tree fence after response")
	}
	treeFence.failFinal.Store(true)
	if w := request(http.MethodGet, source, headers["X-Media-Relay"], "bytes=1-3"); w.Code != http.StatusServiceUnavailable || bytes.Contains(w.Body.Bytes(), ciphertext[1:4]) {
		t.Fatal("relay exposed bytes after final tree fence failure", w.Code)
	}
	treeFence.failFinal.Store(false)
	if treeFence.active.Load() != 0 {
		t.Fatal("failed relay leaked tree fence")
	}
	if w := request(http.MethodHead, source, headers["X-Media-Relay"], ""); w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Fatalf("relay HEAD: %d", w.Code)
	}
	if w := request(http.MethodGet, source, headers["X-Media-Relay"]+"A", "bytes=0-1"); w.Code != http.StatusForbidden {
		t.Fatal("tampered relay grant accepted", w.Code)
	}
	if _, err := db.Database().Exec("UPDATE global_media_objects SET etag=? WHERE media_id=?", "replacement", row.ID); err != nil {
		t.Fatal(err)
	}
	if w := request(http.MethodGet, source, headers["X-Media-Relay"], "bytes=0-1"); w.Code != http.StatusForbidden {
		t.Fatal("replacement object accepted", w.Code)
	}
	if _, err := db.Database().Exec("UPDATE global_media_objects SET etag=? WHERE media_id=?", row.ETag, row.ID); err != nil {
		t.Fatal(err)
	}
	if err := public.media.Hide(ctx, []string{name}, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	if w := request(http.MethodGet, source, headers["X-Media-Relay"], "bytes=0-1"); w.Code != http.StatusForbidden {
		t.Fatal("hidden resource accepted", w.Code)
	}
	if err := public.media.Hide(ctx, []string{name}, false, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{source + "?token=secret", ingress.PublicOrigin + "/api/v1/media/master-relay/" + strings.Repeat("f", 64)} {
		if w := request(http.MethodGet, target, headers["X-Media-Relay"], ""); w.Code < 400 {
			t.Fatal("invalid relay target accepted", w.Code)
		}
	}
	if w := request(http.MethodGet, source, headers["X-Media-Relay"], "bytes=0-1,4-5"); w.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatal("multiple ranges accepted", w.Code)
	}
	routing.policy.ConfiguredTransport, routing.policy.AppliedTransport = "Direct", "Direct"
	if _, _, _, err := reader.Issue(admitted, object, binding, session.SessionID); err == nil {
		t.Fatal("Relay issued under Direct policy")
	}
	if w := request(http.MethodGet, source, headers["X-Media-Relay"], "bytes=0-1"); w.Code != http.StatusPartialContent {
		t.Fatal("issued grant did not drain", w.Code)
	}
	current.set(store.PublicIngress{NodeID: ingress.NodeID, PublicOrigin: ingress.PublicOrigin, Generation: ingress.Generation + 1})
	if w := request(http.MethodGet, source, headers["X-Media-Relay"], "bytes=0-1"); w.Code != http.StatusForbidden {
		t.Fatal("stale ingress admitted", w.Code)
	}
	current.set(ingress)
	public.crypto.RevokeBinding(binding)
	if w := request(http.MethodGet, source, headers["X-Media-Relay"], "bytes=0-1"); w.Code != http.StatusForbidden {
		t.Fatal("revoked session admitted", w.Code)
	}
}
