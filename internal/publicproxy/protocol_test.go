package publicproxy

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
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const testPeerID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testRelationship = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

var testCredential = protocol.Encode(bytes.Repeat([]byte{7}, 48))

type fixtureSigner struct{}

func (fixtureSigner) DialPublicIngress(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (fixtureSigner) SignPublicIngress(_ context.Context, _ string, data []byte) (http.Header, error) {
	headers, err := protocol.AuthHeaders(testCredential, testRelationship, http.MethodPost, ProofDomain, data, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return h, nil
}

type fixtureAuthenticator struct {
	mu           sync.Mutex
	seen         map[string]bool
	relationship store.Relationship
}

func (a *fixtureAuthenticator) Authenticate(_ context.Context, h http.Header, method, path string, body []byte, pending, revoked bool) (store.Relationship, error) {
	if pending || revoked {
		return store.Relationship{}, errors.New("unsafe flag")
	}
	values := map[string]string{}
	for _, name := range nodeAuthHeaders {
		if len(h.Values(name)) != 1 {
			return store.Relationship{}, errors.New("invalid header")
		}
		values[name] = h.Get(name)
	}
	nonce, err := protocol.VerifyAuth(testCredential, values, method, path, body, time.Now().Unix())
	if err != nil {
		return store.Relationship{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.seen == nil {
		a.seen = map[string]bool{}
	}
	if a.seen[nonce] {
		return store.Relationship{}, errors.New("replay")
	}
	a.seen[nonce] = true
	return a.relationship, nil
}

type fixtureCurrent struct {
	mu        sync.RWMutex
	state     store.PublicIngress
	err       error
	commitErr error
	onCommit  func()
}

type leaseCheckingAuthenticator struct {
	current *fixtureCurrent
	next    *fixtureAuthenticator
}

func (a leaseCheckingAuthenticator) Authenticate(ctx context.Context, h http.Header, method, path string, body []byte, pending, revoked bool) (store.Relationship, error) {
	if a.current.mu.TryLock() {
		a.current.mu.Unlock()
		return store.Relationship{}, errors.New("relationship authenticated without ingress lease")
	}
	return a.next.Authenticate(ctx, h, method, path, body, pending, revoked)
}

type fixtureLease struct {
	once     sync.Once
	release  func()
	err      error
	onCommit func()
}

type nilLeaseCurrent struct{}

func (nilLeaseCurrent) AcquireCurrentIngress(context.Context) (store.PublicIngress, store.PublicIngressLease, error) {
	var lease *fixtureLease
	return active(), lease, nil
}

func (l *fixtureLease) Commit() error {
	l.Release()
	if l.onCommit != nil {
		l.onCommit()
	}
	return l.err
}
func (l *fixtureLease) Release() { l.once.Do(l.release) }

func (c *fixtureCurrent) AcquireCurrentIngress(context.Context) (store.PublicIngress, store.PublicIngressLease, error) {
	c.mu.RLock()
	if c.err != nil {
		c.mu.RUnlock()
		return store.PublicIngress{}, nil, c.err
	}
	return c.state, &fixtureLease{release: c.mu.RUnlock, err: c.commitErr, onCommit: c.onCommit}, nil
}
func (c *fixtureCurrent) set(s store.PublicIngress, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state, c.err = s, err
}
func active() store.PublicIngress {
	return store.PublicIngress{NodeID: testPeerID, PublicOrigin: "https://entry.example", Generation: 9}
}
func fixtureVerifier(t *testing.T, master string) (*Verifier, *fixtureAuthenticator, *fixtureCurrent) {
	t.Helper()
	auth := &fixtureAuthenticator{relationship: store.Relationship{ID: testRelationship, PeerID: testPeerID, Direction: "downstream", State: "active", Protocol: protocol.Version}}
	current := &fixtureCurrent{state: active()}
	v, err := NewVerifier(VerifierConfig{MasterOrigin: master, Authenticator: auth, Current: current})
	if err != nil {
		t.Fatal(err)
	}
	return v, auth, current
}

func signedFixture(t *testing.T, master string) *http.Request {
	return signedFixtureFor(t, master, http.MethodPost, "/api/v1/media/crypto/session?x=1")
}

func signedFixtureFor(t *testing.T, master, method, path string) *http.Request {
	t.Helper()
	body := []byte(`{"public_key":"abc"}`)
	if method == http.MethodGet || method == http.MethodDelete {
		body = nil
	}
	r := incoming(method, path, bytes.NewReader(body))
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Origin", "https://entry.example")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Content-Type", "application/json")
	if strings.HasPrefix(path, "/api/v1/media/crypto/") {
		r.Header.Set("Cookie", "frontiercloud_browser_crypto=browser")
	}
	if _, needsSession := recordingControl(path); needsSession {
		r.Header.Set(recordingSessionHeader, testPeerID)
	}
	pub, _ := origin("https://entry.example")
	target, _ := origin(master)
	proof, err := makeProof(testPeerID, 9, pub, target, "192.0.2.10", r, body)
	if err != nil {
		t.Fatal(err)
	}
	headers, err := (fixtureSigner{}).SignPublicIngress(context.Background(), master, proof)
	if err != nil {
		t.Fatal(err)
	}
	for k, values := range headers {
		r.Header[k] = values
	}
	r.Header.Set("X-Fc-Public-Hop", "1")
	r.Header.Set("X-Fc-Public-Version", "1")
	r.Header.Set("X-Fc-Public-Ingress", testPeerID)
	r.Header.Set("X-Fc-Public-Generation", "9")
	r.Header.Set("X-Fc-Public-Origin", "https://entry.example")
	r.Header.Set("X-Fc-Public-Client-Ip", "192.0.2.10")
	return r
}

func TestAdmissionCommitFailureDropsResponseAndHeaders(t *testing.T) {
	const master = "https://master.example"
	v, _, current := fixtureVerifier(t, master)
	current.commitErr = errors.New("connection lost")
	w := httptest.NewRecorder()
	v.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "frontiercloud_browser_crypto=secret")
		w.Header().Set("X-Secret", "sensitive")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("secret-envelope"))
	})).ServeHTTP(w, signedFixture(t, master))
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "secret-envelope") || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-Secret") != "" {
		t.Fatal("failed commit exposed authorization", w.Code, w.Header(), w.Body.String())
	}
}

func TestAdmissionRejectsTypedNilLease(t *testing.T) {
	const master = "https://master.example"
	v, _, _ := fixtureVerifier(t, master)
	v.current = nilLeaseCurrent{}
	w := httptest.NewRecorder()
	v.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("handler reached with nil lease") })).ServeHTTP(w, signedFixture(t, master))
	if w.Code != http.StatusForbidden {
		t.Fatal("typed nil lease accepted", w.Code)
	}
}

func TestAdmissionCancellationDuringCommitDropsResponse(t *testing.T) {
	const master = "https://master.example"
	v, _, current := fixtureVerifier(t, master)
	r := signedFixture(t, master)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	current.onCommit = cancel
	w := httptest.NewRecorder()
	v.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("secret-envelope"))
	})).ServeHTTP(w, r.WithContext(ctx))
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "secret-envelope") {
		t.Fatal("canceled admission exposed its response", w.Code, w.Body.String())
	}
}

func TestAdmissionBufferCapacityHonorsCancellation(t *testing.T) {
	const master = "https://master.example"
	for i := 0; i < cap(keyAdmissionSlots); i++ {
		keyAdmissionSlots <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(keyAdmissionSlots); i++ {
			<-keyAdmissionSlots
		}
	}()
	v, _, _ := fixtureVerifier(t, master)
	r := signedFixture(t, master)
	ctx, cancel := context.WithCancel(r.Context())
	cancel()
	w := httptest.NewRecorder()
	called := false
	v.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(w, r.WithContext(ctx))
	if w.Code != http.StatusServiceUnavailable || called {
		t.Fatal("canceled request acquired a buffer slot", w.Code, called)
	}
}

func TestKeyAdmissionHasIndependentCapacity(t *testing.T) {
	const master = "https://master.example"
	for i := 0; i < cap(businessAdmissionSlots); i++ {
		businessAdmissionSlots <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(businessAdmissionSlots); i++ {
			<-businessAdmissionSlots
		}
	}()
	v, _, _ := fixtureVerifier(t, master)
	w := httptest.NewRecorder()
	v.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(w, signedFixture(t, master))
	if w.Code != http.StatusNoContent {
		t.Fatal("catalog traffic starved key admission", w.Code)
	}
}

func TestAdmissionBufferLimitsByRoute(t *testing.T) {
	const master = "https://master.example"
	for _, test := range []struct {
		name, method, path string
		size               int
		want               int
	}{
		{"key limit", http.MethodPost, "/api/v1/media/crypto/session", maxKeyResponse + 1, http.StatusServiceUnavailable},
		{"native source admission", http.MethodPost, "/api/v1/media/crypto/native/source", 64, http.StatusOK},
		{"native source limit", http.MethodPost, "/api/v1/media/crypto/native/source", maxKeyResponse + 1, http.StatusServiceUnavailable},
		{"lyric metadata admission", http.MethodGet, "/api/v1/media/lyrics/content", maxKeyResponse + 1, http.StatusOK},
		{"lyric metadata limit", http.MethodGet, "/api/v1/media/lyrics/content", maxBusinessResponse + 1, http.StatusServiceUnavailable},
		{"large catalog", http.MethodGet, "/api/v1/media/catalog/media", maxKeyResponse + 1, http.StatusOK},
		{"catalog limit", http.MethodGet, "/api/v1/media/catalog/media", maxBusinessResponse + 1, http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			v, _, _ := fixtureVerifier(t, master)
			w := httptest.NewRecorder()
			v.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-Secret", "must-not-escape-on-error")
				_, _ = w.Write(bytes.Repeat([]byte("x"), test.size))
			})).ServeHTTP(w, signedFixtureFor(t, master, test.method, test.path))
			if w.Code != test.want {
				t.Fatalf("status: %d, want %d", w.Code, test.want)
			}
			if test.want != http.StatusOK && (w.Header().Get("X-Secret") != "" || w.Body.Len() > 128) {
				t.Fatal("oversized response was exposed")
			}
		})
	}
}

func TestAdmissionRollsBackCreatedSessionOnEveryUncommittedExit(t *testing.T) {
	const master = "https://master.example"
	for _, scenario := range []string{"success", "commit failure", "canceled", "canceled during commit", "overflow", "error status", "recovered panic", "panic"} {
		t.Run(scenario, func(t *testing.T) {
			v, _, current := fixtureVerifier(t, master)
			request := signedFixture(t, master)
			ctx, cancel := context.WithCancel(request.Context())
			defer cancel()
			request = request.WithContext(ctx)
			if scenario == "commit failure" {
				current.commitErr = errors.New("disconnected")
			}
			if scenario == "canceled during commit" {
				current.onCommit = cancel
			}
			var aborted atomic.Int32
			handler := v.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				present, registered := network.RegisterPublicAdmissionAbort(r.Context(), func() { aborted.Add(1) })
				if !present || !registered {
					t.Fatal("missing trusted admission")
				}
				w.Header().Set("Set-Cookie", "must-not-escape")
				switch scenario {
				case "canceled":
					cancel()
				case "overflow":
					_, _ = w.Write(bytes.Repeat([]byte("x"), maxKeyResponse+1))
					return
				case "error status":
					w.WriteHeader(http.StatusBadRequest)
				case "recovered panic":
					// A framework recovery can swallow a panic after it has already
					// written 200; the inner boundary reports it through context.
					_, _ = w.Write([]byte("must-not-escape"))
					network.AbortPublicAdmission(r.Context())
					return
				case "panic":
					panic("handler failed")
				}
				_, _ = w.Write([]byte("must-not-escape"))
			}))
			w := httptest.NewRecorder()
			panicked := false
			func() {
				defer func() { panicked = recover() != nil }()
				handler.ServeHTTP(w, request)
			}()
			if scenario == "panic" {
				if !panicked || aborted.Load() != 1 || w.Body.Len() != 0 || w.Header().Get("Set-Cookie") != "" {
					t.Fatal("panic exposed or stranded an uncommitted authorization")
				}
				return
			}
			if panicked {
				t.Fatal("unexpected panic")
			}
			if scenario == "success" {
				if w.Code != http.StatusOK || aborted.Load() != 0 || w.Body.String() != "must-not-escape" {
					t.Fatal("successful admission was rolled back", w.Code, aborted.Load())
				}
				return
			}
			if w.Code != http.StatusServiceUnavailable || aborted.Load() != 1 || strings.Contains(w.Body.String(), "must-not-escape") || w.Header().Get("Set-Cookie") != "" {
				t.Fatal("failed admission exposed or stranded an authorization", w.Code, aborted.Load())
			}
		})
	}
}

func TestAdmissionPreservesOrdinaryHandlerError(t *testing.T) {
	const master = "https://master.example"
	v, _, _ := fixtureVerifier(t, master)
	w := httptest.NewRecorder()
	v.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	})).ServeHTTP(w, signedFixture(t, master))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "bad request") {
		t.Fatal("ordinary client error changed", w.Code)
	}
}

func TestAllBufferedRoutesDiscardResponseOnLeaseFailure(t *testing.T) {
	const master = "https://master.example"
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/media/crypto/session"},
		{http.MethodPost, "/api/v1/media/crypto/key"},
		{http.MethodGet, "/api/v1/media/catalog/categories"},
		{http.MethodGet, "/api/v1/media/catalog/media"},
		{http.MethodGet, "/api/v1/media/metadata"},
	} {
		t.Run(route.path, func(t *testing.T) {
			v, _, current := fixtureVerifier(t, master)
			current.commitErr = errors.New("disconnected")
			w := httptest.NewRecorder()
			v.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-Secret", "must-not-escape")
				_, _ = w.Write([]byte("must-not-escape"))
			})).ServeHTTP(w, signedFixtureFor(t, master, route.method, route.path))
			if w.Code != http.StatusServiceUnavailable || w.Header().Get("X-Secret") != "" || strings.Contains(w.Body.String(), "must-not-escape") {
				t.Fatal("buffered route exposed a response after lease failure", w.Code)
			}
		})
	}
}

func TestPlaybackAdmissionCommitsBeforeHandlerAndDrains(t *testing.T) {
	const master = "https://master.example"
	v, _, current := fixtureVerifier(t, master)
	entered, finish := make(chan struct{}), make(chan struct{})
	completed := make(chan int, 1)
	handler := v.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-finish
		w.WriteHeader(http.StatusNoContent)
	}))
	req := signedFixtureFor(t, master, http.MethodPost, "/api/v1/media/playback")
	go func() { w := httptest.NewRecorder(); handler.ServeHTTP(w, req); completed <- w.Code }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("admitted handler did not start")
	}
	switched := make(chan struct{})
	go func() {
		current.set(store.PublicIngress{NodeID: testPeerID, PublicOrigin: "https://entry.example", Generation: 10}, nil)
		close(switched)
	}()
	select {
	case <-switched:
	case <-time.After(5 * time.Second):
		t.Fatal("admitted operation blocked selection")
	}
	close(finish)
	if code := <-completed; code != http.StatusNoContent {
		t.Fatal("admitted operation did not drain", code)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, signedFixtureFor(t, master, http.MethodPost, "/api/v1/media/playback"))
	if w.Code != http.StatusForbidden {
		t.Fatal("stale generation started a new operation", w.Code)
	}
}

func TestMutationAdmissionFailureDoesNotRunHandler(t *testing.T) {
	const master = "https://master.example"
	for _, path := range []string{"/api/v1/media/playback", "/api/v1/media/crypto/revoke"} {
		t.Run(path, func(t *testing.T) {
			v, _, current := fixtureVerifier(t, master)
			current.commitErr = errors.New("connection lost")
			called := false
			w := httptest.NewRecorder()
			v.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(w, signedFixtureFor(t, master, http.MethodPost, path))
			if called || w.Code != http.StatusServiceUnavailable {
				t.Fatal("mutation ran without committed admission", called, w.Code)
			}
		})
	}
}

func TestAuthenticatedProxyEndToEndAndSourceIsolation(t *testing.T) {
	var calls atomic.Int32
	var verifiedSource, verifiedCookie, verifiedAuthorization string
	// The server's actual origin is known only after startup, so its handler is installed before first use.
	var wrapped atomic.Value
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { wrapped.Load().(http.Handler).ServeHTTP(w, r) }))
	defer server.Close()
	v, _, current := fixtureVerifier(t, server.URL)
	wrapped.Store(v.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resolver, _ := network.New([]string{"127.0.0.0/8", "192.0.2.0/24"})
		identity := resolver.Resolve(r)
		verifiedSource = identity.IP
		assertion, ok := network.AuthenticatedIngressFromContext(r.Context())
		if !ok || assertion.NodeID != testPeerID || assertion.Generation != 9 || assertion.PublicOrigin != "https://entry.example" || identity.PeerIP != "127.0.0.1" || !identity.FromAuthenticatedIngress || identity.FromTrustedProxy || identity.TrustedHeaderMissing {
			t.Error("wrong verified ingress context", identity, assertion)
		}
		verifiedCookie = r.Header.Get("Cookie")
		verifiedAuthorization = r.Header.Get("Authorization")
		if r.Header.Get("X-Fc-Public-Ingress") != "" || r.Header.Get("X-Node-Signature") != "" || r.Header.Get("X-Real-Ip") != "" {
			t.Error("identity headers reached business handler")
		}
		calls.Add(1)
		_, _ = io.WriteString(w, "authorized")
	})))
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	h, err := New(Config{MasterOrigin: server.URL, PublicOrigin: "https://entry.example", RootCAs: roots, Peer: &PeerConfig{NodeID: testPeerID, Generation: 9, Signer: fixtureSigner{}}})
	if err != nil {
		t.Fatal(err)
	}
	defer h.transport.CloseIdleConnections()
	req := incoming("POST", "/api/v1/media/crypto/session", strings.NewReader(`{}`))
	req.TLS = &tls.ConnectionState{}
	req.RemoteAddr = "192.0.2.10:1234"
	req.Header.Set("Origin", "https://entry.example")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Cookie", "admin=secret; frontiercloud_browser_crypto=browser")
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("X-Real-IP", "127.0.0.1")
	req.Header.Set("X-Fc-Public-Ingress", "forged")
	w := newRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 || w.Body.String() != "authorized" || calls.Load() != 1 {
		t.Fatalf("forwarding: %d %q %d", w.Code, w.Body.String(), calls.Load())
	}
	if verifiedSource != "192.0.2.10" || verifiedCookie != "frontiercloud_browser_crypto=browser" || verifiedAuthorization != "" {
		t.Fatalf("untrusted context: %s %q %q", verifiedSource, verifiedCookie, verifiedAuthorization)
	}
	current.set(store.PublicIngress{NodeID: testPeerID, PublicOrigin: "https://entry.example", Generation: 10}, nil)
	req = incoming("POST", "/api/v1/media/crypto/session", strings.NewReader(`{}`))
	req.TLS = &tls.ConnectionState{}
	req.RemoteAddr = "192.0.2.10:1234"
	w = newRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 403 || calls.Load() != 1 {
		t.Fatalf("stale ingress accepted: %d", w.Code)
	}
	current.set(active(), errors.New("database unavailable"))
	req = incoming("POST", "/api/v1/media/crypto/session", strings.NewReader(`{}`))
	req.TLS = &tls.ConnectionState{}
	req.RemoteAddr = "192.0.2.10:1234"
	w = newRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 403 || calls.Load() != 1 {
		t.Fatalf("failed state read accepted: %d", w.Code)
	}
}

func TestProofBindsRequestAndCurrentIngress(t *testing.T) {
	const master = "https://master.example"
	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"body", func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(`{"public_key":"different"}`)) }},
		{"query", func(r *http.Request) { r.URL.RawQuery = "x=2" }},
		{"path", func(r *http.Request) { r.URL.Path = "/api/v1/media/crypto/key" }},
		{"cookie", func(r *http.Request) { r.Header.Set("Cookie", "frontiercloud_browser_crypto=other") }},
		{"origin", func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }},
		{"fetch metadata", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "none") }},
		{"source", func(r *http.Request) { r.Header.Set("X-Fc-Public-Client-Ip", "192.0.2.11") }},
		{"generation", func(r *http.Request) { r.Header.Set("X-Fc-Public-Generation", "10") }},
		{"ingress", func(r *http.Request) { r.Header.Set("X-Fc-Public-Ingress", strings.Repeat("c", 32)) }},
		{"version", func(r *http.Request) { r.Header.Set("X-Fc-Public-Version", "2") }},
		{"host", func(r *http.Request) { r.Host = "evil.example" }},
		{"body too large", func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", maxRequestBody+1)))
			r.ContentLength = -1
		}},
		{"no TLS", func(r *http.Request) { r.TLS = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, _, _ := fixtureVerifier(t, master)
			var called bool
			handler := v.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
			r := signedFixture(t, master)
			tc.mutate(r)
			w := newRecorder()
			handler.ServeHTTP(w, r)
			if called || w.Code < 400 {
				t.Errorf("tampered request accepted: %d", w.Code)
			}
		})
	}
	for _, tc := range []struct {
		name  string
		state store.PublicIngress
		err   error
	}{
		{"old generation", store.PublicIngress{NodeID: testPeerID, Generation: 10, PublicOrigin: "https://entry.example"}, nil},
		{"old node", store.PublicIngress{NodeID: strings.Repeat("d", 32), Generation: 9, PublicOrigin: "https://entry.example"}, nil},
		{"origin changed", store.PublicIngress{NodeID: testPeerID, Generation: 9, PublicOrigin: "https://other.example"}, nil},
		{"store failed", store.PublicIngress{}, errors.New("unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, _, state := fixtureVerifier(t, master)
			state.set(tc.state, tc.err)
			called := false
			w := newRecorder()
			v.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(w, signedFixture(t, master))
			if called || w.Code != 403 {
				t.Errorf("unavailable or stale state accepted: %d", w.Code)
			}
		})
	}
}

func TestVerifierRejectsPreexistingIngressContext(t *testing.T) {
	const master = "https://master.example"
	v, _, _ := fixtureVerifier(t, master)
	request := signedFixture(t, master)
	ctx, err := network.WithAuthenticatedIngress(request.Context(), network.AuthenticatedIngress{
		NodeID: strings.Repeat("c", 32), Generation: 4, PublicOrigin: "https://evil.example", ClientIP: "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	request = request.WithContext(ctx)
	called := false
	w := newRecorder()
	v.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(w, request)
	if called || w.Code != http.StatusForbidden {
		t.Fatalf("preexisting assertion accepted: called=%v status=%d", called, w.Code)
	}
}

func TestNodeNonceReplayAndRelationEligibility(t *testing.T) {
	const master = "https://master.example"
	v, auth, _ := fixtureVerifier(t, master)
	called := 0
	handler := v.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called++ }))
	r := signedFixture(t, master)
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	duplicate := r.Clone(r.Context())
	duplicate.Body = io.NopCloser(bytes.NewReader(body))
	w := newRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 200 || called != 1 {
		t.Fatalf("valid proof rejected: %d", w.Code)
	}
	w = newRecorder()
	handler.ServeHTTP(w, duplicate)
	if w.Code != 403 || called != 1 {
		t.Fatalf("replay accepted: %d", w.Code)
	}
	for _, rel := range []store.Relationship{
		{PeerID: testPeerID, Direction: "upstream", State: "active", Protocol: protocol.Version},
		{PeerID: testPeerID, Direction: "downstream", State: "revoked", Protocol: protocol.Version},
		{PeerID: testPeerID, Direction: "downstream", State: "active", Protocol: 0},
		{PeerID: strings.Repeat("d", 32), Direction: "downstream", State: "active", Protocol: protocol.Version},
	} {
		auth.relationship = rel
		w = newRecorder()
		handler.ServeHTTP(w, signedFixture(t, master))
		if w.Code != 403 || called != 1 {
			t.Errorf("ineligible relation accepted: %+v status %d", rel, w.Code)
		}
	}
}

func TestSignerRejectsUntrustedTransportAndVerifierBlocksNonPublic(t *testing.T) {
	seal, err := peerSeal(&PeerConfig{NodeID: testPeerID, Generation: 9, Signer: fixtureSigner{}}, &url.URL{Scheme: "https", Host: "master.example"}, &url.URL{Scheme: "https", Host: "entry.example"})
	if err != nil {
		t.Fatal(err)
	}
	in := incoming("POST", "/api/v1/media/crypto/key", strings.NewReader(`{}`))
	in.RemoteAddr = "192.0.2.1:10"
	in.Header.Set("X-Forwarded-Proto", "https")
	in.Header.Set("X-Real-Ip", "192.0.2.2")
	out := incoming("POST", "/api/v1/media/crypto/key", strings.NewReader(`{}`))
	if err = seal(context.Background(), out, []byte(`{}`), in); err == nil {
		t.Fatal("untrusted forwarded identity accepted")
	}
	in.TLS = &tls.ConnectionState{}
	in.RemoteAddr = "[::ffff:0:0]:10"
	if err = seal(context.Background(), out, []byte(`{}`), in); err == nil {
		t.Fatal("mapped unspecified browser identity accepted")
	}
	v, _, _ := fixtureVerifier(t, "https://master.example")
	handler := v.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unapproved route reached") }))
	for _, target := range []string{"/api/v1/media/admin/nodes", "/internal/v1/identity", "/api/v1/media/stream", "/api/v1/media/crypto/bytes"} {
		r := signedFixture(t, "https://master.example")
		r.URL.Path = target
		w := newRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Errorf("%s: %d", target, w.Code)
		}
	}
	for _, gen := range []string{"0", "+9", "09", strconv.FormatUint(^uint64(0), 10)} {
		r := signedFixture(t, "https://master.example")
		r.Header.Set("X-Fc-Public-Generation", gen)
		w := newRecorder()
		handler.ServeHTTP(w, r)
		if w.Code < 400 {
			t.Errorf("invalid generation %q", gen)
		}
	}
}

func TestLoopGuardAndTrustedEdgeIdentity(t *testing.T) {
	if _, err := New(Config{MasterOrigin: "https://entry.example", PublicOrigin: "https://entry.example", Peer: &PeerConfig{NodeID: testPeerID, Generation: 9, Signer: fixtureSigner{}}}); err == nil {
		t.Fatal("self target accepted")
	}
	h, err := New(Config{MasterOrigin: "https://master.example", PublicOrigin: "https://entry.example", Peer: &PeerConfig{NodeID: testPeerID, Generation: 9, Signer: fixtureSigner{}, TrustedProxyNetworks: []string{"10.0.0.0/8"}}})
	if err != nil {
		t.Fatal(err)
	}
	req := incoming("GET", "/api/v1/media/catalog/media", nil)
	req.Header.Set("X-Fc-Public-Hop", "1")
	w := newRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("loop marker accepted: %d", w.Code)
	}
	in := incoming("POST", "/api/v1/media/crypto/key", strings.NewReader(`{}`))
	in.RemoteAddr = "10.1.2.3:444"
	in.Header.Set("X-Real-IP", "192.0.2.17")
	in.Header.Set("X-Forwarded-Proto", "https")
	out := incoming("POST", "/api/v1/media/crypto/key", strings.NewReader(`{}`))
	err = h.seal(context.Background(), out, []byte(`{}`), in)
	if err != nil || out.Header.Get("X-Fc-Public-Client-Ip") != "192.0.2.17" {
		t.Fatalf("trusted edge failed: %v %v", err, out.Header)
	}
	in.Header.Add("X-Real-IP", "192.0.2.18")
	if err := h.seal(context.Background(), out, []byte(`{}`), in); err == nil {
		t.Fatal("ambiguous trusted-edge source accepted")
	}
}

func TestTypedNilConfigurationFailsClosed(t *testing.T) {
	var signer *fixtureSigner
	if _, err := New(Config{MasterOrigin: "https://master.example", PublicOrigin: "https://entry.example", Peer: &PeerConfig{NodeID: testPeerID, Generation: 9, Signer: signer}}); err == nil {
		t.Fatal("nil signer accepted")
	}
	var auth *fixtureAuthenticator
	if _, err := NewVerifier(VerifierConfig{MasterOrigin: "https://master.example", Authenticator: auth, Current: &fixtureCurrent{}}); err == nil {
		t.Fatal("nil authenticator accepted")
	}
}

func TestCurrentIngressLeaseOrdersRequestsAndSelection(t *testing.T) {
	const master = "https://master.example"
	v, _, current := fixtureVerifier(t, master)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan int, 1)
	handler := v.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { close(entered); <-release; w.WriteHeader(200) }))
	go func() { w := newRecorder(); handler.ServeHTTP(w, signedFixture(t, master)); done <- w.Code }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not acquire lease")
	}
	attempted := make(chan struct{})
	committed := make(chan struct{})
	go func() {
		close(attempted)
		current.set(store.PublicIngress{NodeID: testPeerID, Generation: 10, PublicOrigin: "https://entry.example"}, nil)
		close(committed)
	}()
	<-attempted
	select {
	case <-committed:
		t.Fatal("selection committed while old request held lease")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case status := <-done:
		if status != 200 {
			t.Errorf("accepted request: %d", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request did not finish")
	}
	select {
	case <-committed:
	case <-time.After(5 * time.Second):
		t.Fatal("selection did not proceed")
	}
	after := newRecorder()
	handler.ServeHTTP(after, signedFixture(t, master))
	if after.Code != 403 {
		t.Fatalf("old generation accepted after selection: %d", after.Code)
	}
}

func TestRelationshipAuthenticationHoldsIngressLease(t *testing.T) {
	v, auth, current := fixtureVerifier(t, "https://master.example")
	v.auth = leaseCheckingAuthenticator{current: current, next: auth}
	w := httptest.NewRecorder()
	v.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(w, signedFixture(t, "https://master.example"))
	if w.Code != http.StatusNoContent {
		t.Fatalf("request was not authenticated under the ingress lease: %d", w.Code)
	}
}

func TestCanonicalConfiguredOrigins(t *testing.T) {
	for raw, want := range map[string]string{
		"https://MASTER.example:443/":     "https://master.example",
		"https://例子.测试/":                  "https://xn--fsqu00a.xn--0zwm56d",
		"https://[::ffff:192.0.2.10]:443": "https://192.0.2.10",
	} {
		got, err := origin(raw)
		if err != nil || got.String() != want {
			t.Errorf("origin %q: %v %v", raw, got, err)
		}
	}
}
