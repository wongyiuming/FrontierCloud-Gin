package publicproxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestRecordingTicketDormantAndAuthenticatedAcrossTLS(t *testing.T) {
	var wrapped atomic.Value
	server := httptest.NewTLSServer(http.StripPrefix(EdgePrefix, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped.Load().(http.Handler).ServeHTTP(w, r)
	})))
	defer server.Close()
	v, _, current := fixtureVerifier(t, server.URL)
	var calls atomic.Int32
	wrapped.Store(v.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		identity, ok := network.AuthenticatedIngressFromContext(r.Context())
		if !ok || identity.ClientIP != "192.0.2.10" || r.Header.Get("X-Karaoke-CSRF") != "csrf-proof" || r.Header.Get("Authorization") != "" {
			t.Errorf("untrusted recording context: %#v %v", identity, r.Header)
		}
		if r.Header.Get("Cookie") != "frontiercloud_browser_crypto=browser; __Host-karaoke_session=session; __Host-karaoke_csrf=csrf" {
			t.Errorf("unexpected forwarded cookies: %q", r.Header.Get("Cookie"))
		}
		body, err := io.ReadAll(r.Body)
		wantBytes := store.MaxRecordingMetadata + 8192
		if r.URL.Path == recordingAudioPreparePath || strings.HasSuffix(r.URL.Path, "/audio-complete") {
			wantBytes = 2
		}
		if strings.HasSuffix(r.URL.Path, "/audio-complete") && r.Header.Get(recordingSessionHeader) != testPeerID {
			t.Error("recording session not forwarded")
		}
		if err != nil || len(body) != wantBytes {
			t.Errorf("incorrect recording request body: %d %v", len(body), err)
		}
		http.SetCookie(w, &http.Cookie{Name: "admin", Value: "must-not-escape", Path: "/", Secure: true})
		w.Header().Set("X-Internal-Secret", "must-not-escape")
		_, _ = io.WriteString(w, `{"recording_id":"fixture"}`)
	})))
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	h, err := New(Config{MasterOrigin: server.URL, PublicOrigin: "https://entry.example", RootCAs: roots, MasterEdge: true, Peer: &PeerConfig{NodeID: testPeerID, Generation: 9, Signer: fixtureSigner{}}})
	if err != nil {
		t.Fatal(err)
	}
	defer h.CloseIdleConnections()
	request := func(size int) *http.Request {
		r := incoming(http.MethodPost, recordingTicketPath, strings.NewReader(strings.Repeat("x", size)))
		r.TLS = &tls.ConnectionState{}
		r.RemoteAddr = "192.0.2.10:1234"
		r.Header.Set("Origin", "https://entry.example")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Karaoke-CSRF", "csrf-proof")
		r.Header.Set("Cookie", "admin=must-not-forward; __Host-karaoke_session=session; __Host-karaoke_csrf=csrf; frontiercloud_browser_crypto=browser")
		r.Header.Set("Authorization", "Bearer must-not-forward")
		return r
	}
	audioPrepare := func(size int) *http.Request {
		r := request(size)
		r.URL.Path = recordingAudioPreparePath
		return r
	}
	call := func(r *http.Request) *testResponseRecorder {
		w := newRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	limit := store.MaxRecordingMetadata + 8192
	if w := call(request(limit)); w.Code != http.StatusServiceUnavailable || calls.Load() != 0 {
		t.Fatalf("dormant ingress issued ticket: %d", w.Code)
	}
	if w := call(audioPrepare(2)); w.Code != http.StatusServiceUnavailable || calls.Load() != 0 {
		t.Fatalf("dormant ingress forwarded recording preparation: %d", w.Code)
	}
	h.recordingTicketReady = true
	if w := call(request(limit)); w.Code != http.StatusServiceUnavailable || calls.Load() != 0 {
		t.Fatalf("dormant Master issued ticket: %d", w.Code)
	}
	if w := call(audioPrepare(2)); w.Code != http.StatusServiceUnavailable || calls.Load() != 0 {
		t.Fatalf("dormant Master admitted recording preparation: %d", w.Code)
	}
	v.recordingTicketReady = true
	if w := call(request(limit)); w.Code != http.StatusOK || calls.Load() != 1 || w.Header().Get("Cache-Control") != "private, no-store" || w.Header().Get("X-Internal-Secret") != "" || len(w.Result().Cookies()) != 0 {
		t.Fatalf("ticket response: %d calls=%d headers=%v", w.Code, calls.Load(), w.Header())
	}
	if w := call(request(limit + 1)); w.Code != http.StatusRequestEntityTooLarge || calls.Load() != 1 {
		t.Fatalf("oversize ticket forwarded: %d calls=%d", w.Code, calls.Load())
	}
	unknownLength := request(limit + 1)
	unknownLength.ContentLength = -1
	if w := call(unknownLength); w.Code != http.StatusRequestEntityTooLarge || calls.Load() != 1 {
		t.Fatalf("oversize unknown-length ticket forwarded: %d calls=%d", w.Code, calls.Load())
	}
	duplicate := request(1)
	duplicate.Header.Set("Cookie", "__Host-karaoke_session=a; __Host-karaoke_session=b")
	if w := call(duplicate); w.Code != http.StatusBadRequest || calls.Load() != 1 {
		t.Fatalf("duplicate account credential accepted: %d calls=%d", w.Code, calls.Load())
	}
	duplicateCSRF := request(1)
	duplicateCSRF.Header.Add("X-Karaoke-CSRF", "another")
	if w := call(duplicateCSRF); w.Code != http.StatusForbidden || calls.Load() != 1 {
		t.Fatalf("duplicate CSRF accepted: %d calls=%d", w.Code, calls.Load())
	}
	if w := call(audioPrepare(maxRequestBody + 1)); w.Code != http.StatusRequestEntityTooLarge || calls.Load() != 1 {
		t.Fatalf("oversize preparation forwarded: %d calls=%d", w.Code, calls.Load())
	}
	if w := call(audioPrepare(2)); w.Code != http.StatusOK || calls.Load() != 2 || w.Header().Get("Cache-Control") != "private, no-store" || w.Header().Get("X-Internal-Secret") != "" || len(w.Result().Cookies()) != 0 {
		t.Fatalf("recording preparation response: %d calls=%d", w.Code, calls.Load())
	}
	complete := func() *http.Request {
		r := request(2)
		r.URL.Path = recordingsPath + "/" + testPeerID + "/audio-complete"
		return r
	}
	if w := call(complete()); w.Code != http.StatusForbidden || calls.Load() != 2 {
		t.Fatalf("missing recording session forwarded: %d calls=%d", w.Code, calls.Load())
	}
	duplicateSession := complete()
	duplicateSession.Header.Add(recordingSessionHeader, testPeerID)
	duplicateSession.Header.Add(recordingSessionHeader, testPeerID)
	if w := call(duplicateSession); w.Code != http.StatusForbidden || calls.Load() != 2 {
		t.Fatalf("duplicate recording session forwarded: %d calls=%d", w.Code, calls.Load())
	}
	ready := complete()
	ready.Header.Set(recordingSessionHeader, testPeerID)
	if w := call(ready); w.Code != http.StatusOK || calls.Load() != 3 {
		t.Fatalf("recording completion response: %d calls=%d", w.Code, calls.Load())
	}
	current.set(store.PublicIngress{NodeID: testPeerID, PublicOrigin: "https://entry.example", Generation: 10}, nil)
	if w := call(request(1)); w.Code != http.StatusForbidden || calls.Load() != 3 {
		t.Fatalf("stale ingress issued ticket: %d calls=%d", w.Code, calls.Load())
	}
	if w := call(audioPrepare(2)); w.Code != http.StatusForbidden || calls.Load() != 3 {
		t.Fatalf("stale ingress issued recording preparation: %d calls=%d", w.Code, calls.Load())
	}
}

func TestRecordingTicketSlotsDoNotStarveOtherRoutes(t *testing.T) {
	recordingTicketIngressSlot <- struct{}{}
	defer func() { <-recordingTicketIngressSlot }()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	h := testProxy(t, server)
	h.recordingTicketReady = true
	if w := invoke(h, http.MethodPost, recordingTicketPath, "{}"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("ticket limit not enforced: %d", w.Code)
	}
	if w := invoke(h, http.MethodPost, "/api/v1/media/network-observation", "{}"); w.Code != http.StatusNoContent {
		t.Fatalf("ticket occupied observation capacity: %d", w.Code)
	}

	recordingTicketMasterSlot <- struct{}{}
	defer func() { <-recordingTicketMasterSlot }()
	v, _, _ := fixtureVerifier(t, "https://master.example")
	v.recordingTicketReady = true
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	})
	w := newRecorder()
	v.Wrap(next).ServeHTTP(w, signedFixtureFor(t, "https://master.example", http.MethodPost, recordingTicketPath))
	if reached || w.Code != http.StatusServiceUnavailable {
		t.Fatalf("Master ticket limit not enforced: %d", w.Code)
	}
	w = newRecorder()
	v.Wrap(next).ServeHTTP(w, signedFixtureFor(t, "https://master.example", http.MethodPost, "/api/v1/media/playback"))
	if !reached || w.Code != http.StatusNoContent {
		t.Fatalf("ticket occupied playback capacity: %d", w.Code)
	}
}

func TestRecordingTicketUsesIndependentPoolsAndTransport(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	h := testProxy(t, server)
	defer h.CloseIdleConnections()
	h.recordingTicketReady = true
	if h.ticketTransport == h.transport || h.ticketTransport.ResponseHeaderTimeout != recordingTicketTimeout {
		t.Fatal("ticket shares the short ordinary response deadline")
	}
	for i := 0; i < cap(h.bodies); i++ {
		h.bodies <- struct{}{}
	}
	for i := 0; i < cap(h.keys); i++ {
		h.keys <- struct{}{}
	}
	for i := 0; i < cap(h.keyResponses); i++ {
		h.keyResponses <- struct{}{}
	}
	if w := invoke(h, http.MethodPost, recordingTicketPath, "{}"); w.Code != http.StatusNoContent {
		t.Fatalf("ordinary pool saturation blocked isolated ticket: %d", w.Code)
	}
}

func TestRecordingTicketRequiresMasterReadDeadlineAndDoesNotRetry(t *testing.T) {
	v, _, _ := fixtureVerifier(t, "https://master.example")
	v.recordingTicketReady = true
	reached := false
	w := httptest.NewRecorder() // Does not support SetReadDeadline.
	v.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })).ServeHTTP(
		w, signedFixtureFor(t, "https://master.example", http.MethodPost, recordingTicketPath),
	)
	if reached || w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unbounded Master ticket read accepted: %d", w.Code)
	}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		panic(http.ErrAbortHandler) // Commit outcome is unknown to the caller.
	}))
	defer server.Close()
	h := testProxy(t, server)
	defer h.CloseIdleConnections()
	h.recordingTicketReady = true
	if got := invoke(h, http.MethodPost, recordingTicketPath, "{}"); got.Code != http.StatusBadGateway || calls.Load() != 1 {
		t.Fatalf("uncertain ticket was retried or accepted: %d calls=%d", got.Code, calls.Load())
	}
}

func TestRecordingTicketRejectsTamperedSignedInputs(t *testing.T) {
	const master = "https://master.example"
	for _, change := range []string{"body", "csrf", "cookie", "recording-session"} {
		t.Run(change, func(t *testing.T) {
			v, _, _ := fixtureVerifier(t, master)
			v.recordingTicketReady = true
			path := recordingTicketPath
			if change == "recording-session" {
				path = recordingsPath + "/" + testPeerID + "/audio-complete"
			}
			r := signedFixtureFor(t, master, http.MethodPost, path)
			switch change {
			case "body":
				body := `{"public_key":"abd"}`
				r.Body = io.NopCloser(strings.NewReader(body))
				r.ContentLength = int64(len(body))
			case "csrf":
				r.Header.Set("X-Karaoke-CSRF", "tampered")
			case "cookie":
				r.Header.Set("Cookie", "__Host-karaoke_session=tampered")
			case "recording-session":
				r.Header.Set(recordingSessionHeader, strings.Repeat("b", 32))
			}
			reached := false
			w := newRecorder()
			v.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })).ServeHTTP(w, r)
			if reached || w.Code != http.StatusForbidden {
				t.Fatalf("tampered %s accepted: %d", change, w.Code)
			}
		})
	}
}
