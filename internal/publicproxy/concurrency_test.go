package publicproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// These tests exercise actual browser-to-ingress and ingress-to-Master sockets.
// They use the real signer and TLS transport, while the Master responds directly.
func networkProxy(t *testing.T, master *httptest.Server) (*Handler, *httptest.Server) {
	return networkProxyWrapped(t, master, func(h http.Handler) http.Handler { return h })
}

func networkProxyWrapped(t *testing.T, master *httptest.Server, wrap func(http.Handler) http.Handler) (*Handler, *httptest.Server) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(master.Certificate())
	h, err := New(Config{
		MasterOrigin: master.URL,
		PublicOrigin: "https://entry.example",
		RootCAs:      roots,
		Peer:         &PeerConfig{NodeID: testPeerID, Generation: 9, Signer: fixtureSigner{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.CloseIdleConnections)
	entry := httptest.NewTLSServer(wrap(h))
	t.Cleanup(entry.Close)
	return h, entry
}

type blockingNetworkWriter struct {
	http.ResponseWriter
	entered chan<- struct{}
	release <-chan struct{}
}

func (w *blockingNetworkWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *blockingNetworkWriter) Write(p []byte) (int, error) {
	w.entered <- struct{}{}
	<-w.release
	return w.ResponseWriter.Write(p)
}

func networkKeyRequest(ctx context.Context, client *http.Client, entry, query string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, entry+"/api/v1/media/crypto/key"+query, strings.NewReader(`{}`))
	if err != nil {
		return nil, err
	}
	req.Host = "entry.example"
	return client.Do(req)
}

func waitForSlots(t *testing.T, name string, slots chan struct{}, want int) {
	waitForSlotsWithin(t, name, slots, want, 3*time.Second)
}

func waitForSlotsWithin(t *testing.T, name string, slots chan struct{}, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for len(slots) != want {
		select {
		case <-deadline.C:
			t.Fatalf("%s slots: got %d, want %d", name, len(slots), want)
		case <-tick.C:
		}
	}
}

func TestNetworkSlowBodiesDoNotOccupyKeyCapacity(t *testing.T) {
	master := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer master.Close()
	h, entry := networkProxy(t, master)

	roots := x509.NewCertPool()
	roots.AddCert(entry.Certificate())
	var connections []*tls.Conn
	t.Cleanup(func() {
		for _, conn := range connections {
			_ = conn.Close()
		}
	})
	addPartial := func() {
		conn, err := tls.Dial("tcp", entry.Listener.Addr().String(), &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12})
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
		_, err = fmt.Fprint(conn, "POST /api/v1/media/crypto/key HTTP/1.1\r\nHost: entry.example\r\nContent-Length: 10\r\n\r\n{")
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < keySlots; i++ {
		addPartial()
	}
	waitForSlots(t, "body", h.bodies, keySlots)
	if got := len(h.keys); got != 0 {
		t.Fatalf("incomplete bodies occupied %d key slots", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := networkKeyRequest(ctx, entry.Client(), entry.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil || resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("normal key request: status=%d body=%q error=%v", resp.StatusCode, body, readErr)
	}
	if got := len(h.bodies); got != keySlots {
		t.Fatalf("slow requests did not remain in flight: %d", got)
	}
	// Once every bounded upload slot is occupied, excess uploads fail
	// immediately rather than creating an unbounded number of readers.
	for i := keySlots; i < bodySlots; i++ {
		addPartial()
	}
	waitForSlots(t, "body", h.bodies, bodySlots)
	limited, err := networkKeyRequest(ctx, entry.Client(), entry.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	_, readErr = io.Copy(io.Discard, limited.Body)
	_ = limited.Body.Close()
	if readErr != nil || limited.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("full body admission: status=%d error=%v", limited.StatusCode, readErr)
	}
	for _, conn := range connections[:keySlots] {
		_ = conn.Close()
	}
	waitForSlots(t, "body", h.bodies, bodySlots-keySlots)
	// Remaining stalled bodies must release themselves at the read deadline.
	waitForSlotsWithin(t, "body", h.bodies, 0, bodyReadTimeout+2*time.Second)
}

func TestNetworkPublicAssetWaitsForBusinessCapacity(t *testing.T) {
	const catalog = "/api/v1/media/catalog/media"
	const asset = "/static/js/player.js"
	entered := make(chan struct{}, businessSlots)
	release := make(chan struct{})
	master := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == catalog {
			entered <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(master.Close)
	_, entry := networkProxyWrapped(t, master, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == asset {
				time.AfterFunc(200*time.Millisecond, func() { close(release) })
			}
			next.ServeHTTP(w, r)
		})
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	fetch := func(path string) (int, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, entry.URL+path, nil)
		if err != nil {
			return 0, err
		}
		req.Host = "entry.example"
		resp, err := entry.Client().Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		_, err = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, err
	}
	held := make(chan error, businessSlots)
	for range businessSlots {
		go func() {
			status, err := fetch(catalog)
			if err == nil && status != http.StatusOK {
				err = fmt.Errorf("admitted catalog returned %d", status)
			}
			held <- err
		}()
	}
	for range businessSlots {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("business requests did not reach Master")
		}
	}
	if status, err := fetch(catalog); err != nil || status != http.StatusServiceUnavailable {
		t.Fatalf("saturated business request: status=%d error=%v", status, err)
	}
	if status, err := fetch(asset); err != nil || status != http.StatusOK {
		t.Fatalf("player asset under transient saturation: status=%d error=%v", status, err)
	}
	for range businessSlots {
		select {
		case err := <-held:
			if err != nil {
				t.Error(err)
			}
		case <-ctx.Done():
			t.Fatal("released business request did not finish")
		}
	}
}

func TestPublicAssetWaitersAreBoundedAndCanceled(t *testing.T) {
	h := &Handler{
		business:     make(chan struct{}, businessSlots),
		assetWaiters: make(chan struct{}, assetWaitSlots),
	}
	for range businessSlots {
		h.business <- struct{}{}
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan bool, assetWaitSlots)
	for range assetWaitSlots {
		go func() { done <- h.waitForAssetSlot(ctx) }()
	}
	waitForSlotsWithin(t, "asset waiters", h.assetWaiters, assetWaitSlots, assetQueueTimeout/2)
	overflowCtx, expire := context.WithTimeout(t.Context(), assetQueueTimeout/2)
	defer expire()
	if h.waitForAssetSlot(overflowCtx) || overflowCtx.Err() != nil {
		t.Fatal("full asset queue must reject without waiting")
	}
	cancel()
	for range assetWaitSlots {
		select {
		case admitted := <-done:
			if admitted {
				t.Fatal("a canceled waiter acquired a business slot")
			}
		case <-overflowCtx.Done():
			t.Fatal("canceled waiters did not stop")
		}
	}
	if len(h.assetWaiters) != 0 || len(h.business) != businessSlots {
		t.Fatal("cancellation changed active capacity or retained waiters")
	}
}

func TestNetworkSlowMasterRequestsDoNotStarveKeyCapacity(t *testing.T) {
	entered := make(chan struct{}, keySlots)
	canceled := make(chan struct{}, keySlots)
	release := make(chan struct{})
	master := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("slow") == "1" {
			_, _ = io.Copy(io.Discard, r.Body)
			entered <- struct{}{}
			select {
			case <-r.Context().Done():
				canceled <- struct{}{}
			case <-release:
			}
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer master.Close()
	defer close(release)
	h, entry := networkProxy(t, master)
	ctx, cancel := context.WithTimeout(context.Background(), keyQueueTimeout+5*time.Second)
	defer cancel()
	slowResults := make(chan error, keySlots)
	for i := 0; i < keySlots; i++ {
		go func() {
			resp, err := networkKeyRequest(ctx, entry.Client(), entry.URL, "?slow=1")
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusBadGateway {
					err = fmt.Errorf("slow request returned %d", resp.StatusCode)
				}
			}
			slowResults <- err
		}()
	}
	for i := 0; i < keySlots; i++ {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("slow requests did not reach Master")
		}
	}
	if got := len(h.keys); got != keySlots {
		t.Fatalf("expected %d occupied key slots, got %d", keySlots, got)
	}
	queuedCtx, cancelQueued := context.WithCancel(ctx)
	defer cancelQueued()
	queuedResult := make(chan error, 1)
	go func() {
		resp, err := networkKeyRequest(queuedCtx, entry.Client(), entry.URL, "")
		if err == nil {
			_ = resp.Body.Close()
			err = fmt.Errorf("canceled request unexpectedly returned %d", resp.StatusCode)
		}
		queuedResult <- err
	}()
	waitForSlots(t, "key response", h.keyResponses, keySlots+1)
	cancelQueued()
	select {
	case err := <-queuedResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("queued request was not canceled: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("canceled client request did not return")
	}
	waitForSlots(t, "key response", h.keyResponses, keySlots)
	if got := len(h.keys); got != keySlots {
		t.Fatalf("slow Master requests ended before cancellation was checked: %d", got)
	}
	resp, err := networkKeyRequest(ctx, entry.Client(), entry.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil || resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("queued key request: status=%d body=%q error=%v", resp.StatusCode, body, readErr)
	}
	for i := 0; i < keySlots; i++ {
		select {
		case err := <-slowResults:
			if err != nil {
				t.Error(err)
			}
		case <-ctx.Done():
			t.Fatal("slow request did not time out")
		}
		select {
		case <-canceled:
		case <-ctx.Done():
			t.Fatal("Master did not observe cancellation")
		}
	}
}

func TestNetworkSlowDownstreamDoesNotOccupyKeyCapacity(t *testing.T) {
	master := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer master.Close()
	entered := make(chan struct{}, keySlots)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	h, entry := networkProxyWrapped(t, master, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("slow") == "1" {
				w = &blockingNetworkWriter{ResponseWriter: w, entered: entered, release: release}
			}
			next.ServeHTTP(w, r)
		})
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	slowResults := make(chan error, keySlots)
	for i := 0; i < keySlots; i++ {
		go func() {
			resp, err := networkKeyRequest(ctx, entry.Client(), entry.URL, "?slow=1")
			if err == nil {
				_, err = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if err == nil && resp.StatusCode != http.StatusOK {
					err = fmt.Errorf("slow response returned %d", resp.StatusCode)
				}
			}
			slowResults <- err
		}()
	}
	for i := 0; i < keySlots; i++ {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("slow downstream writes did not block")
		}
	}
	if got := len(h.keys); got != 0 {
		t.Fatalf("blocked downstream writes retained %d key slots", got)
	}
	if got := len(h.keyResponses); got != keySlots {
		t.Fatalf("expected %d bounded downstream responses, got %d", keySlots, got)
	}
	resp, err := networkKeyRequest(ctx, entry.Client(), entry.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil || resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("normal key request: status=%d body=%q error=%v", resp.StatusCode, body, readErr)
	}
	unblock()
	for i := 0; i < keySlots; i++ {
		select {
		case err := <-slowResults:
			if err != nil {
				t.Error(err)
			}
		case <-ctx.Done():
			t.Fatal("released downstream response did not finish")
		}
	}
}

func TestNetworkKeyResponseSizeBound(t *testing.T) {
	master := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		size := maxKeyResponse
		if r.URL.Query().Get("oversize") == "1" {
			size++
		}
		_, _ = io.WriteString(w, strings.Repeat("x", size))
	}))
	defer master.Close()
	_, entry := networkProxy(t, master)
	for _, tc := range []struct {
		query string
		code  int
		size  int
	}{{"", http.StatusOK, maxKeyResponse}, {"?oversize=1", http.StatusBadGateway, 0}} {
		resp, err := networkKeyRequest(context.Background(), entry.Client(), entry.URL, tc.query)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != tc.code || (tc.size != 0 && len(body) != tc.size) || (tc.size == 0 && len(body) > 100) {
			t.Errorf("query %q: status=%d length=%d error=%v", tc.query, resp.StatusCode, len(body), err)
		}
	}
}
