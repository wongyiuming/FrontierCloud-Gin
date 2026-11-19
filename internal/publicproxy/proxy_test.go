package publicproxy

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testResponseRecorder struct{ *httptest.ResponseRecorder }

func (w *testResponseRecorder) SetReadDeadline(time.Time) error  { return nil }
func (w *testResponseRecorder) SetWriteDeadline(time.Time) error { return nil }
func newRecorder() *testResponseRecorder                         { return &testResponseRecorder{httptest.NewRecorder()} }
func testProxy(t *testing.T, server *httptest.Server) *Handler {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	h, err := New(Config{MasterOrigin: server.URL, PublicOrigin: "https://entry.example", RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	h.seal = func(context.Context, *http.Request, []byte, *http.Request) error { return nil }
	t.Cleanup(h.transport.CloseIdleConnections)
	return h
}

func incoming(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	req.Host = "entry.example"
	return req
}

func invoke(h http.Handler, method, target, body string) *testResponseRecorder {
	req := incoming(method, target, strings.NewReader(body))
	w := newRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestOriginsAndDormantHandler(t *testing.T) {
	for _, bad := range []string{"", "http://master.example", "https://user:password@master.example", "https://master.example/path", "https://master.example?x=1", "https://master.example#x", "https://master.example:", "https://master.example:99999", "https://master.example\\evil", "//master.example", "https://master.example/?"} {
		if _, err := New(Config{MasterOrigin: bad, PublicOrigin: "https://entry.example"}); err == nil {
			t.Errorf("accepted Master origin %q", bad)
		}
		if _, err := New(Config{MasterOrigin: "https://master.example", PublicOrigin: bad}); err == nil {
			t.Errorf("accepted public origin %q", bad)
		}
	}
	h, err := New(Config{MasterOrigin: "https://master.example", PublicOrigin: "https://entry.example"})
	if err != nil {
		t.Fatal(err)
	}
	defer h.transport.CloseIdleConnections()
	if w := invoke(h, "GET", "/api/v1/media/catalog/media", ""); w.Code != 503 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("dormant handler: %d %v", w.Code, w.Header())
	}
}

func TestOnlyExactMethodAndPathAreEligible(t *testing.T) {
	for _, r := range routes {
		req := incoming(r.method, r.path, nil)
		if got, ok := match(req); !ok || got != r {
			t.Errorf("route not matched: %+v", r)
		}
	}
	recording := recordingsPath + "/" + strings.Repeat("a", 32)
	for _, tc := range []struct{ method, path string }{
		{"POST", "/api/v1/media/catalog/media"}, {"GET", "/api/v1/media/crypto/key"},
		{"GET", "/api/v1/media/admin"}, {"GET", "/api/v1/media/admin/nodes"},
		{"POST", "/api/v1/media/admin/elevate"}, {"POST", "/internal/v1/pair"},
		{"GET", "/api/v1/media/stream"}, {"POST", "/api/v1/media/lyrics/content"},
		{"POST", "/api/v1/media/crypto/source"}, {"GET", "/api/v1/media/crypto/bytes"},
		{"GET", "/api/v1/media/catalog/media/"}, {"GET", "/api/v1/media/catalog/%6dedia"},
		{"GET", "/api/v1/media/catalog/../admin"}, {"GET", "/api/v1/media/catalog/media?bad=%ZZ"},
		{"GET", recording + "/audio"}, {"GET", recording + "/content"}, {"PUT", recording + "/audio-upload"},
		{"GET", recording + "/audio-key"}, {"POST", recording}, {"DELETE", recording + "/audio-key"},
		{"POST", recording + "/audio-recover/"}, {"POST", recording + "/audio-complete?"},
		{"DELETE", recording + "?token=hidden"}, {"DELETE", recording + "/pending/"}, {"POST", recording + "/pending"},
		{"POST", recordingsPath + "/" + strings.Repeat("A", 32) + "/audio-key"},
	} {
		req := incoming(tc.method, tc.path, nil)
		if _, ok := match(req); ok {
			t.Errorf("unexpected match %s %s", tc.method, tc.path)
		}
	}
	req := incoming("GET", "/api/v1/media/catalog/media?x="+strings.Repeat("a", maxQuery), nil)
	if _, ok := match(req); ok {
		t.Fatal("oversized query accepted")
	}
}

func TestTLSHeaderBoundaryAndNoStore(t *testing.T) {
	seen := make(chan *http.Request, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Clone(r.Context())
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("X-Accel-Redirect", "/secret")
		w.Header().Set("X-Node-Signature", "secret")
		http.SetCookie(w, &http.Cookie{Name: "admin", Value: "secret", Path: "/", Secure: true})
		http.SetCookie(w, &http.Cookie{Name: "frontiercloud_browser_crypto", Value: "value", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer server.Close()
	h := testProxy(t, server)
	var sealedRemote string
	h.seal = func(_ context.Context, req *http.Request, body []byte, source *http.Request) error {
		sealedRemote, _, _ = net.SplitHostPort(source.RemoteAddr)
		if req.Host != "entry.example" || req.URL.Host != strings.TrimPrefix(server.URL, "https://") || req.URL.RawQuery != "q=one" || string(body) != `{}` {
			t.Error("seal did not receive controlled request")
		}
		return nil
	}
	req := incoming("POST", "/api/v1/media/crypto/session?q=one", strings.NewReader(`{}`))
	req.RemoteAddr = "192.0.2.9:1234"
	req.Header.Set("Origin", "https://entry.example")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Forwarded", "for=127.0.0.1;host=evil")
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Forwarded-Host", "evil")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Real-IP", "127.0.0.1")
	req.Header.Set("X-Node-Relationship", "forged")
	req.Header.Set("X-Ingress-Version", "forged")
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Cookie", "admin=secret; frontiercloud_browser_crypto=browser")
	w := newRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 || w.Body.String() != `{"ok":true}` {
		t.Fatalf("status/body %d %q", w.Code, w.Body.String())
	}
	if sealedRemote != "192.0.2.9" {
		t.Errorf("untrusted source address: %q", sealedRemote)
	}
	got := <-seen
	for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP", "X-Node-Relationship", "X-Ingress-Version", "Authorization"} {
		if got.Header.Get(name) != "" {
			t.Errorf("forwarded %s", name)
		}
	}
	if got.Header.Get("Cookie") != "frontiercloud_browser_crypto=browser" {
		t.Errorf("forwarded cookies: %q", got.Header.Get("Cookie"))
	}
	if got.Header.Get("Origin") != "https://entry.example" {
		t.Errorf("origin lost: %q", got.Header.Get("Origin"))
	}
	if w.Header().Get("Cache-Control") != "private, no-store" || w.Header().Get("X-Accel-Redirect") != "" || w.Header().Get("X-Node-Signature") != "" {
		t.Errorf("unsafe response headers: %v", w.Header())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "frontiercloud_browser_crypto" {
		t.Errorf("unsafe response cookies: %v", cookies)
	}
}

func TestUntrustedTLSRedirectAndBadInputsFailClosed(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("redirect") == "1" {
			http.Redirect(w, r, "https://evil.example/private", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	h := testProxy(t, server)
	if w := invoke(h, "GET", "/api/v1/media/catalog/media?redirect=1", ""); w.Code != 502 || w.Header().Get("Location") != "" || strings.Contains(w.Body.String(), "evil") {
		t.Errorf("unsafe redirect: %d %v %s", w.Code, w.Header(), w.Body.String())
	}
	untrusted, err := New(Config{MasterOrigin: server.URL, PublicOrigin: "https://entry.example"})
	if err != nil {
		t.Fatal(err)
	}
	untrusted.seal = h.seal
	defer untrusted.transport.CloseIdleConnections()
	if w := invoke(untrusted, "GET", "/api/v1/media/catalog/media", ""); w.Code != 502 {
		t.Errorf("untrusted certificate: %d", w.Code)
	}
	for _, tc := range []struct{ name, value string }{
		{"Origin", "https://evil.example"}, {"Origin", "null"}, {"Sec-Fetch-Site", "cross-site"}, {"Connection", "Cookie"},
	} {
		req := incoming("POST", "/api/v1/media/crypto/session", strings.NewReader(`{}`))
		req.Header.Set(tc.name, tc.value)
		w := newRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 403 {
			t.Errorf("accepted %s=%q: %d", tc.name, tc.value, w.Code)
		}
	}
	req := incoming("POST", "/api/v1/media/crypto/session", strings.NewReader(`{}`))
	req.Header.Add("Origin", "https://entry.example")
	req.Header.Add("Origin", "https://evil.example")
	w := newRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Errorf("duplicate origins: %d", w.Code)
	}
	req = incoming("POST", "/api/v1/media/crypto/session", strings.NewReader(strings.Repeat("x", maxRequestBody+1)))
	w = newRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 413 {
		t.Errorf("oversized request: %d", w.Code)
	}
	req = incoming("POST", "/api/v1/media/crypto/session", strings.NewReader(`{}`))
	req.Header.Set("Cookie", "frontiercloud_browser_crypto=a; frontiercloud_browser_crypto=b")
	w = newRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Errorf("ambiguous cookie: %d", w.Code)
	}
	req = incoming("POST", "/api/v1/media/crypto/session", strings.NewReader(`{}`))
	req.Host = "wrong.example"
	w = newRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Errorf("unconfigured host: %d", w.Code)
	}
}

func TestStreamingAndCancellation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	cancelled := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery == "cancel=1" {
			close(started)
			<-r.Context().Done()
			close(cancelled)
			return
		}
		_, _ = io.WriteString(w, "first")
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, "second")
	}))
	defer server.Close()
	h := testProxy(t, server)
	proxy := httptest.NewServer(h)
	defer proxy.Close()
	req, _ := http.NewRequest("GET", proxy.URL+"/api/v1/media/catalog/media", nil)
	req.Host = "entry.example"
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(response.Body, buf); err != nil || string(buf) != "first" {
		t.Fatalf("response did not stream: %q %v", buf, err)
	}
	close(release)
	rest, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(rest) != "second" {
		t.Fatalf("stream remainder: %q %v", rest, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	req, _ = http.NewRequestWithContext(ctx, "GET", proxy.URL+"/api/v1/media/catalog/media?cancel=1", nil)
	req.Host = "entry.example"
	done := make(chan struct{})
	go func() {
		resp, _ := http.DefaultClient.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream not reached")
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not reach upstream")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("client did not stop")
	}
}

func TestSeparateBoundedKeyCapacity(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer server.Close()
	h := testProxy(t, server)
	entered := make(chan struct{}, businessSlots)
	release := make(chan struct{})
	var workers sync.WaitGroup
	h.seal = func(ctx context.Context, r *http.Request, _ []byte, _ *http.Request) error {
		if r.URL.Path == "/api/v1/media/catalog/media" {
			entered <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	for i := 0; i < businessSlots; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); invoke(h, "GET", "/api/v1/media/catalog/media", "") }()
	}
	for i := 0; i < businessSlots; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("business slot not entered")
		}
	}
	if w := invoke(h, "GET", "/api/v1/media/catalog/media", ""); w.Code != 503 {
		t.Errorf("business limit: %d", w.Code)
	}
	if w := invoke(h, "POST", "/api/v1/media/crypto/key", `{}`); w.Code != 200 {
		t.Errorf("key capacity blocked: %d", w.Code)
	}
	close(release)
	workers.Wait()
}

func TestRangePassesWithoutBufferingOrRetargeting(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "bytes=2-4" {
			t.Errorf("range lost: %s", r.Header.Get("Range"))
		}
		w.Header().Set("Content-Range", "bytes 2-4/10")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = io.Copy(w, bytes.NewBufferString("234"))
	}))
	defer server.Close()
	h := testProxy(t, server)
	req := incoming("GET", "/api/v1/media/catalog/media?url=https%3A%2F%2Fevil.example", nil)
	req.Header.Set("Range", "bytes=2-4")
	w := newRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 206 || w.Body.String() != "234" || w.Header().Get("Content-Range") != "bytes 2-4/10" {
		t.Fatal(fmt.Sprintf("range response: %d %q %v", w.Code, w.Body.String(), w.Header()))
	}
}

type measuredReader struct{ reads atomic.Int32 }

func (r *measuredReader) Read(p []byte) (int, error) {
	if r.reads.Add(1) > 2 {
		return 0, io.EOF
	}
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

func (*measuredReader) WriteTo(io.Writer) (int64, error) {
	panic("unbounded fast path must not be used")
}

type blockedWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *blockedWriter) Header() http.Header { return http.Header{} }
func (w *blockedWriter) WriteHeader(int)     {}
func (w *blockedWriter) Flush()              {}
func (w *blockedWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(p), nil
}

func TestSlowDownstreamAppliesBackpressure(t *testing.T) {
	input := &measuredReader{}
	sink := &blockedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		_, err := io.CopyBuffer(flushWriter{w: sink, controller: http.NewResponseController(sink)}, readerOnly{input}, make([]byte, 32<<10))
		done <- err
	}()
	select {
	case <-sink.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("downstream write did not start")
	}
	if reads := input.reads.Load(); reads != 1 {
		t.Errorf("read ahead while downstream blocked: %d", reads)
	}
	close(sink.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("copy did not stop")
	}
}

func TestTLSRequiresConfiguredHostname(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer server.Close()
	actual, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	h, err := New(Config{MasterOrigin: "https://wrong.example:" + actual.Port(), PublicOrigin: "https://entry.example", RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	h.seal = func(context.Context, *http.Request, []byte, *http.Request) error { return nil }
	h.transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", actual.Host)
	}
	defer h.transport.CloseIdleConnections()
	if w := invoke(h, "GET", "/api/v1/media/catalog/media", ""); w.Code != 502 {
		t.Errorf("wrong hostname accepted: %d", w.Code)
	}
}

func TestSealFailureNeverContactsMasterOrLeaksError(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1) }))
	defer server.Close()
	h := testProxy(t, server)
	h.seal = func(context.Context, *http.Request, []byte, *http.Request) error {
		return errors.New("private credential and query")
	}
	w := invoke(h, "POST", "/api/v1/media/crypto/key?secret=token", `{}`)
	if w.Code != 503 || requests.Load() != 0 || strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), "token") {
		t.Fatalf("seal failure leaked or forwarded: %d %q %d", w.Code, w.Body.String(), requests.Load())
	}
}

func TestRejectResponseHopHeaderNominations(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Connection", "Content-Type")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "private")
	}))
	defer server.Close()
	h := testProxy(t, server)
	w := invoke(h, "GET", "/api/v1/media/catalog/media", "")
	if w.Code != 502 || strings.Contains(w.Body.String(), "private") {
		t.Fatalf("nominated response header accepted: %d %q", w.Code, w.Body.String())
	}
}

func TestDefaultHandlerCannotReachMaster(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	h, err := New(Config{MasterOrigin: server.URL, PublicOrigin: "https://entry.example", RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer h.transport.CloseIdleConnections()
	for _, route := range routes {
		if w := invoke(h, route.method, route.path, ""); w.Code != 503 {
			t.Errorf("%s %s: %d", route.method, route.path, w.Code)
		}
	}
	if requests.Load() != 0 {
		t.Fatal("dormant handler contacted Master")
	}
}

func TestUpstreamTruncationAbortsUnknownLengthResponse(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "prefix")
		w.(http.Flusher).Flush()
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = conn.Close()
	}))
	defer upstream.Close()
	h := testProxy(t, upstream)
	proxy := httptest.NewServer(h)
	defer proxy.Close()
	req, err := http.NewRequest("GET", proxy.URL+"/api/v1/media/catalog/media", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "entry.example"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.ContentLength != -1 || string(body) != "prefix" || readErr == nil {
		t.Fatalf("truncation appeared complete: length=%d body=%q error=%v", resp.ContentLength, body, readErr)
	}
}

func TestCloseDelimitedUpstreamIsRejected(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\nprefix")
		_ = rw.Flush()
	}))
	defer upstream.Close()
	h := testProxy(t, upstream)
	proxy := httptest.NewServer(h)
	defer proxy.Close()
	req, _ := http.NewRequest(http.MethodGet, proxy.URL+"/api/v1/media/catalog/media", nil)
	req.Host = "entry.example"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusBadGateway || strings.Contains(string(body), "prefix") {
		t.Fatalf("close-delimited response accepted: status=%d body=%q error=%v", resp.StatusCode, body, err)
	}
}

func TestTruncatedKeyResponseFailsBeforeHeaders(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "partial key")
		w.(http.Flusher).Flush()
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = conn.Close()
	}))
	defer upstream.Close()
	h := testProxy(t, upstream)
	proxy := httptest.NewServer(h)
	defer proxy.Close()
	req, _ := http.NewRequest(http.MethodPost, proxy.URL+"/api/v1/media/crypto/key", strings.NewReader(`{}`))
	req.Host = "entry.example"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusBadGateway || strings.Contains(string(body), "partial key") {
		t.Fatalf("truncated key response accepted: status=%d body=%q error=%v", resp.StatusCode, body, err)
	}
}
