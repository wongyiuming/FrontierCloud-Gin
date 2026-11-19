package publicproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRelayCapabilityAndRangeAreBoundToPeerProof(t *testing.T) {
	const master = "https://master.example"
	for _, prefix := range []string{relayPrefix, "/api/v1/media/follower-relay/", "/api/v1/media/opaque-follower-relay/"} {
		path := prefix + strings.Repeat("a", 64)
		for _, name := range []string{"X-Media-Relay", "Range"} {
			v, _, _ := fixtureVerifier(t, master)
			r := signedFixtureFor(t, master, http.MethodGet, path)
			r.Header.Set(name, "tampered")
			w := httptest.NewRecorder()
			v.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("modified relay proof reached reader") })).ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("modified %s admitted: %d", name, w.Code)
			}
		}
	}
}

func TestRelayHTTP2RequiresEmptyRequestBody(t *testing.T) {
	path := "/api/v1/media/opaque-follower-relay/" + strings.Repeat("a", 64)
	var upstreamCalls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		if r.URL.Path != path || r.Header.Get("Range") != "bytes=1-1" || r.Body != http.NoBody {
			t.Error("upstream request did not preserve the path, range and empty body")
		}
		w.Header().Set("Content-Range", "bytes 1-1/3")
		w.Header().Set("Content-Length", "1")
		w.WriteHeader(http.StatusPartialContent)
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, "x")
		}
	}))
	defer upstream.Close()
	h := testProxy(t, upstream)
	defer h.CloseIdleConnections()
	entry := httptest.NewUnstartedServer(h)
	entry.EnableHTTP2 = true
	entry.StartTLS()
	defer entry.Close()

	for _, tc := range []struct {
		name, method string
		body         io.Reader
		wantStatus   int
		wantBody     string
	}{
		{"empty GET", http.MethodGet, nil, http.StatusPartialContent, "x"},
		{"empty HEAD", http.MethodHead, nil, http.StatusPartialContent, ""},
		{"declared body", http.MethodGet, strings.NewReader("x"), http.StatusBadRequest, "Bad Request\n"},
		{"undeclared body", http.MethodGet, io.NopCloser(strings.NewReader("x")), http.StatusBadRequest, "Bad Request\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, tc.method, entry.URL+path, tc.body)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = "entry.example"
			req.Header.Set("X-Media-Relay", "payload.signature")
			req.Header.Set("Range", "bytes=1-1")
			resp, err := entry.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil || resp.ProtoMajor != 2 || resp.StatusCode != tc.wantStatus || string(body) != tc.wantBody {
				t.Fatalf("response %s %d %q, read error %v", resp.Proto, resp.StatusCode, body, err)
			}
			if tc.wantStatus == http.StatusPartialContent && resp.Header.Get("Content-Range") != "bytes 1-1/3" {
				t.Fatal("partial response lost its range")
			}
		})
	}
	if count := upstreamCalls.Load(); count != 2 {
		t.Fatalf("upstream received %d requests, want 2", count)
	}
}

// Four slow resource streams occupy only relay capacity. Key requests keep
// their separate transport and slots, and closing browsers cancels upstream.
func TestRelayStreamingBackpressureCancellationAndKeyIsolation(t *testing.T) {
	started := make(chan struct{}, 4)
	cancelled := make(chan struct{}, 4)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/media/crypto/session" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{}`)
			return
		}
		if !relayRoute(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(w, "x")
		w.(http.Flusher).Flush()
		started <- struct{}{}
		<-r.Context().Done()
		cancelled <- struct{}{}
	}))
	defer server.Close()
	h := testProxy(t, server)
	defer h.CloseIdleConnections()
	entry := httptest.NewServer(h)
	defer entry.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	client := entry.Client()
	path := relayPrefix + strings.Repeat("a", 64)
	request := func(method, target string) *http.Request {
		r, err := http.NewRequestWithContext(ctx, method, entry.URL+target, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Host = "entry.example"
		if target == path {
			r.Header.Set("X-Media-Relay", "payload.signature")
		}
		return r
	}
	var opened []*http.Response
	for i := 0; i < 4; i++ {
		response, err := client.Do(request(http.MethodGet, path))
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatal("relay failed", response, err)
		}
		opened = append(opened, response)
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("upstream did not stream")
		}
	}
	fifth, err := client.Do(request(http.MethodGet, path))
	if err != nil {
		t.Fatal(err)
	}
	_ = fifth.Body.Close()
	if fifth.StatusCode != http.StatusServiceUnavailable {
		t.Fatal("relay capacity exceeded", fifth.StatusCode)
	}
	key, err := client.Do(request(http.MethodPost, "/api/v1/media/crypto/session"))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, key.Body)
	_ = key.Body.Close()
	if key.StatusCode != http.StatusOK {
		t.Fatal("relay streams blocked key", key.StatusCode)
	}
	for _, response := range opened {
		_ = response.Body.Close()
	}
	for i := 0; i < 4; i++ {
		select {
		case <-cancelled:
		case <-ctx.Done():
			t.Fatal("browser cancellation did not stop upstream")
		}
	}
}
