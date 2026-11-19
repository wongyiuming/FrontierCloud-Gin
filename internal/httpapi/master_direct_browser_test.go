package httpapi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// This opt-in development-host/browser fixture uses real Master handlers and
// ephemeral TLS sockets. Selection and applied policy are injected because the
// real non-Master activation gate remains deliberately closed.
func TestMasterDirectRealBrowserFixture(t *testing.T) {
	if os.Getenv("FRONTIERCLOUD_MASTER_DIRECT_BROWSER") != "1" {
		t.Skip("isolated real-browser fixture is opt-in")
	}
	if os.Getenv("FC_CHROME_EXECUTABLE") == "" || os.Getenv("FC_PLAYWRIGHT_MODULE") == "" {
		t.Fatal("explicit isolated browser paths required")
	}
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	masterRouter, db, dir, public, original := clusterFixture(t, "https://master.test", transport, false)
	plain := []byte("authenticated Direct plaintext for browser fixture")
	type item struct {
		Path       string                `json:"path"`
		Encryption *mediacrypto.Metadata `json:"encryption"`
		Expected   string                `json:"expected"`
		ResourceID string                `json:"resource_id,omitempty"`
		ObjectID   string                `json:"object_id,omitempty"`
		SizeBytes  int64                 `json:"size_bytes,omitempty"`
	}
	var items []item
	for _, name := range []string{"direct-a.mp3", "direct-b.mp3", "direct-c.mp3"} {
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
		path, err := public.media.PublishEncrypted(ctx, stage, name, "music/artist", "", false, 255, store.AdminAudit{}, &meta)
		stage.Close()
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, item{Path: path, Encryption: &meta, Expected: string(plain)})
	}
	lyricText := "[00:01.00] real browser lyric\n"
	lyricStage, err := public.media.Stage(ctx, strings.NewReader(lyricText), int64(len(lyricText)))
	if err != nil {
		t.Fatal(err)
	}
	lyricPath, err := public.media.Publish(ctx, lyricStage, "plain-browser.lrc", "", "", true, 255, store.AdminAudit{})
	lyricStage.Close()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := original.Promote(ctx, "Master", "https://master.test", 10*store.GiB, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := db.Pool().Resources(ctx, "music/artist/song.mp3", true)
	if err != nil || len(rows) != 1 {
		t.Fatal("plain media fixture", err)
	}
	if _, err = public.media.ReplaceLyrics(ctx, "track", rows[0].Path, []string{lyricPath}, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	items = append(items, item{Path: rows[0].Path, Expected: "0123456789", ResourceID: rows[0].ID, ObjectID: rows[0].ObjectID, SizeBytes: rows[0].Bytes})
	items = append(items, item{Path: lyricPath, Expected: lyricText})
	ingress := store.PublicIngress{NodeID: strings.Repeat("a", 32), PublicOrigin: "https://entry.test", Generation: 5}
	routing := &masterDirectHTTPRouting{selectedIngressRepository: selectedIngressRepository{NodeRepository: db.Nodes(), PublicRoutingRepository: db.Nodes().(store.PublicRoutingRepository), selected: ingress},
		policy: store.NativeTransportPolicy{MemberID: identity.ID, ConfiguredTransport: "Direct", AppliedTransport: "Direct", State: "applied", Revision: 2}}
	localIdentity, err := node.Initialize(ctx, db.Nodes(), filepath.Join(dir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	control := node.NewService(routing, localIdentity, transport)
	prepareMasterHTTPPolicy(t, control)
	public.media.ConfigureCluster(routing, db.Pool(), control)
	settings := public.settings
	settings.TLSEnabled = true
	directRouter := gin.New()
	reader, err := RegisterMasterDirect(directRouter, settings, "https://resource.test", public.media, control, public.crypto)
	if err != nil {
		t.Fatal(err)
	}
	public.masterDirect = reader
	verified, err := network.WithAuthenticatedIngress(ctx, network.AuthenticatedIngress{NodeID: ingress.NodeID, PublicOrigin: ingress.PublicOrigin, Generation: ingress.Generation, ClientIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	var failureMode atomic.Int32
	type observed struct {
		Method, Origin, Path, Query, Cookie, Range string
		Capability                                 bool
		Status                                     int
	}
	var mu sync.Mutex
	var observedRequests []observed
	direct := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status := http.StatusOK
		wrapped := &browserStatusWriter{ResponseWriter: w, status: &status}
		if failureMode.Load() == 1 && r.Method == http.MethodGet {
			w.Header().Set("Access-Control-Allow-Origin", ingress.PublicOrigin)
			w.Header().Set("Location", "/fixture/trap")
			wrapped.WriteHeader(http.StatusFound)
		} else if failureMode.Load() == 2 && r.Method == http.MethodGet {
			w.Header().Set("Access-Control-Allow-Origin", ingress.PublicOrigin)
			wrapped.WriteHeader(http.StatusServiceUnavailable)
		} else {
			directRouter.ServeHTTP(wrapped, r)
		}
		mu.Lock()
		observedRequests = append(observedRequests, observed{Method: r.Method, Origin: r.Header.Get("Origin"), Path: r.URL.Path, Query: r.URL.RawQuery, Cookie: r.Header.Get("Cookie"), Range: r.Header.Get("Range"), Capability: r.Header.Get("X-Media-Capability") != "", Status: status})
		mu.Unlock()
	}))
	defer direct.Close()
	publicServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/media/stream" {
			mu.Lock()
			observedRequests = append(observedRequests, observed{Method: r.Method, Path: r.URL.Path})
			mu.Unlock()
		}
		switch r.URL.Path {
		case "/fixture":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, `<meta charset="utf-8"><script src="/static/js/compiled/media-crypto-common.js"></script><script src="/static/js/compiled/media-crypto.js"></script>`)
			return
		case "/fixture/items":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(items)
			return
		case "/fixture/redirect":
			if r.Method == http.MethodPost {
				failureMode.Store(1)
			} else {
				failureMode.Store(0)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		case "/fixture/unavailable":
			if r.Method == http.MethodPost {
				failureMode.Store(2)
			} else {
				failureMode.Store(0)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		case "/fixture/stats":
			mu.Lock()
			snapshot := append([]observed(nil), observedRequests...)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(snapshot)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/media/crypto/") || r.URL.Path == "/api/v1/media/lyrics/content" || r.URL.Path == "/api/v1/media/catalog/media" {
			requestContext, admission := network.WithPublicAdmission(verified)
			defer admission.Abort()
			recorder := httptest.NewRecorder()
			masterRouter.ServeHTTP(recorder, r.WithContext(requestContext))
			if !admission.Commit() {
				http.Error(w, "fixture admission failed", 503)
				return
			}
			for name, values := range recorder.Header() {
				for _, value := range values {
					w.Header().Add(name, value)
				}
			}
			w.WriteHeader(recorder.Code)
			_, _ = w.Write(recorder.Body.Bytes())
			return
		}
		masterRouter.ServeHTTP(w, r)
	}))
	defer publicServer.Close()
	_, publicPort, _ := net.SplitHostPort(publicServer.Listener.Addr().String())
	_, resourcePort, _ := net.SplitHostPort(direct.Listener.Addr().String())
	runCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(runCtx, "node", filepath.Join("..", "..", "tests", "master_direct_browser.mjs"), publicPort, resourcePort)
	command.Env = append(os.Environ(), "FC_FIXTURE_ENTRY=https://entry.test", "FC_FIXTURE_RESOURCE=https://resource.test")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated browser: %v\n%s", err, output)
	}
	t.Logf("%s", bytes.TrimSpace(output))
	mu.Lock()
	defer mu.Unlock()
	if len(observedRequests) == 0 {
		t.Fatal("browser never reached real Direct handler")
	}
	for _, request := range observedRequests {
		if request.Query != "" || request.Cookie != "" {
			t.Fatalf("capability query or cookie reached resource: %+v", request)
		}
	}
}

type browserStatusWriter struct {
	http.ResponseWriter
	status *int
}

func (w *browserStatusWriter) WriteHeader(status int) {
	*w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *browserStatusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
