package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestCatalogIngressAdmissionUsesMasterLeaseAndDoesNotReacquirePeerLease(t *testing.T) {
	for _, master := range []bool{false, true} {
		name := "standalone"
		if master {
			name = "master"
		}
		t.Run(name, func(t *testing.T) {
			router, _, dir, public, _ := cryptoLeaseFixture(t, master)
			file, err := os.OpenFile(filepath.Join(dir, "data.db"+store.PublicIngressLeaseSuffix), os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			release, err := filelease.Acquire(context.Background(), file, true)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			call := func(ctx context.Context, route string) int {
				w := httptest.NewRecorder()
				r := httptest.NewRequest(http.MethodGet, cryptoLeaseOrigin+route, nil).WithContext(ctx)
				router.ServeHTTP(w, r)
				return w.Code
			}
			for _, route := range []string{"/api/v1/media/catalog/categories", "/api/v1/media/catalog/media", "/api/v1/media/metadata"} {
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				status := call(ctx, route)
				cancel()
				want := http.StatusUnprocessableEntity // handler rejects missing parameters
				if master {
					want = http.StatusServiceUnavailable
				}
				if status != want {
					t.Fatalf("%s: got %d want %d", route, status, want)
				}
			}
			for _, route := range []string{"/api/v1/media", "/api/v1/media/", "/api/v1/media/music", "/api/v1/media/video"} {
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				status := call(ctx, route)
				cancel()
				want := http.StatusOK
				if master {
					want = http.StatusServiceUnavailable
				}
				if status != want {
					t.Fatalf("page %s: got %d want %d", route, status, want)
				}
			}
			if !master {
				return
			}
			identity, err := public.media.IdentityState(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			ctx, err := network.WithAuthenticatedIngress(context.Background(), network.AuthenticatedIngress{NodeID: identity.ID, Generation: 1, PublicOrigin: cryptoLeaseOrigin, ClientIP: "192.0.2.1"})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			for _, route := range []string{"/api/v1/media/catalog/categories", "/api/v1/media/catalog/media", "/api/v1/media/metadata"} {
				if got := call(ctx, route); got != http.StatusUnprocessableEntity {
					t.Fatalf("peer %s: %d", route, got)
				}
			}
		})
	}
}

func TestMasterStreamAndS3SourceWaitForIngressFence(t *testing.T) {
	router, _, dir, _, path := cryptoLeaseFixture(t, true)
	file, err := os.OpenFile(filepath.Join(dir, "data.db"+store.PublicIngressLeaseSuffix), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	release, err := filelease.Acquire(context.Background(), file, true)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	for _, target := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/media/stream?" + url.Values{"file_path": {path}}.Encode(), ""},
		{http.MethodPost, "/api/v1/media/crypto/source", `{}`},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		r := httptest.NewRequest(target.method, cryptoLeaseOrigin+target.path, strings.NewReader(target.body)).WithContext(ctx)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		cancel()
		if w.Code < 400 || w.Header().Get("Location") != "" || w.Header().Get("X-Accel-Redirect") != "" {
			t.Fatalf("authorization escaped held fence for %s: %d %v", target.path, w.Code, w.Header())
		}
	}
	release()
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, cryptoLeaseOrigin+"/api/v1/media/stream?"+url.Values{"file_path": {path}}.Encode(), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("admitted local stream failed: %d %s", w.Code, w.Body.String())
	}
}

func TestLocalCatalogDiscardsResponseWhenIngressCommitFails(t *testing.T) {
	lease := &cryptoFaultLease{err: errors.New("commit failed")}
	ingress := store.PublicIngress{NodeID: strings.Repeat("a", 32), Generation: 1, PublicOrigin: "https://entry.test"}
	router := gin.New()
	router.GET("/", func(c *gin.Context) {
		servePublicWithIngressLease(c, ingress, lease, false, maxLocalCatalogResponse)
	}, func(c *gin.Context) { c.String(http.StatusOK, "secret-resource-handle") })
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "secret-resource-handle") || !lease.released || lease.commits != 1 {
		t.Fatalf("response exposed or lease not released: status %d body %q lease %+v", w.Code, w.Body.String(), lease)
	}
}

func TestLocalCatalogForcesNoStoreOnCommittedResponse(t *testing.T) {
	lease := &cryptoFaultLease{}
	ingress := store.PublicIngress{NodeID: strings.Repeat("a", 32), Generation: 1, PublicOrigin: "https://entry.test"}
	router := gin.New()
	router.GET("/", func(c *gin.Context) {
		servePublicWithIngressLease(c, ingress, lease, false, maxLocalCatalogResponse)
	}, func(c *gin.Context) {
		c.Header("Cache-Control", "public, max-age=300")
		c.String(http.StatusOK, "resource-handle")
	})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK || w.Body.String() != "resource-handle" || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") || !lease.released || lease.commits != 1 {
		t.Fatalf("incorrect admitted response: status %d headers %v lease %+v", w.Code, w.Header(), lease)
	}
}

func TestLocalCatalogRejectsIncompleteIngressBeforeHandler(t *testing.T) {
	lease := &cryptoFaultLease{}
	reached := false
	router := gin.New()
	router.GET("/", func(c *gin.Context) {
		servePublicWithIngressLease(c, store.PublicIngress{}, lease, false, maxLocalCatalogResponse)
	}, func(c *gin.Context) {
		reached = true
		c.String(http.StatusOK, "secret-resource-handle")
	})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusServiceUnavailable || reached || !lease.released || lease.commits != 0 || strings.Contains(w.Body.String(), "secret-resource-handle") {
		t.Fatalf("incomplete ingress was admitted: status %d reached %v lease %+v", w.Code, reached, lease)
	}
}
