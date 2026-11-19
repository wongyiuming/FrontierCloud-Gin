//go:build linux && ledger_fixture

package business

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

// The supplier is a local HTTPS S3-shaped fixture. The actual AWS SDK and
// cross-process file gate are used; this does not represent a real cloud S3.
func TestSelectedS3FileGateHeldAcrossLocalTLSProvider(t *testing.T) {
	started, proceed := make(chan struct{}), make(chan struct{})
	var creates, aborts atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		key := strings.TrimPrefix(r.URL.Path, "/fixture-bucket/")
		switch {
		case r.Method == http.MethodPost && r.URL.Query().Has("uploads"):
			if r.Header.Get("X-Amz-Meta-Fc-Format") != "opaque-v1" || r.Header.Get("X-Amz-Meta-Fc-Owner") == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			creates.Add(1)
			close(started)
			select {
			case <-proceed:
			case <-r.Context().Done():
				return
			}
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprintf(w, "<InitiateMultipartUploadResult><Bucket>fixture-bucket</Bucket><Key>%s</Key><UploadId>fixture-upload</UploadId></InitiateMultipartUploadResult>", key)
		case r.Method == http.MethodDelete && r.URL.Query().Get("uploadId") == "fixture-upload":
			aborts.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	if err := server.Certificate().VerifyHostname("example.com"); err != nil {
		t.Fatal("fixture certificate lacks example.com", err)
	}
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	provider, err := s3store.FixtureLocalTLSClient(s3store.Config{Endpoint: "https://example.com:" + port, Bucket: "fixture-bucket", Region: "us-east-1", Prefix: "managed", AddressStyle: "path"}, s3store.Credentials{AccessKey: "EXAMPLEACCESSKEY", SecretKey: "fixture-only-secret-key"}, roots, server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err = PrepareSelectedS3FileGate(root, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	tree := &sealedtree.SQLStore{}
	gate, err := OpenSelectedS3FileGate(root, tree, func(ctx context.Context) error { return ctx.Err() })
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	upload := strings.Repeat("a", 32)
	lease, err := gate.AcquireSelectedS3(ctx, tree, upload)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	physical := strings.Repeat("b", 64)
	key := "objects/bb/bb/" + physical + ".blob"
	type result struct {
		id  string
		err error
	}
	resultCh := make(chan result, 1)
	go func() {
		id, e := provider.CreateMultipart(ctx, key, map[string]string{"fc-format": "opaque-v1", "fc-owner": strings.Repeat("c", 64)})
		resultCh <- result{id, e}
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("provider request not started")
	}
	childCtx, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	child := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestSelectedS3FileGateChild$", "-test.count=1")
	child.Env = append(os.Environ(), "FC_S3_GATE_CHILD_ROOT="+dir, "FC_S3_GATE_CHILD_UPLOAD="+upload, "FC_S3_GATE_CHILD_EXPECT=busy")
	if output, e := child.CombinedOutput(); e != nil {
		close(proceed)
		t.Fatalf("provider operation lost cross-process lock: %v %s", e, output)
	}
	close(proceed)
	got := <-resultCh
	if got.err != nil || got.id != "fixture-upload" || lease.Check(ctx) != nil {
		t.Fatal("real SDK create", got.err)
	}
	if err = provider.Abort(ctx, key, got.id); err != nil || creates.Load() != 1 || aborts.Load() != 1 || lease.Check(ctx) != nil {
		t.Fatal("real SDK abort", err)
	}
}
