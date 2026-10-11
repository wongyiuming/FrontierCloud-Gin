package certmanager

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
	"go.uber.org/zap"
)

// Explicit development-only fixture. Only this test binary can inject a local
// CA/root; the shipping CLI has no CA, trust, certificate or directory override.
func TestAutomaticTLSContainerLifecycle(t *testing.T) {
	profile := Profile(os.Getenv("FRONTIERCLOUD_TEST_AUTOMATIC_TLS_PROFILE"))
	if profile == "" {
		t.Skip("requires isolated automatic TLS Compose fixture")
	}
	if profile != Business && profile != Direct && profile != Relay {
		t.Fatal("invalid fixture profile")
	}
	if os.Geteuid() != 0 || os.Getegid() != 10001 {
		t.Fatal("fixture controller identity mismatch")
	}
	host := "storage.fixture.test"
	challenge := "localhost:80"
	if profile == Business {
		host = "business.fixture.test"
		challenge = "nginx:80"
	}
	// This private test network resolves the advertised identity at its fixed
	// HTTPS port, as an isolated substitute for the public DNS entrance.
	serving := host + ":443"
	if profile == Relay {
		serving = host + ":8443"
	}
	ca := newCA(t, host, challenge)
	if err := os.WriteFile("/fixture/ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.root.Raw}), 0644); err != nil {
		t.Fatal(err)
	}
	marker := func(name string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join("/fixture", name), []byte("ready"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	waitMarker := func(name string) {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(filepath.Join("/fixture", name)); err == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("container fixture synchronization timed out", name)
	}
	marker("ca-ready")
	// The controller starts before consumers, as in the actual fresh Compose
	// graph. Business issuance must wait for its private HTTP-01 edge route.
	opt := options{host: host, enabled: true, profile: profile, private: PrivateDirectory, published: PublishedDirectory, runtime: RuntimeDirectory, challenge: ":80", serving: serving, ca: ca.server.URL + "/directory", roots: ca.roots}
	if profile == Business {
		opt.ingress = "http://nginx/.well-known/acme-challenge/frontiercloud-readiness"
	}
	opt.issuer = func(cfg *certmagic.Config) *certmagic.ACMEIssuer {
		return certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{CA: opt.ca, Agreed: true, DisableTLSALPNChallenge: true, ListenHost: "", AltHTTPPort: 80, CertObtainTimeout: 30 * time.Second, Logger: zap.NewNop()})
	}
	m, err := open(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	startControl := func(m *Manager) chan struct{} {
		done := make(chan struct{})
		go func() {
			defer close(done)
			if err := m.Serve(); err != nil {
				t.Error("container control socket failed", err)
			}
		}()
		return done
	}
	controlDone := startControl(m)
	wait := func(match func(certificate.View) bool) certificate.View {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			v := m.Status()
			if match(v) {
				return v
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatal("container lifecycle timed out", m.Status())
		return certificate.View{}
	}
	original := wait(func(v certificate.View) bool { return v.State == Active && v.HTTPSReady && v.ServingMatches })
	if profile != Business {
		released(t, ":80")
	}
	marker("active")
	waitMarker("serving-recreated")
	wait(func(v certificate.View) bool {
		return v.State == Active && v.Fingerprint == original.Fingerprint && v.ServingMatches
	})
	m.Close()
	<-controlDone
	m, err = open(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	controlDone = startControl(m)
	wait(func(v certificate.View) bool { return v.State == Active && v.ServingMatches })
	ca.mu.Lock()
	before := ca.issued
	accounts := ca.accounts
	ca.mu.Unlock()
	if before != 1 || accounts != 1 {
		t.Fatal("restart reissued valid certificate or discarded ACME account", before, accounts)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err = m.cfg.RenewCertSync(ctx, host, true); err != nil {
		t.Fatal("container real ACME renewal failed", err)
	}
	wait(func(v certificate.View) bool {
		return v.State == Active && v.ServingMatches && v.Fingerprint != original.Fingerprint
	})
	if profile != Business {
		released(t, ":80")
	}
	marker("renewed")
	waitMarker("verified")
	m.Close()
	<-controlDone
	t.Log("PASS: actual local-CA issuance, serving fingerprint, Compose recreation, persistent account and online renewal", profile)
}

// The native fleet uses independently issued private-CA identities to test
// business flows. This observer runs the real controller and serving handshake
// checks over that restored state, without making public CA requests.
func TestCertificateFleetObserver(t *testing.T) {
	host := os.Getenv("FRONTIERCLOUD_TEST_CERTIFICATE_FLEET_HOST")
	if host == "" {
		t.Skip("requires private-CA native fleet fixture")
	}
	if !certificate.Hostname(host) || os.Geteuid() != 0 || os.Getegid() != 10001 {
		t.Fatal("invalid fleet certificate fixture")
	}
	profile := Profile(os.Getenv("FRONTIERCLOUD_TEST_CERTIFICATE_FLEET_PROFILE"))
	serving := os.Getenv("FRONTIERCLOUD_TEST_CERTIFICATE_FLEET_SERVING")
	if profile != Business && profile != Direct && profile != Relay || serving == "" {
		t.Fatal("invalid private fleet profile")
	}
	ca := newCA(t, host, "localhost:80")
	roots := x509.NewCertPool()
	root, err := os.ReadFile("/certs/ca.pem")
	if err != nil || !roots.AppendCertsFromPEM(root) {
		t.Fatal("private fleet trust missing")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	m, err := open(ctx, options{host: host, enabled: true, profile: profile, private: PrivateDirectory, published: PublishedDirectory, runtime: RuntimeDirectory, challenge: ":80", serving: serving, ca: ca.server.URL + "/directory", roots: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err = m.Serve(); err != nil {
		t.Fatal(err)
	}
}
