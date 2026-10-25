package certmanager

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
	"go.uber.org/zap"
)

// The local CA's ordinary fixture polls ARI hourly. This response adapter only
// accelerates private test-CA polling; shipping code has no such override.
type containerARIResponse struct {
	http.ResponseWriter
	retryAfter string
}

func (w containerARIResponse) Write(p []byte) (int, error) {
	w.Header().Set("Retry-After", w.retryAfter)
	return w.ResponseWriter.Write(p)
}

// A real controller and shipping serving containers use one isolated literal
// IP. The test binary alone supplies the private CA, trust and shortened ticks.
func TestAutomaticTLSIPContainerLifecycle(t *testing.T) {
	host := os.Getenv("FRONTIERCLOUD_TEST_AUTOMATIC_TLS_IP")
	if host == "" {
		t.Skip("requires isolated IP automatic TLS Compose fixture")
	}
	profile := Profile(os.Getenv("FRONTIERCLOUD_TEST_AUTOMATIC_TLS_PROFILE"))
	if profile != Business && profile != Direct && profile != Relay || !certificate.IsIP(host) || !certificate.Hostname(host) || os.Geteuid() != 0 || os.Getegid() != 10001 {
		t.Fatal("invalid IP container fixture identity or profile")
	}
	port := "443"
	if profile == Relay {
		port = "8443"
	}
	ca := newCA(t, host, net.JoinHostPort(host, "80"))
	ca.ariWindowStart, ca.ariWindowEnd = time.Now().Add(time.Hour), time.Now().Add(2*time.Hour)
	ca.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/renewal-info/") {
			ca.mu.Lock()
			issued := ca.issued
			ca.mu.Unlock()
			retry := "1"
			if issued > 1 {
				retry = "3600"
			}
			ca.handle(containerARIResponse{w, retry}, r)
			return
		}
		ca.handle(w, r)
	})
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
		deadline := time.Now().Add(2 * time.Minute)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(filepath.Join("/fixture", name)); err == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("IP container fixture synchronization timed out", name)
	}
	opt := options{host: host, enabled: true, profile: profile, private: PrivateDirectory, published: PublishedDirectory, runtime: RuntimeDirectory, challenge: ":80", serving: net.JoinHostPort(host, port), ca: ca.server.URL + "/directory", roots: ca.roots, renewCheck: time.Second, retryDelay: 2 * time.Second, attemptTimeout: 30 * time.Second}
	if profile == Business {
		opt.ingress = "http://nginx/.well-known/acme-challenge/frontiercloud-readiness"
	}
	opt.issuer = func(cfg *certmagic.Config) *certmagic.ACMEIssuer {
		return certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{CA: opt.ca, Agreed: true, DisableTLSALPNChallenge: true, AltHTTPPort: 80, CertObtainTimeout: 25 * time.Second, Logger: zap.NewNop(), HTTPProxy: func(*http.Request) (*url.URL, error) { return nil, nil }})
	}
	m, err := open(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	startControl := func(managed *Manager) chan error {
		out := make(chan error, 1)
		go func() { out <- managed.Serve() }()
		return out
	}
	control := startControl(m)
	wait := func(description string, match func(certificate.View) bool) certificate.View {
		t.Helper()
		deadline := time.Now().Add(2 * time.Minute)
		for time.Now().Before(deadline) {
			view := m.Status()
			if match(view) {
				return view
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatal(description, m.Status())
		return certificate.View{}
	}
	verifyReleased := func() {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for {
			listener, err := net.Listen("tcp", ":80")
			if err == nil {
				_ = listener.Close()
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("idle IP challenge socket was not released within one second", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	verifyHTTPS := func(expected string) {
		t.Helper()
		transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: ca.roots, ServerName: host}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
		response, err := client.Get("https://" + net.JoinHostPort(host, port) + "/health/ready")
		if err != nil {
			t.Fatal("shipping IP HTTPS request failed", err)
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		if response.StatusCode != http.StatusOK || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 || fingerprint(&tls.Certificate{Certificate: [][]byte{response.TLS.PeerCertificates[0].Raw}}) != expected {
			t.Fatal("shipping IP HTTPS identity or readiness mismatch", response.StatusCode)
		}
	}
	marker("ca-ready")
	initial := wait("first IP issue", func(v certificate.View) bool { return v.State == Active && v.HTTPSReady && v.ServingMatches })
	if len(initial.SAN) != 1 || initial.SAN[0] != host || initial.NotAfter-initial.NotBefore != int64(160*time.Hour/time.Second) {
		t.Fatal("missing real IP SAN or short-lived certificate facts", initial)
	}
	if profile != Business {
		verifyReleased()
	}
	verifyHTTPS(initial.Fingerprint)
	marker("active")
	waitMarker("serving-recreated")
	wait("recreated serving identity", func(v certificate.View) bool {
		return v.State == Active && v.ServingMatches && v.Fingerprint == initial.Fingerprint
	})
	m.Close()
	<-control
	m, err = open(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	control = startControl(m)
	wait("controller cache/account restart", func(v certificate.View) bool {
		return v.State == Active && v.ServingMatches && v.Fingerprint == initial.Fingerprint
	})
	verifyHTTPS(initial.Fingerprint)
	ca.mu.Lock()
	if ca.issued != 1 || ca.accounts != 1 {
		ca.mu.Unlock()
		t.Fatal("controller restart reissued identity/account")
	}
	ca.problem = "rateLimited"
	ca.ariWindowStart, ca.ariWindowEnd = time.Now().Add(5*time.Second), time.Now().Add(10*time.Second)
	ca.mu.Unlock()
	failed := wait("scheduled ARI renewal rejection", func(v certificate.View) bool {
		return v.State == Degraded && v.LastRenewal == "failed" && v.LastError == "rate_limited"
	})
	if !failed.HTTPSReady || !failed.ServingMatches || failed.Fingerprint != initial.Fingerprint {
		t.Fatal("failed renewal lost valid old TLS", failed)
	}
	if profile != Business {
		verifyReleased()
	}
	verifyHTTPS(initial.Fingerprint)
	marker("renewal-failed")
	waitMarker("failure-verified")
	ca.mu.Lock()
	ca.problem = ""
	ca.mu.Unlock()
	// No RenewCertSync/force call: the actual cache retry driver must recover
	// after its real one-minute backoff, using the still-due ARI window.
	renewed := wait("automatic ARI retry recovery", func(v certificate.View) bool {
		return v.State == Active && v.LastRenewal == "success" && v.ServingMatches && v.Fingerprint != initial.Fingerprint
	})
	if profile != Business {
		verifyReleased()
	}
	verifyHTTPS(renewed.Fingerprint)
	ca.mu.Lock()
	if ca.issued != 2 || ca.accounts != 1 || ca.ariRequests == 0 || len(ca.orders) < 3 {
		ca.mu.Unlock()
		t.Fatal("incomplete real ARI failure/retry/account lifecycle")
	}
	first := ca.certificates[0]
	replaces := base64.RawURLEncoding.EncodeToString(first.AuthorityKeyId) + "." + base64.RawURLEncoding.EncodeToString(first.SerialNumber.Bytes())
	if ca.orders[len(ca.orders)-1]["replaces"] != replaces {
		ca.mu.Unlock()
		t.Fatal("automatic IP retry omitted original ARI replacement identity")
	}
	facts := map[string]any{"ip": host, "profile": profile, "accounts": ca.accounts, "issued": ca.issued, "http01_validations": ca.verified, "ari_requests": ca.ariRequests, "orders": len(ca.orders), "initial_fingerprint": initial.Fingerprint, "renewed_fingerprint": renewed.Fingerprint, "renewal_failure_preserved_tls": true, "controller_reopen_preserved_account": true, "automatic_ari_retry": true, "public_ca_requests": 0}
	ca.mu.Unlock()
	encoded, _ := json.MarshalIndent(facts, "", "  ")
	if err := os.WriteFile("/fixture/ip-evidence.json", encoded, 0644); err != nil {
		t.Fatal(err)
	}
	marker("renewed")
	waitMarker("verified")
	m.Close()
	<-control
	t.Log("PASS: actual local-CA IP issuance, shipping TLS, persistent account, ARI failure and automatic retry", profile, host)
}

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
