package certmanager

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	stdatomic "sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
)

func ipFixture(t *testing.T, host string) (options, *mockCA, *Serving) {
	t.Helper()
	opt, ca, serving := fixture(t, Direct)
	opt.host, ca.host, serving.host = host, host, host
	opt.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		t.Error("literal IP certificate identity was sent to DNS")
		return nil, errors.New("IP must not use DNS")
	}
	return opt, ca, serving
}

func TestIPShortlivedIPv4IPv6ServingAndRestart(t *testing.T) {
	for _, host := range []string{"8.8.8.8", "2001:4860:4860::8888"} {
		t.Run(host, func(t *testing.T) {
			opt, ca, serving := ipFixture(t, host)
			m, err := open(context.Background(), opt)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(m.Close)
			view := waitView(t, m, func(v certificate.View) bool { return v.State == Active && v.ServingMatches })
			if len(view.SAN) != 1 || view.SAN[0] != host || view.NotAfter-view.NotBefore != int64(160*time.Hour/time.Second) || m.issuer.Profile != "shortlived" || m.cfg.RenewalWindowRatio != 0.5 {
				t.Fatal("IP certificate policy or SAN facts missing", view)
			}
			released(t, opt.challenge)
			// Go deliberately sends no SNI for IP literals. Verify the real
			// handshake still checks the IP SAN and serves the managed pair.
			var sawSNI stdatomic.Bool
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			actualTLS := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if hello.ServerName != "" {
					sawSNI.Store(true)
				}
				return serving.GetCertificate(hello)
			}}
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return actualTLS, nil }}
			server.StartTLS()
			got, err := probe(context.Background(), strings.TrimPrefix(server.URL, "https://"), host, ca.roots)
			server.Close()
			if err != nil || sawSNI.Load() || got != view.Fingerprint {
				t.Fatal("IP/no-SNI TLS handshake failed", err)
			}
			if _, err = serving.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example"}); err == nil {
				t.Fatal("foreign SNI accepted")
			}
			m.Close()
			restarted, err := open(context.Background(), opt)
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.Close()
			waitView(t, restarted, func(v certificate.View) bool { return v.State == Active && v.Fingerprint == view.Fingerprint })
			ca.mu.Lock()
			issued, accounts := ca.issued, ca.accounts
			ca.mu.Unlock()
			if issued != 1 || accounts != 1 {
				t.Fatal("restart reissued IP certificate/account", issued, accounts)
			}
		})
	}
}

func TestIPRequiresAdvertisedShortlivedProfile(t *testing.T) {
	opt, ca, _ := ipFixture(t, "8.8.4.4")
	ca.profiles = false
	m, err := open(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	waitView(t, m, func(v certificate.View) bool { return v.State == Failed && v.LastError != "" })
	ca.mu.Lock()
	issued, orders := ca.issued, len(ca.orders)
	ca.mu.Unlock()
	if issued != 0 || orders != 0 {
		t.Fatal("missing profile silently used CA default", issued, orders)
	}
	released(t, opt.challenge)
}

func TestIPRejectsTrustedLongLivedCertificate(t *testing.T) {
	opt, ca, _ := ipFixture(t, "8.8.4.4")
	leaf := &x509.Certificate{SerialNumber: big.NewInt(900), IPAddresses: []net.IP{net.ParseIP(opt.host)}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(90 * 24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca.root, &ca.key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = parsed.Verify(x509.VerifyOptions{DNSName: opt.host, Roots: ca.roots, CurrentTime: time.Now()}); err != nil {
		t.Fatal("fixture is not otherwise trusted", err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(ca.key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	defer clear(keyPEM)
	if _, err = Validate(opt.host, certPEM, keyPEM, ca.roots, time.Now()); err == nil {
		t.Fatal("IP profile silently accepted a trusted long-lived certificate")
	}
}

func TestIPAutomaticARIRenewalSendsNewOrderReplaces(t *testing.T) {
	opt, ca, _ := ipFixture(t, "1.1.1.1")
	opt.renewCheck = 100 * time.Millisecond // Test-only clock polling; production is five minutes.
	ca.ariWindowStart = time.Now().Add(10 * time.Second)
	ca.ariWindowEnd = ca.ariWindowStart.Add(2 * time.Second)
	m, err := open(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	// No RenewCertSync/force call: the real cache scheduler must observe ARI
	// becoming due while the 160-hour certificate is nowhere near ratio renewal.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		v := m.Status()
		ca.mu.Lock()
		issued := ca.issued
		ca.mu.Unlock()
		if issued == 2 && v.State == Active && v.LastRenewal == "success" && v.ServingMatches {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	view := m.Status()
	if view.State != Active || view.LastRenewal != "success" || !view.ServingMatches {
		t.Fatal("automatic ARI renewal did not become active", view)
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if len(ca.certificates) != 2 || len(ca.orders) != 2 || ca.ariRequests == 0 {
		t.Fatal("automatic ARI path did not run", ca.issued, len(ca.orders), ca.ariRequests)
	}
	first := ca.certificates[0]
	expected := base64.RawURLEncoding.EncodeToString(first.AuthorityKeyId) + "." + base64.RawURLEncoding.EncodeToString(first.SerialNumber.Bytes())
	if len(first.AuthorityKeyId) == 0 || ca.orders[0]["replaces"] != nil && ca.orders[0]["replaces"] != "" || ca.orders[1]["replaces"] != expected {
		t.Fatal("real ACME newOrder did not bind the ARI replacement", ca.orders[0]["replaces"], ca.orders[1]["replaces"], expected)
	}
}

func TestIPFailedRenewalRetainsOldIdentityAndPersistentCooldown(t *testing.T) {
	opt, ca, serving := ipFixture(t, "9.9.9.9")
	m, err := open(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	initial := waitView(t, m, func(v certificate.View) bool { return v.State == Active })
	ca.mu.Lock()
	ca.problem = "rateLimited"
	ca.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = m.cfg.RenewCertSync(ctx, opt.host, true); err == nil {
		t.Fatal("CA rejection accepted")
	}
	view := waitView(t, m, func(v certificate.View) bool { return v.State == Degraded && v.LastError == "rate_limited" })
	if view.Fingerprint != initial.Fingerprint || !view.ServingMatches || !view.HTTPSReady || view.LastRenewal != "failed" {
		t.Fatal("failed renewal lost valid IP service", view)
	}
	released(t, opt.challenge)
	m.Close()
	restarted, err := open(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	view = waitView(t, restarted, func(v certificate.View) bool { return v.HTTPSReady })
	if view.LastError != "rate_limited" || view.State != Degraded || view.Job.Code != "rate_limited" {
		t.Fatal("restart erased IP cooldown", view)
	}
	serving.mu.Lock()
	serving.pair.Leaf.NotAfter = time.Now().Add(-time.Second)
	serving.mu.Unlock()
	if _, err = serving.GetCertificate(nil); err == nil {
		t.Fatal("expired IP certificate was served")
	}
}

type failedIPKeySource struct{}

func (failedIPKeySource) GenerateKey() (crypto.PrivateKey, error) {
	return nil, errors.New("injected key generation failure")
}

func TestIPIssuanceWatchdogReleasesPortOnMissingTerminalEvent(t *testing.T) {
	opt, _, _ := ipFixture(t, "149.112.112.112")
	opt.attemptTimeout = 3 * time.Second
	m, err := open(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	before := waitView(t, m, func(v certificate.View) bool { return v.State == Active })
	m.cfg.KeySource = failedIPKeySource{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err = m.cfg.RenewCertSync(ctx, opt.host, true); err == nil {
		t.Fatal("key generation failure accepted")
	}
	view := waitView(t, m, func(v certificate.View) bool { return v.State == Degraded && v.LastError == "ca_timeout" })
	if view.Fingerprint != before.Fingerprint || !view.HTTPSReady {
		t.Fatal("unfinished cache operation destroyed old IP identity", view)
	}
	waitIPChallengeReleased(t, opt.challenge)
}

func TestIPPortCompetitionAutomaticRetryAcceptance(t *testing.T) {
	if os.Getenv("FC_IP_CERTIFICATE_RETRY_ACCEPTANCE") != "1" {
		t.Skip("development-only real CertMagic retry interval acceptance")
	}
	opt, ca, _ := ipFixture(t, "208.67.222.222")
	opt.retryDelay = time.Second
	occupied, err := net.Listen("tcp", opt.challenge)
	if err != nil {
		t.Fatal(err)
	}
	m, err := open(context.Background(), opt)
	if err != nil {
		occupied.Close()
		t.Fatal(err)
	}
	defer m.Close()
	waitView(t, m, func(v certificate.View) bool { return v.State == Failed && v.LastError == "port80_busy" })
	ca.mu.Lock()
	issued := ca.issued
	ca.mu.Unlock()
	if issued != 0 {
		t.Fatal("controller stole the other service's HTTP01 listener")
	}
	occupied.Close()
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		view := m.Status()
		if view.State == Active && view.HTTPSReady && view.ServingMatches {
			released(t, opt.challenge)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("real automatic retry did not recover after the competing listener exited", m.Status())
}
