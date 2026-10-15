package certmanager

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
)

type delayedMetadata struct {
	certmagic.Storage
	key string
}

func (s delayedMetadata) Load(ctx context.Context, key string) ([]byte, error) {
	value, err := s.Storage.Load(ctx, key)
	if err == nil && key == s.key {
		// Real local work may finish after its context deadline under CPU quotas.
		time.Sleep(3100 * time.Millisecond)
	}
	return value, err
}

func TestRefreshServingBudgetIndependentOfLocalWork(t *testing.T) {
	opt, _, _ := fixture(t, Relay)
	live, err := open(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(live.Close)
	initial := waitView(t, live, func(v certificate.View) bool { return v.State == Active && v.ServingMatches })
	live.Close()
	// Stop maintenance before injecting delays; keep real persisted certificate
	// generations and a real trusted TLS server, with no injected probe result.
	cfg := &certmagic.Config{Storage: delayedMetadata{Storage: live.storage.backend, key: certmagic.StorageKeys.SiteMeta(live.issuer.IssuerKey(), opt.host)}, RenewalWindowRatio: live.cfg.RenewalWindowRatio}
	m := &Manager{opt: opt, ctx: context.Background(), cfg: cfg, issuer: live.issuer, journal: live.journal, view: initial}
	m.refresh()
	v := m.Status()
	if v.State != Active || v.LastError != "" || !v.ServingMatches || !v.HTTPSReady || v.ServingFingerprint != initial.Fingerprint {
		t.Fatalf("local work consumed independent serving proof: %+v", v)
	}

	// A failed handshake must remain unverified and report its actual category.
	cfg.Storage = live.storage.backend
	alternate, ca, _ := fixture(t, Relay)
	other, err := open(context.Background(), alternate)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Close)
	otherView := waitView(t, other, func(v certificate.View) bool { return v.State == Active && v.ServingMatches })
	other.Close()
	m.opt.roots = opt.roots.Clone()
	m.opt.roots.AddCert(ca.root)
	m.opt.serving = alternate.serving
	m.refresh()
	v = m.Status()
	if v.LastError != "serving_certificate_mismatch" || v.ServingMatches || !v.HTTPSReady || v.ServingFingerprint != otherView.Fingerprint {
		t.Fatalf("trusted different serving identity was not distinguished: %+v", v)
	}
	wrong := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer wrong.Close()
	m.opt.serving = strings.TrimPrefix(wrong.URL, "https://")
	m.refresh()
	v = m.Status()
	if v.LastError != "serving_tls_verification" || v.ServingMatches || v.HTTPSReady || v.ServingFingerprint != "" {
		t.Fatalf("untrusted TLS was mislabeled or admitted: %+v", v)
	}
	m.opt.serving = opt.serving
	m.refresh()
	if v = m.Status(); v.State != Active || v.LastError != "" || !v.ServingMatches {
		t.Fatalf("fresh proof failed to recover a probe error: %+v", v)
	}
	// Recovery must not erase an independent failed renewal or its state.
	m.journal.Error = "rate_limited"
	m.journal.State = Degraded
	m.refresh()
	if v = m.Status(); v.LastError != "rate_limited" || v.State != Degraded || !v.ServingMatches {
		t.Fatalf("serving proof erased renewal failure: %+v", v)
	}
	m.journal.Error = "serving_probe_timeout"
	m.journal.State = Renewing
	m.refresh()
	if v = m.Status(); v.LastError != "" || v.State != Renewing {
		t.Fatalf("probe recovery replaced in-flight renewal state: %+v", v)
	}
}

func TestCAErrorClassificationPreservesProblemsAndTransportTimeout(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
	}{
		{&net.DNSError{IsTimeout: true}, "ca_timeout"},
		{context.DeadlineExceeded, "ca_timeout"},
		{&net.DNSError{IsNotFound: true}, "dns"},
		{acme.Problem{Type: "urn:ietf:params:acme:error:rateLimited"}, "rate_limited"},
	} {
		if got := classify(fmt.Errorf("transport: %w", tc.err)); got != tc.code {
			t.Fatalf("CA classification got %s, want %s", got, tc.code)
		}
	}
}

func TestServingProbeErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
	}{
		{nil, "serving_certificate_mismatch"},
		{context.DeadlineExceeded, "serving_probe_timeout"},
		{&net.DNSError{Err: "timeout", IsTimeout: true}, "serving_probe_timeout"},
		{&net.DNSError{Err: "no such host", IsNotFound: true}, "serving_dns"},
		{&net.OpError{Op: "dial", Err: errors.New("refused")}, "serving_connection"},
		{&tls.CertificateVerificationError{Err: errors.New("untrusted")}, "serving_tls_verification"},
		{errors.New("EOF"), "serving_tls_handshake"},
	} {
		err := tc.err
		if err != nil {
			err = fmt.Errorf("private endpoint: %w", err)
		}
		if got := classifyServingProbe(err); got != tc.code || !servingProbeError(got) {
			t.Fatalf("classification got %s, want %s", got, tc.code)
		}
	}
}

func TestServingProbeStalledTLSHonorsCallerDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			_, _ = conn.Read(make([]byte, 4096))
			_, _ = conn.Read(make([]byte, 1)) // wait for timed-out client to close
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	served, err := probe(ctx, listener.Addr().String(), "storage.fixture.test", nil)
	if served != "" || classifyServingProbe(err) != "serving_probe_timeout" {
		t.Fatal("stalled TLS did not fail closed as a timeout", served, err)
	}
	<-done
}
