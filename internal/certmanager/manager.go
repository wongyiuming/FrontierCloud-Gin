package certmanager

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
	"go.uber.org/zap"
	"golang.org/x/net/netutil"
)

// Profile is a network deployment contract, independent of pairing state.
type Profile string

const (
	Business   Profile = "business"
	Direct     Profile = "direct"
	Relay      Profile = "relay"
	Disabled           = "DISABLED"
	Pending            = "PENDING"
	Validating         = "VALIDATING"
	Issuing            = "ISSUING"
	Active             = "ACTIVE"
	Renewing           = "RENEWING"
	Degraded           = "DEGRADED"
	Failed             = "FAILED"
)

type options struct {
	host                                                string
	enabled                                             bool
	profile                                             Profile
	private, published, runtime, challenge, serving, ca string
	roots                                               *x509.CertPool
	lookup                                              func(context.Context, string) ([]net.IPAddr, error)
	issuer                                              func(*certmagic.Config) *certmagic.ACMEIssuer
	ingress                                             string
}
type journal struct {
	Host        string `json:"host"`
	State       string `json:"state"`
	Error       string `json:"error,omitempty"`
	LastRenewal string `json:"last_renewal,omitempty"`
	RetryAt     int64  `json:"retry_at,omitempty"`
	StartedAt   int64  `json:"started_at,omitempty"`
	CompletedAt int64  `json:"completed_at,omitempty"`
}
type Manager struct {
	mu                sync.Mutex
	opt               options
	ctx               context.Context
	cancel            context.CancelFunc
	release           func()
	cache             *certmagic.Cache
	storage           *controlledStorage
	cfg               *certmagic.Config
	issuer            *boundedIssuer
	journal           journal
	view              certificate.View
	challenge         *http.Server
	challengeListener net.Listener
	wake              chan struct{}
	wg                sync.WaitGroup
	close             sync.Once
	issueFinished     time.Time
}

// New has no certificate-path, CA-path or insecure configuration surface.
// Directory paths and the approved public CA are fixed program internals.
func New(ctx context.Context, host string, enabled bool, profile Profile, relayPort int) (*Manager, error) {
	// Verify the advertised DNS entrance, including any external proxy, rather
	// than treating a successful private-loopback handshake as public proof.
	serving := net.JoinHostPort(host, "443")
	if profile == Relay {
		serving = net.JoinHostPort(host, strconv.Itoa(relayPort))
	}
	opt := options{host: host, enabled: enabled, profile: profile, private: PrivateDirectory, published: PublishedDirectory, runtime: RuntimeDirectory, challenge: ":80", serving: serving, ca: certmagic.LetsEncryptProductionCA, lookup: net.DefaultResolver.LookupIPAddr}
	if profile == Business {
		opt.ingress = "http://nginx/.well-known/acme-challenge/frontiercloud-readiness"
	}
	return open(ctx, opt)
}

func open(parent context.Context, opt options) (*Manager, error) {
	if opt.profile != Business && opt.profile != Direct && opt.profile != Relay {
		return nil, errors.New("invalid certificate network profile")
	}
	if opt.enabled && !certificate.Hostname(opt.host) {
		return nil, errors.New("automatic TLS requires a public DNS hostname")
	}
	for _, entry := range []struct {
		path string
		mode os.FileMode
	}{{opt.private, 0700}, {opt.published, 0750}, {opt.runtime, 0710}} {
		info, e := os.Lstat(entry.path)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&^entry.mode != 0 {
			return nil, errors.New("certificate controller requires isolated private, published and runtime volumes")
		}
	}
	lock, e := os.OpenFile(filepath.Join(opt.private, "controller.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	release, e := filelease.Try(lock, true)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(parent)
	m := &Manager{opt: opt, ctx: ctx, cancel: cancel, release: release, wake: make(chan struct{}, 1), journal: journal{Host: opt.host, State: Pending}}
	ok := false
	defer func() {
		if !ok {
			cancel()
			if m.storage != nil {
				m.storage.close()
			}
			release()
		}
	}()
	if !opt.enabled {
		// Explicit HTTP mode never consumes or rewrites damaged TLS state.
		m.journal = journal{Host: opt.host, State: Disabled}
		m.updateView()
		ok = true
		return m, nil
	}
	journalInvalid := false
	if b, e := readBounded(filepath.Join(opt.private, "lifecycle.json"), 4096); e == nil {
		if json.Unmarshal(b, &m.journal) != nil {
			journalInvalid = true
		}
		if m.journal.Host != opt.host {
			m.journal = journal{Host: opt.host, State: Pending}
		}
		if m.journal.State == Issuing || m.journal.State == Validating || m.journal.State == Renewing {
			m.journal.State = Pending
			m.journal.Error = "interrupted"
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		journalInvalid = true
	}
	if journalInvalid {
		// Preserve the damaged record, retain accounts/certificates and impose
		// a fresh conservative cooldown rather than losing rate-limit state.
		if e = os.Rename(filepath.Join(opt.private, "lifecycle.json"), filepath.Join(opt.private, "lifecycle-invalid-"+rand.Text()+".json")); e != nil {
			return nil, errors.New("certificate lifecycle recovery could not preserve damaged state")
		}
		m.journal = journal{Host: opt.host, State: Pending, Error: "journal_recovered", RetryAt: time.Now().Add(5 * time.Minute).Unix()}
		slog.Warn("automatic TLS lifecycle journal recovered", "domain", opt.host, "code", "journal_recovered")
	}
	logger := zap.NewNop() // ACME logs can contain full filesystem paths and CSR data.
	m.cache = certmagic.NewCache(certmagic.CacheOptions{GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return m.cfg, nil }, Capacity: 1, RenewCheckInterval: time.Hour, Logger: logger})
	m.storage = &controlledStorage{backend: &certmagic.FileStorage{Path: filepath.Join(opt.private, "cache")}}
	m.cfg = certmagic.New(m.cache, certmagic.Config{DefaultServerName: opt.host, Storage: m.storage, OnEvent: m.event, Logger: logger, KeySource: certmagic.StandardKeyGenerator{KeyType: certmagic.P256}})
	issue := opt.issuer
	if issue == nil {
		issue = func(cfg *certmagic.Config) *certmagic.ACMEIssuer {
			return certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{CA: opt.ca, Agreed: true, DisableTLSALPNChallenge: true, ListenHost: challengeHost(opt.challenge), AltHTTPPort: challengePort(opt.challenge), CertObtainTimeout: 3 * time.Minute, HTTPProxy: func(*http.Request) (*url.URL, error) { return nil, nil }, Logger: logger})
		}
	}
	m.issuer = &boundedIssuer{ACMEIssuer: issue(m.cfg), manager: m}
	m.cfg.Issuers = []certmagic.Issuer{m.issuer}
	if err := m.adoptLegacy(); err != nil {
		// Invalid historical material is retained for offline recovery, never
		// trusted or served. Automatic issuance continues with a new identity.
		m.journal.Error = "legacy_certificate_invalid"
		slog.Warn("automatic TLS legacy adoption refused", "domain", opt.host, "code", m.journal.Error)
	}
	m.updateView()
	if e = m.saveLocked(); e != nil {
		m.cache.Stop()
		return nil, e
	}
	if opt.profile == Business {
		if e = m.beginChallenge(); e != nil {
			m.cache.Stop()
			return nil, e
		}
	}
	m.refresh()
	m.wg.Add(2)
	go m.manage()
	go m.observe()
	ok = true
	return m, nil
}

func challengeHost(addr string) string { host, _, _ := net.SplitHostPort(addr); return host }
func challengePort(addr string) int {
	_, p, _ := net.SplitHostPort(addr)
	n, _ := strconv.Atoi(p)
	return n
}

// The wrapper preserves CertMagic's ARI, revocation and pre-check interfaces.
// All ACME work stays off the normal Web request path.
type boundedIssuer struct {
	*certmagic.ACMEIssuer
	manager *Manager
}

func (b *boundedIssuer) Issue(parent context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	m := b.manager
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	m.mu.Lock()
	retry := m.journal.RetryAt
	m.mu.Unlock()
	if time.Now().Unix() < retry {
		return nil, errors.New("certificate retry cooldown")
	}
	m.mu.Lock()
	last := m.journal.CompletedAt
	m.mu.Unlock()
	if time.Now().Year() < 2020 || last > time.Now().Add(5*time.Minute).Unix() {
		m.failed("system_clock", false)
		return nil, errors.New("certificate issuance refused because system time is inconsistent")
	}
	if m.opt.lookup != nil {
		lookupCtx, stop := context.WithTimeout(ctx, 3*time.Second)
		addresses, e := m.opt.lookup(lookupCtx, m.opt.host)
		stop()
		if e != nil || len(addresses) == 0 {
			m.failed("dns", false)
			return nil, errors.New("certificate DNS lookup failed")
		}
	}
	if m.opt.profile != Business {
		if e := m.beginChallenge(); e != nil {
			m.failed("port80_busy", false)
			return nil, e
		}
		defer m.endChallenge()
	}
	if m.opt.ingress != "" {
		if err := awaitIngress(ctx, m.opt.ingress, m.opt.host); err != nil {
			m.failed("http01_ingress", false)
			return nil, err
		}
	}
	m.mu.Lock()
	renewal := m.view.Fingerprint != ""
	m.journal.State = Issuing
	if renewal {
		m.journal.State = Renewing
	}
	m.journal.StartedAt = time.Now().Unix()
	m.issueFinished = time.Time{}
	m.journal.Error = ""
	if err := m.saveLocked(); err != nil {
		m.journal.Error = "journal_unwritable"
		m.journal.State = Failed
		m.updateView()
		m.mu.Unlock()
		return nil, errors.New("certificate lifecycle journal cannot be persisted")
	}
	m.updateView()
	m.mu.Unlock()
	result, e := b.ACMEIssuer.Issue(ctx, csr)
	if e != nil {
		m.failed(classify(e), renewal)
	} else {
		m.mu.Lock()
		m.issueFinished = time.Now()
		m.mu.Unlock()
	}
	return result, e
}

// Each node has one bounded challenge server. Relay owns it only while Issue
// runs; every success, error and cancellation path releases its socket.
func (m *Manager) beginChallenge() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx.Err() != nil {
		return m.ctx.Err()
	}
	if m.challengeListener != nil {
		return nil
	}
	listener, e := net.Listen("tcp", m.opt.challenge)
	if e != nil {
		return errors.New("HTTP-01 public port 80 is occupied or unavailable")
	}
	handler := m.issuer.HTTPChallengeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	server := &http.Server{ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 4096, BaseContext: func(net.Listener) context.Context { return m.ctx }, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != "GET" || r.URL.RawQuery != "" || r.URL.Path != "/health/controller" && !strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/health/controller" {
			http.NotFound(w, r)
			return
		}
		m.mu.Lock()
		if m.journal.State == Issuing {
			m.journal.State = Validating
			m.updateView()
		}
		m.mu.Unlock()
		w.Header().Set("X-FrontierCloud-ACME", "ready")
		handler.ServeHTTP(w, r)
	})}
	m.challenge = server
	m.challengeListener = listener
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		if err := server.Serve(netutil.LimitListener(listener, 1)); err != nil && !errors.Is(err, http.ErrServerClosed) && m.ctx.Err() == nil {
			m.failed("challenge_listener", false)
		}
	}()
	return nil
}
func (m *Manager) endChallenge() {
	m.mu.Lock()
	server, listener := m.challenge, m.challengeListener
	m.challenge = nil
	m.challengeListener = nil
	m.mu.Unlock()
	if server != nil {
		_ = server.Close()
	}
	if listener != nil {
		_ = listener.Close()
	}
}
func (m *Manager) event(ctx context.Context, name string, data map[string]any) error {
	if m.ctx.Err() != nil {
		return m.ctx.Err()
	}
	switch name {
	case "cert_obtaining":
		m.mu.Lock()
		m.journal.State = Pending
		if renewal, _ := data["renewal"].(bool); renewal {
			m.journal.State = Renewing
		}
		m.updateView()
		m.mu.Unlock()
	case "cert_failed":
		m.mu.Lock()
		recorded := m.journal.Error != ""
		m.mu.Unlock()
		if recorded {
			return nil
		}
		e, _ := data["error"].(error)
		renewal, _ := data["renewal"].(bool)
		m.failed(classify(e), renewal)
	case "cert_obtained":
		m.mu.Lock()
		m.issueFinished = time.Time{}
		m.journal.State = Pending
		m.journal.Error = ""
		m.journal.RetryAt = 0
		m.journal.CompletedAt = time.Now().Unix()
		if renewal, _ := data["renewal"].(bool); renewal {
			m.journal.LastRenewal = "success"
		}
		if err := m.saveLocked(); err != nil {
			m.journal.Error = "journal_unwritable"
			m.journal.State = Degraded
		}
		m.mu.Unlock()
		select {
		case m.wake <- struct{}{}:
		default:
		}
	}
	return nil
}
func classify(e error) string {
	if e == nil {
		return "ca_error"
	}
	var p acme.Problem
	if errors.As(e, &p) {
		switch strings.TrimPrefix(p.Type, "urn:ietf:params:acme:error:") {
		case "dns":
			return "dns"
		case "caa":
			return "caa"
		case "rateLimited":
			return "rate_limited"
		case "connection":
			return "http01_unreachable"
		case "unauthorized":
			return "authorization"
		case "rejectedIdentifier":
			return "domain_rejected"
		case "serverInternal":
			return "ca_unavailable"
		}
	}
	var network net.Error
	if errors.Is(e, context.DeadlineExceeded) || errors.As(e, &network) && network.Timeout() {
		return "ca_timeout"
	}
	var dns *net.DNSError
	if errors.As(e, &dns) {
		return "dns"
	}
	return "ca_error"
}
func (m *Manager) failed(code string, renewal bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx.Err() != nil {
		return
	}
	m.journal.Error = code
	m.journal.RetryAt = time.Now().Add(5 * time.Minute).Unix()
	m.journal.CompletedAt = time.Now().Unix()
	m.journal.State = Failed
	if m.view.NotAfter > time.Now().Unix() {
		m.journal.State = Degraded
	}
	if renewal {
		m.journal.LastRenewal = "failed"
	}
	if e := m.saveLocked(); e != nil {
		m.journal.Error = "journal_unwritable"
	}
	m.updateView()
	slog.Warn("automatic TLS operation failed", "domain", m.opt.host, "code", m.journal.Error)
}
func (m *Manager) saveLocked() error {
	if m.ctx.Err() != nil {
		return m.ctx.Err()
	}
	b, _ := json.Marshal(m.journal)
	return atomic(filepath.Join(m.opt.private, "lifecycle.json"), b, 0600)
}
func (m *Manager) updateView() {
	v := &m.view
	v.Enabled = m.opt.enabled
	v.ControllerRunning = m.ctx.Err() == nil
	v.Hostname = m.opt.host
	v.Mode = "automatic"
	v.Managed = m.opt.enabled
	v.AutoRenew = m.opt.enabled
	v.State = m.journal.State
	v.LastError = m.journal.Error
	v.LastRenewal = m.journal.LastRenewal
	v.Validation = "http01"
	if m.opt.profile != Business {
		v.Validation = "temporary_port80"
	}
	v.Job = certificate.Job{State: m.journal.State, Code: m.journal.Error, StartedAt: m.journal.StartedAt, CompletedAt: m.journal.CompletedAt, Port80Active: m.challengeListener != nil}
}
func (m *Manager) Status() certificate.View {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateView()
	v := m.view
	v.SAN = append([]string(nil), v.SAN...)
	v.ServingMatches = v.ServingMatches && v.Fingerprint != "" && v.Fingerprint == v.ServingFingerprint
	if v.NotAfter != 0 {
		v.RemainingSeconds = max(0, v.NotAfter-time.Now().Unix())
		if v.RemainingSeconds == 0 {
			v.State = Failed
			v.HTTPSReady = false
			v.ServingMatches = false
			v.LastError = "certificate_expired"
		}
	}
	if v.NotBefore != 0 && time.Now().Unix() < v.NotBefore {
		v.State = Failed
		v.HTTPSReady = false
		v.ServingMatches = false
		v.LastError = "certificate_not_yet_valid"
	}
	return v
}
func (m *Manager) manage() {
	defer m.wg.Done()
	m.mu.Lock()
	delay := time.Until(time.Unix(m.journal.RetryAt, 0))
	m.mu.Unlock()
	if delay > 0 {
		t := time.NewTimer(delay)
		defer t.Stop()
		select {
		case <-m.ctx.Done():
			return
		case <-t.C:
		}
	}
	m.mu.Lock()
	if m.journal.Error == "journal_recovered" {
		m.journal.Error = ""
		if err := m.saveLocked(); err != nil {
			m.journal.Error = "journal_unwritable"
		}
		m.updateView()
	}
	m.mu.Unlock()
	if e := m.cfg.ManageAsync(m.ctx, []string{m.opt.host}); e != nil && m.ctx.Err() == nil {
		m.failed(classify(e), false)
	}
}
func (m *Manager) observe() {
	defer m.wg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-m.wake:
			m.refresh()
		case <-ticker.C:
			m.refresh()
		}
	}
}

func (m *Manager) refresh() {
	if !m.opt.enabled {
		return
	}
	m.mu.Lock()
	stalled := !m.issueFinished.IsZero() && time.Since(m.issueFinished) > 10*time.Second
	renewing := m.journal.State == Renewing
	if stalled {
		m.issueFinished = time.Time{}
	}
	m.mu.Unlock()
	if stalled {
		m.failed("certificate_cache_unwritable", renewing)
	}
	ctx, cancel := context.WithTimeout(m.ctx, 3*time.Second)
	defer cancel()
	issuer := m.issuer.IssuerKey()
	cacheProblem := ""
	cert, e := m.cfg.Storage.Load(ctx, certmagic.StorageKeys.SiteCert(issuer, m.opt.host))
	if e == nil {
		key, ke := m.cfg.Storage.Load(ctx, certmagic.StorageKeys.SitePrivateKey(issuer, m.opt.host))
		if ke == nil {
			pair, pe := Validate(m.opt.host, cert, key, m.opt.roots, time.Now())
			defer clear(key)
			if pe == nil {
				// The verified private cache is authoritative. A remembered view
				// fingerprint cannot prove the published pair survived disk damage.
				pc, pk, readErr := readGeneration(m.opt.published)
				published, validErr := Validate(m.opt.host, pc, pk, m.opt.roots, time.Now())
				clear(pk)
				same := readErr == nil && validErr == nil && fingerprint(published) == fingerprint(pair)
				if !same {
					_, pe = publish(m.opt.published, m.opt.host, cert, key, m.opt.roots)
				}
			}
			if pe != nil {
				cacheProblem = "certificate_validation"
			}
		} else {
			cacheProblem = "certificate_cache_unreadable"
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		cacheProblem = "certificate_cache_unreadable"
	}
	m.mu.Lock()
	if cacheProblem != "" && m.journal.Error != cacheProblem {
		m.journal.Error = cacheProblem
		m.journal.State = Failed
		if m.view.NotAfter > time.Now().Unix() {
			m.journal.State = Degraded
		}
		if err := m.saveLocked(); err != nil {
			m.journal.Error = "journal_unwritable"
		}
		m.updateView()
	} else if cacheProblem == "" && (m.journal.Error == "certificate_validation" || m.journal.Error == "certificate_cache_unreadable") {
		m.journal.Error = ""
	}
	m.mu.Unlock()
	cert, key, e := readGeneration(m.opt.published)
	if e != nil {
		return
	}
	defer clear(key)
	pair, e := Validate(m.opt.host, cert, key, m.opt.roots, time.Now())
	if e != nil {
		served, probeErr := probe(m.ctx, m.opt.serving, m.opt.host, m.opt.roots)
		if m.ctx.Err() != nil {
			return
		}
		m.mu.Lock()
		m.journal.State = Failed
		m.journal.Error = "certificate_invalid"
		m.view.ServingFingerprint = served
		m.view.ServingMatches = false
		m.view.HTTPSReady = probeErr == nil && served != ""
		if err := m.saveLocked(); err != nil {
			m.journal.Error = "journal_unwritable"
		}
		m.updateView()
		m.mu.Unlock()
		return
	}
	m.mu.Lock()
	if m.view.Fingerprint != fingerprint(pair) {
		// A new managed generation needs its own real serving proof. Do not
		// reuse the previous generation's affirmative result during the probe.
		m.view.ServingMatches = false
	}
	m.view.Fingerprint = fingerprint(pair)
	m.view.NotBefore = pair.Leaf.NotBefore.Unix()
	m.view.NotAfter = pair.Leaf.NotAfter.Unix()
	m.view.SAN = append([]string(nil), pair.Leaf.DNSNames...)
	m.view.Issuer = pair.Leaf.Issuer.String()
	m.view.NextRenewal = pair.Leaf.NotAfter.Add(-time.Duration(float64(pair.Leaf.NotAfter.Sub(pair.Leaf.NotBefore)) * m.cfg.RenewalWindowRatio)).Unix()
	m.mu.Unlock()
	if meta, err := m.cfg.Storage.Load(ctx, certmagic.StorageKeys.SiteMeta(issuer, m.opt.host)); err == nil && len(meta) <= 65536 {
		var resource certmagic.CertificateResource
		var data acme.Certificate
		if json.Unmarshal(meta, &resource) == nil && json.Unmarshal(resource.IssuerData, &data) == nil && data.RenewalInfo != nil && !data.RenewalInfo.SelectedTime.IsZero() {
			m.mu.Lock()
			m.view.NextRenewal = data.RenewalInfo.SelectedTime.Unix()
			m.mu.Unlock()
		}
	}
	// Local cache/metadata work must not consume the serving handshake budget.
	// The independent bound also covers DNS, connect and TLS under CPU quotas.
	served, e := probe(m.ctx, m.opt.serving, m.opt.host, m.opt.roots)
	if m.ctx.Err() != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	previous := m.journal
	m.view.ServingFingerprint = served
	m.view.ServingMatches = e == nil && served == m.view.Fingerprint
	// A still-valid old serving identity can keep business available while an
	// edge reload is pending. Availability and managed-generation agreement
	// are independent facts; exports and release readiness require both.
	m.view.HTTPSReady = e == nil && served != ""
	if m.view.ServingMatches {
		prune(m.opt.published)
		if servingProbeError(m.journal.Error) {
			m.journal.Error = ""
		}
		if m.journal.Error == "" && m.journal.State != Renewing && m.journal.State != Issuing && m.journal.State != Validating {
			m.journal.State = Active
		} else if m.journal.State != Renewing && m.journal.State != Issuing && m.journal.State != Validating {
			m.journal.State = Degraded
		}
	} else {
		if m.journal.State != Renewing && m.journal.State != Issuing && m.journal.State != Validating {
			m.journal.State = Degraded
		}
		if m.journal.Error == "" || servingProbeError(m.journal.Error) {
			m.journal.Error = classifyServingProbe(e)
		}
	}
	m.updateView()
	if previous != m.journal {
		if err := m.saveLocked(); err != nil {
			m.journal.Error = "journal_unwritable"
			m.journal.State = Degraded
			m.updateView()
		}
	}
}
func probe(ctx context.Context, address, host string, roots *x509.CertPool) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	conn, e := (&tls.Dialer{NetDialer: &net.Dialer{}, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: roots}}).DialContext(ctx, "tcp", address)
	if e != nil {
		return "", e
	}
	defer conn.Close()
	peer := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(peer) == 0 {
		return "", errors.New("no serving certificate")
	}
	return fingerprint(&tls.Certificate{Certificate: [][]byte{peer[0].Raw}}), nil
}

func servingProbeError(code string) bool {
	switch code {
	case "serving_certificate_mismatch", "serving_probe_timeout", "serving_dns", "serving_connection", "serving_tls_verification", "serving_tls_handshake":
		return true
	}
	return false
}

// Return only bounded diagnostic codes; raw network errors may contain node
// addresses and must not become public Admin/heartbeat error strings.
func classifyServingProbe(err error) string {
	if err == nil {
		return "serving_certificate_mismatch"
	}
	var network net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &network) && network.Timeout() {
		return "serving_probe_timeout"
	}
	var verification *tls.CertificateVerificationError
	if errors.As(err, &verification) {
		return "serving_tls_verification"
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "serving_dns"
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return "serving_connection"
	}
	return "serving_tls_handshake"
}
func (m *Manager) Close() {
	m.close.Do(func() {
		m.cancel()
		m.endChallenge()
		if m.cache != nil {
			m.cache.Stop()
		}
		m.wg.Wait()
		if m.storage != nil {
			m.storage.close()
		}
		// Join any callback already persisting the journal under this mutex.
		m.mu.Lock()
		m.mu.Unlock()
		m.release()
	})
}
