package certmanager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
)

// This fixture implements a local CA transport, not production ACME code.
// The actual CertMagic/acmez client performs account, order, challenge and CSR
// operations. The CA verifies the challenge served by the real bounded listener.
type mockCA struct {
	mu                                      sync.Mutex
	server                                  *httptest.Server
	root                                    *x509.Certificate
	key                                     *ecdsa.PrivateKey
	roots                                   *x509.CertPool
	challenge, host, thumb, status, problem string
	chain                                   []byte
	accounts, issued, verified              int
	profiles                                bool
	ariWindowStart, ariWindowEnd            time.Time
	ariRequests                             int
	orders                                  []map[string]any
	certificates                            []*x509.Certificate
	ipValidity                              time.Duration
}

func newCA(t *testing.T, host, challenge string) *mockCA {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "local fixture root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	root, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	ca := &mockCA{root: root, key: key, roots: roots, host: host, challenge: challenge, status: "pending", profiles: true}
	ca.server = httptest.NewServer(http.HandlerFunc(ca.handle))
	t.Cleanup(ca.server.Close)
	return ca
}
func (ca *mockCA) handle(w http.ResponseWriter, r *http.Request) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	nonce := make([]byte, 24)
	_, _ = rand.Read(nonce)
	w.Header().Set("Replay-Nonce", base64.RawURLEncoding.EncodeToString(nonce))
	w.Header().Set("Content-Type", "application/json")
	base := ca.server.URL
	kind := "dns"
	if net.ParseIP(ca.host) != nil {
		kind = "ip"
	}
	var payload map[string]any
	if r.Method == "POST" {
		var jws struct{ Protected, Payload string }
		_ = json.NewDecoder(io.LimitReader(r.Body, 65536)).Decode(&jws)
		raw, _ := base64.RawURLEncoding.DecodeString(jws.Payload)
		_ = json.Unmarshal(raw, &payload)
		if r.URL.Path == "/account" && ca.thumb == "" {
			protected, _ := base64.RawURLEncoding.DecodeString(jws.Protected)
			var header map[string]json.RawMessage
			_ = json.Unmarshal(protected, &header)
			var jwk map[string]any
			_ = json.Unmarshal(header["jwk"], &jwk)
			canonical, _ := json.Marshal(jwk)
			hash := sha256.Sum256(canonical)
			ca.thumb = base64.RawURLEncoding.EncodeToString(hash[:])
		}
	}
	out := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	order := func() map[string]any {
		state := "pending"
		if ca.status == "valid" {
			state = "ready"
		}
		if len(ca.chain) > 0 {
			state = "valid"
		}
		v := map[string]any{"status": state, "identifiers": []any{map[string]any{"type": kind, "value": ca.host}}, "authorizations": []string{base + "/authorization"}, "finalize": base + "/finalize"}
		if len(ca.chain) > 0 {
			v["certificate"] = base + "/certificate"
		}
		return v
	}
	if strings.HasPrefix(r.URL.Path, "/renewal-info/") {
		ca.ariRequests++
		start, end := ca.ariWindowStart, ca.ariWindowEnd
		firstID := ""
		if len(ca.certificates) > 0 {
			first := ca.certificates[0]
			firstID = base64.RawURLEncoding.EncodeToString(first.AuthorityKeyId) + "." + base64.RawURLEncoding.EncodeToString(first.SerialNumber.Bytes())
		}
		if strings.TrimPrefix(r.URL.Path, "/renewal-info/") != firstID {
			start = time.Now().Add(48 * time.Hour)
			end = start.Add(time.Hour)
		}
		w.Header().Set("Retry-After", "3600")
		out(map[string]any{"suggestedWindow": map[string]string{"start": start.UTC().Format(time.RFC3339Nano), "end": end.UTC().Format(time.RFC3339Nano)}})
		return
	}
	switch r.URL.Path {
	case "/directory":
		directory := map[string]any{"newNonce": base + "/nonce", "newAccount": base + "/account", "newOrder": base + "/new-order", "revokeCert": base + "/revoke", "keyChange": base + "/key-change"}
		if ca.profiles {
			directory["meta"] = map[string]any{"profiles": map[string]any{"shortlived": base + "/profiles/shortlived"}}
		}
		if !ca.ariWindowStart.IsZero() {
			directory["renewalInfo"] = base + "/renewal-info"
		}
		out(directory)
	case "/nonce":
		w.WriteHeader(200)
	case "/account":
		ca.accounts++
		w.Header().Set("Location", base+"/account/1")
		w.WriteHeader(201)
		out(map[string]any{"status": "valid", "orders": base + "/orders"})
	case "/account/1":
		out(map[string]any{"status": "valid", "orders": base + "/orders"})
	case "/new-order":
		identifiers, _ := payload["identifiers"].([]any)
		validIdentifier := len(identifiers) == 1
		if validIdentifier {
			identifier, _ := identifiers[0].(map[string]any)
			validIdentifier = identifier["type"] == kind && identifier["value"] == ca.host
		}
		if !validIdentifier || kind == "ip" && payload["profile"] != "shortlived" {
			w.WriteHeader(400)
			out(map[string]any{"type": "urn:ietf:params:acme:error:malformed", "detail": "unexpected identifier/profile", "status": 400})
			return
		}
		ca.orders = append(ca.orders, payload)
		if ca.problem != "" {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(429)
			out(map[string]any{"type": "urn:ietf:params:acme:error:" + ca.problem, "detail": "fixture rejection", "status": 429})
			return
		}
		ca.status = "pending"
		ca.chain = nil
		w.Header().Set("Location", base+"/order")
		w.WriteHeader(201)
		out(order())
	case "/order":
		out(order())
	case "/authorization":
		out(map[string]any{"status": ca.status, "identifier": map[string]any{"type": kind, "value": ca.host}, "challenges": []any{map[string]any{"type": "http-01", "url": base + "/challenge", "status": ca.status, "token": "fixture-token"}}})
	case "/challenge":
		req, _ := http.NewRequest("GET", "http://"+ca.challenge+"/.well-known/acme-challenge/fixture-token", nil)
		req.Host = ca.host
		if net.ParseIP(ca.host) != nil && strings.Contains(ca.host, ":") {
			req.Host = "[" + ca.host + "]"
		}
		client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
		response, e := client.Do(req)
		if e != nil {
			w.WriteHeader(500)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		response.Body.Close()
		client.CloseIdleConnections()
		if response.StatusCode != 200 || string(body) != "fixture-token."+ca.thumb {
			w.WriteHeader(500)
			return
		}
		ca.verified++
		ca.status = "valid"
		out(map[string]any{"type": "http-01", "status": "valid", "url": base + "/challenge", "token": "fixture-token"})
	case "/finalize":
		encoded, _ := payload["csr"].(string)
		der, e := base64.RawURLEncoding.DecodeString(encoded)
		if e != nil {
			w.WriteHeader(400)
			return
		}
		csr, e := x509.ParseCertificateRequest(der)
		validCSR := e == nil && csr.CheckSignature() == nil
		if validCSR && kind == "ip" {
			validCSR = len(csr.DNSNames) == 0 && len(csr.IPAddresses) == 1 && csr.IPAddresses[0].Equal(net.ParseIP(ca.host))
		} else if validCSR {
			validCSR = len(csr.DNSNames) == 1 && csr.DNSNames[0] == ca.host && len(csr.IPAddresses) == 0
		}
		if !validCSR {
			w.WriteHeader(400)
			return
		}
		ca.issued++
		notBefore, notAfter := time.Now().Add(-time.Minute), time.Now().Add(90*24*time.Hour)
		if kind == "ip" {
			notAfter = notBefore.Add(160 * time.Hour)
			if ca.ipValidity > 0 {
				notAfter = notBefore.Add(ca.ipValidity)
			}
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(ca.issued + 10)), DNSNames: csr.DNSNames, IPAddresses: csr.IPAddresses, NotBefore: notBefore, NotAfter: notAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
		cert, e := x509.CreateCertificate(rand.Reader, leaf, ca.root, csr.PublicKey, ca.key)
		if e != nil {
			w.WriteHeader(500)
			return
		}
		ca.chain = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
		parsed, _ := x509.ParseCertificate(cert)
		ca.certificates = append(ca.certificates, parsed)
		w.Header().Set("Location", base+"/order")
		out(order())
	case "/certificate":
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(ca.chain)
	default:
		http.NotFound(w, r)
	}
}
func fixture(t *testing.T, profile Profile) (options, *mockCA, *Serving) {
	t.Helper()
	root := t.TempDir()
	opt := options{host: strings.ToLower(strings.ReplaceAll(t.Name(), "_", "-")) + ".fixture.test", enabled: true, profile: profile, private: filepath.Join(root, "private"), published: filepath.Join(root, "published"), runtime: filepath.Join(root, "runtime")}
	// Short names stay valid even for verbose test method names.
	sum := sha256.Sum256([]byte(t.Name()))
	opt.host = fmt.Sprintf("node-%x.fixture.test", sum[:8])
	for _, entry := range []struct {
		path string
		mode os.FileMode
	}{{opt.private, 0700}, {opt.published, 0750}, {opt.runtime, 0710}} {
		if e := os.Mkdir(entry.path, entry.mode); e != nil {
			t.Fatal(e)
		}
	}
	reservation, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	opt.challenge = reservation.Addr().String()
	reservation.Close()
	ca := newCA(t, opt.host, opt.challenge)
	opt.ca = ca.server.URL + "/directory"
	opt.roots = ca.roots
	opt.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, nil
	}
	opt.issuer = func(cfg *certmagic.Config) *certmagic.ACMEIssuer {
		return certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{CA: opt.ca, Agreed: true, DisableTLSALPNChallenge: true, ListenHost: challengeHost(opt.challenge), AltHTTPPort: challengePort(opt.challenge), CertObtainTimeout: 5 * time.Second})
	}
	serving := &Serving{host: opt.host, directory: opt.published, roots: ca.roots}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	actualTLS := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: serving.GetCertificate}
	// StartTLS injects a localhost default certificate. A client using an IP
	// sends no SNI, so return the real serving configuration before selection.
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return actualTLS, nil }}
	server.StartTLS()
	t.Cleanup(server.Close)
	opt.serving = strings.TrimPrefix(server.URL, "https://")
	return opt, ca, serving
}
func waitView(t *testing.T, m *Manager, match func(certificate.View) bool) certificate.View {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		v := m.Status()
		if match(v) {
			return v
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("certificate lifecycle timeout: %+v", m.Status())
	return certificate.View{}
}
func released(t *testing.T, addr string) {
	t.Helper()
	listener, e := net.Listen("tcp", addr)
	if e != nil {
		t.Fatal("challenge socket was not released", e)
	}
	listener.Close()
}

func TestACMEFirstIssueVerifiedServingRenewalAndRestart(t *testing.T) {
	opt, ca, serving := fixture(t, Relay)
	if _, e := serving.GetCertificate(nil); e == nil {
		t.Fatal("missing certificate admitted TLS")
	}
	m, e := open(context.Background(), opt)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(m.Close)
	v := waitView(t, m, func(v certificate.View) bool { return v.State == Active && v.ServingMatches && v.HTTPSReady })
	if v.NotAfter <= time.Now().Unix() || len(v.SAN) != 1 || v.Issuer == "" || v.NextRenewal == 0 {
		t.Fatal("missing actual certificate facts", v)
	}
	released(t, opt.challenge)
	before, e := serving.GetCertificate(nil)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if e = m.cfg.RenewCertSync(ctx, opt.host, true); e != nil {
		t.Fatal("real ACME renewal failed", e)
	}
	v = waitView(t, m, func(v certificate.View) bool {
		return v.State == Active && v.Fingerprint != fingerprint(before) && v.ServingMatches
	})
	released(t, opt.challenge)
	m.Close()
	restarted, e := open(context.Background(), opt)
	if e != nil {
		t.Fatal(e)
	}
	defer restarted.Close()
	waitView(t, restarted, func(v certificate.View) bool { return v.State == Active && v.HTTPSReady })
	ca.mu.Lock()
	issued, accounts, verified := ca.issued, ca.accounts, ca.verified
	ca.mu.Unlock()
	if issued != 2 || accounts != 1 || verified != 2 {
		t.Fatal("restart lost account or reissued unchanged identity", issued, accounts, verified)
	}
}
func TestRenewalRateLimitRetainsValidServingPairAndReleasesPort(t *testing.T) {
	opt, ca, _ := fixture(t, Relay)
	m, e := open(context.Background(), opt)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	initial := waitView(t, m, func(v certificate.View) bool { return v.State == Active })
	ca.mu.Lock()
	ca.problem = "rateLimited"
	ca.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e = m.cfg.RenewCertSync(ctx, opt.host, true); e == nil {
		t.Fatal("CA failure accepted")
	}
	v := waitView(t, m, func(v certificate.View) bool { return v.LastError == "rate_limited" && v.State == Degraded })
	if v.Fingerprint != initial.Fingerprint || !v.HTTPSReady || v.LastRenewal != "failed" {
		t.Fatal("failed renewal replaced valid serving pair", v)
	}
	released(t, opt.challenge)
}
func TestMissingDNSIsDiagnosticAndControllerLeaseIsExclusive(t *testing.T) {
	opt, _, _ := fixture(t, Relay)
	opt.lookup = func(context.Context, string) ([]net.IPAddr, error) { return nil, &net.DNSError{IsNotFound: true} }
	m, e := open(context.Background(), opt)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	waitView(t, m, func(v certificate.View) bool { return v.State == Failed && v.LastError == "dns" && v.ControllerRunning })
	released(t, opt.challenge)
	if second, e := open(context.Background(), opt); e == nil {
		second.Close()
		t.Fatal("two controllers obtained one node's private lease")
	}
	if _, e = pointer(opt.published); !os.IsNotExist(e) {
		t.Fatal("DNS failure created a serving certificate", e)
	}
}
func TestPortConflictDoesNotStealListenerOrIssue(t *testing.T) {
	opt, ca, _ := fixture(t, Relay)
	listener, e := net.Listen("tcp", opt.challenge)
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	m, e := open(context.Background(), opt)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	waitView(t, m, func(v certificate.View) bool { return v.LastError == "port80_busy" && v.State == Failed })
	ca.mu.Lock()
	issued := ca.issued
	ca.mu.Unlock()
	if issued != 0 {
		t.Fatal("issued despite challenge conflict")
	}
}
