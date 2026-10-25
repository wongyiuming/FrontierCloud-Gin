package certedge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func edgeFixture(t *testing.T) *Edge {
	t.Helper()
	directory := t.TempDir()
	e := &Edge{Host: "business.fixture.test", Enabled: true, config: filepath.Join(directory, "nginx.conf"), runtime: filepath.Join(directory, "runtime"), published: filepath.Join(directory, "published")}
	for _, folder := range []string{e.runtime, e.published} {
		if err := os.Mkdir(folder, 0750); err != nil {
			t.Fatal(err)
		}
	}
	for path, value := range map[string]string{e.config: "http { include public-tls.conf; business_api; }", filepath.Join(e.runtime, files[0]): "server { business_http; }", filepath.Join(e.runtime, files[1]): "ssl_certificate /etc/nginx/certs/fullchain.pem; ssl_certificate_key /etc/nginx/certs/privkey.pem;", filepath.Join(e.runtime, "ip-security.conf"): "old-security"} {
		if err := os.WriteFile(path, []byte(value), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return e
}
func publishFixture(t *testing.T, e *Edge, generation, domain string, expires time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	e.roots = x509.NewCertPool()
	e.roots.AddCert(root)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{domain}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if address := net.ParseIP(domain); address != nil {
		leaf.DNSNames, leaf.IPAddresses = nil, []net.IP{address}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	folder := filepath.Join(e.published, generation)
	if err = os.Mkdir(folder, 0750); err != nil {
		t.Fatal(err)
	}
	for file, data := range map[string][]byte{"fullchain.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "privkey.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})} {
		if err = os.WriteFile(filepath.Join(folder, file), data, 0640); err != nil {
			t.Fatal(err)
		}
	}
	pointer, _ := json.Marshal(map[string]string{"generation": generation})
	if err = os.WriteFile(filepath.Join(e.published, "current.json"), pointer, 0640); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestReadinessRejectsBootstrapAndStaleServingGeneration(t *testing.T) {
	e := edgeFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e.readyAt(ctx, "127.0.0.1:1") == nil {
		t.Fatal("certificate bootstrap reported TLS ready")
	}
	first := strings.Repeat("a", 32)
	oldRoot := publishFixture(t, e, first, e.Host, time.Now().Add(time.Hour))
	pair, err := tls.LoadX509KeyPair(filepath.Join(e.published, first, "fullchain.pem"), filepath.Join(e.published, first, "privkey.pem"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	address := server.Listener.Addr().String()
	if err = e.readyAt(ctx, address); err != nil {
		t.Fatal("actual trusted managed TLS rejected", err)
	}
	publishFixture(t, e, strings.Repeat("b", 32), e.Host, time.Now().Add(time.Hour))
	e.roots.AddCert(oldRoot)
	if e.readyAt(ctx, address) == nil {
		t.Fatal("trusted but stale TLS fingerprint reported healthy")
	}
}
func TestBootstrapHasNoBusinessAndSwitchIsVerifiedAndRollbackSafe(t *testing.T) {
	for _, fault := range []string{"", "validation", "reload"} {
		t.Run(fault, func(t *testing.T) {
			e := edgeFixture(t)
			if err := e.Initialize(); err != nil {
				t.Fatal(err)
			}
			bootstrap, err := os.ReadFile(e.config)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(bootstrap), "business_api") || strings.Contains(string(bootstrap), "listen 443") || !strings.Contains(string(bootstrap), "location / { return 444; }") {
				t.Fatal("bootstrap admitted plaintext business")
			}
			generation := strings.Repeat("a", 32)
			publishFixture(t, e, generation, e.Host, time.Now().Add(30*24*time.Hour))
			var calls [][]string
			e.Execute = func(_ context.Context, args ...string) error {
				calls = append(calls, append([]string(nil), args...))
				if fault == "validation" && args[0] == "-t" || fault == "reload" && args[0] == "-s" {
					return errors.New("fixture failure")
				}
				return nil
			}
			err = e.Apply()
			if fault != "" {
				if err == nil {
					t.Fatal("failed Nginx command accepted")
				}
				current, _ := os.ReadFile(e.config)
				if string(current) != string(bootstrap) {
					t.Fatal("failed switch did not restore prior configuration")
				}
				if _, err = os.Stat(filepath.Join(e.runtime, "tls-applied")); !os.IsNotExist(err) {
					t.Fatal("failed switch marked applied")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				body, _ := os.ReadFile(e.config)
				if !strings.Contains(string(body), "business_api") {
					t.Fatal("valid switch did not enable HTTPS business configuration")
				}
				tlsConf, _ := os.ReadFile(filepath.Join(e.runtime, "public-tls.conf"))
				if !strings.Contains(string(tlsConf), filepath.Join(e.published, generation, "privkey.pem")) {
					t.Fatal("Nginx did not select one complete generation")
				}
				if err = e.Apply(); err != nil || len(calls) != 2 {
					t.Fatal("unchanged certificate caused repeated reload", err, calls)
				}
			}
			want := [][]string{{"-t"}, {"-s", "reload"}}
			if fault == "validation" {
				want = want[:1]
			}
			if !reflect.DeepEqual(calls, want) {
				t.Fatal("unexpected command authority", calls)
			}
		})
	}
}
func TestExpiredSANMismatchAndUntrustedPairsNeverEnableHTTPS(t *testing.T) {
	for _, condition := range []string{"expired", "san", "untrusted", "key"} {
		t.Run(condition, func(t *testing.T) {
			e := edgeFixture(t)
			domain := e.Host
			expires := time.Now().Add(time.Hour)
			if condition == "expired" {
				expires = time.Now().Add(-time.Minute)
			}
			if condition == "san" {
				domain = "other.fixture.test"
			}
			publishFixture(t, e, strings.Repeat("b", 32), domain, expires)
			if condition == "untrusted" {
				e.roots = x509.NewCertPool()
			}
			if condition == "key" {
				if err := os.WriteFile(filepath.Join(e.published, strings.Repeat("b", 32), "privkey.pem"), []byte("invalid"), 0640); err != nil {
					t.Fatal(err)
				}
			}
			if err := e.Initialize(); err != nil {
				t.Fatal(err)
			}
			body, _ := os.ReadFile(e.config)
			if strings.Contains(string(body), "business_api") {
				t.Fatal("invalid certificate enabled business")
			}
			e.Execute = func(context.Context, ...string) error {
				t.Fatal("invalid generation reached Nginx command")
				return nil
			}
			if err := e.Apply(); err == nil {
				t.Fatal("invalid generation admitted")
			}
		})
	}
}
func TestSecurityReloadFailurePreservesRules(t *testing.T) {
	e := edgeFixture(t)
	if err := os.WriteFile(filepath.Join(e.runtime, "ip-security.candidate"), []byte("new-security"), 0644); err != nil {
		t.Fatal(err)
	}
	e.Execute = func(context.Context, ...string) error { return errors.New("fixture rejection") }
	if err := e.SecurityUpdate(); err == nil {
		t.Fatal("failed rules accepted")
	}
	rules, _ := os.ReadFile(filepath.Join(e.runtime, "ip-security.conf"))
	if string(rules) != "old-security" {
		t.Fatal("prior rules not restored")
	}
}
