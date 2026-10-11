package certificate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func testPair(t *testing.T, host string, days int) ([]byte, []byte) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Duration(days) * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})
}
func port(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	v := l.Addr().String()
	l.Close()
	return v
}
func waitJob(t *testing.T, a *Agent) View {
	t.Helper()
	end := time.Now().Add(3 * time.Second)
	for time.Now().Before(end) {
		v := a.Status()
		if v.Job.State != "running" {
			return v
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("certificate job did not complete")
	return View{}
}
func openTest(t *testing.T, address string, issuer Issuer) *Agent {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	a, e := Open(context.Background(), "storage.fixture.test", dir, address, issuer)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(a.Close)
	return a
}

func TestChallengeLifecycleCoalescesAndReleasesOnEveryOutcome(t *testing.T) {
	for _, outcome := range []string{"success", "failed", "wrong_hostname", "cancelled"} {
		t.Run(outcome, func(t *testing.T) {
			address := port(t)
			entered := make(chan struct{})
			proceed := make(chan struct{})
			var calls atomic.Int32
			cert, key := testPair(t, "storage.fixture.test", 90)
			if outcome == "wrong_hostname" {
				cert, key = testPair(t, "other.fixture.test", 90)
			}
			a := openTest(t, address, func(ctx context.Context, present func(string, string) (func(), error)) ([]byte, []byte, error) {
				calls.Add(1)
				_, e := present("fixture_token", "fixture_response")
				if e != nil {
					return nil, nil, e
				}
				close(entered)
				select {
				case <-proceed:
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				}
				if outcome == "failed" {
					return nil, nil, errors.New("issuer failed")
				}
				return cert, key, nil
			})
			if _, e := a.Start(); e != nil {
				t.Fatal(e)
			}
			<-entered
			if _, e := a.Start(); e != nil || calls.Load() != 1 {
				t.Fatal("overlapping issuance", e, calls.Load())
			}
			client := &http.Client{Timeout: time.Second}
			request, _ := http.NewRequest("GET", "http://"+address+"/.well-known/acme-challenge/fixture_token", nil)
			request.Host = "storage.fixture.test"
			response, e := client.Do(request)
			if e != nil {
				t.Fatal(e)
			}
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != 200 || string(body) != "fixture_response" {
				t.Fatal(response.Status, string(body))
			}
			request, _ = http.NewRequest("GET", "http://"+address+"/.well-known/acme-challenge/fixture_token", nil)
			request.Host = "other.fixture.test"
			response, e = client.Do(request)
			if e != nil {
				t.Fatal(e)
			}
			response.Body.Close()
			if response.StatusCode != 404 {
				t.Fatal("challenge served for foreign host")
			}
			if outcome == "cancelled" {
				a.Close()
			} else {
				close(proceed)
			}
			v := waitJob(t, a)
			if v.Job.Port80Active {
				t.Fatal("port remained active", v)
			}
			if outcome == "success" {
				if v.Job.State != "success" || v.State != "valid" {
					t.Fatal(v)
				}
			} else {
				if v.Job.State != "failed" || v.State != "missing" {
					t.Fatal("failed issuance published TLS", v)
				}
			}
			l, e := net.Listen("tcp", address)
			if e != nil {
				t.Fatal("challenge port leaked", e)
			}
			l.Close()
			if outcome == "failed" {
				if _, e = a.Start(); e == nil {
					t.Fatal("failed retry bypassed cooldown")
				}
			}
		})
	}
}
func TestOccupiedPortAndPrivateLeaseDoNotDisturbOtherService(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "business") }))
	defer server.Close()
	a := openTest(t, server.Listener.Addr().String(), func(ctx context.Context, present func(string, string) (func(), error)) ([]byte, []byte, error) {
		_, e := present("token", "response")
		return nil, nil, e
	})
	if _, e := Open(context.Background(), a.host, a.directory, a.address, a.issue); e == nil {
		t.Fatal("second agent obtained same private lease")
	}
	if _, e := a.Start(); e != nil {
		t.Fatal(e)
	}
	v := waitJob(t, a)
	if v.Job.Code != "port80_busy" || v.Job.Port80Active {
		t.Fatal(v)
	}
	response, e := http.Get(server.URL)
	if e != nil {
		t.Fatal("existing business listener stopped", e)
	}
	defer response.Body.Close()
	b, _ := io.ReadAll(response.Body)
	if string(b) != "business" {
		t.Fatal("existing listener changed")
	}
}
func TestAtomicTLSHotReloadRejectsBadPairsAndKeepsConnections(t *testing.T) {
	oldCert, oldKey := testPair(t, "storage.fixture.test", 20)
	newCert, newKey := testPair(t, "storage.fixture.test", 90)
	a := openTest(t, port(t), func(context.Context, func(string, string) (func(), error)) ([]byte, []byte, error) {
		return newCert, newKey, nil
	})
	bootstrap := t.TempDir()
	cf, kf := filepath.Join(bootstrap, "cert.pem"), filepath.Join(bootstrap, "key.pem")
	os.WriteFile(cf, oldCert, 0600)
	os.WriteFile(kf, oldKey, 0600)
	manager, e := NewTLS(a.host, a.directory, cf, kf)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "stream bytes") }))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: manager.GetCertificate}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(oldCert)
	roots.AppendCertsFromPEM(newCert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: a.host, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	get := func() *x509.Certificate {
		t.Helper()
		r, e := client.Get(server.URL)
		if e != nil {
			t.Fatal(e)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if string(b) != "stream bytes" {
			t.Fatal("media body changed")
		}
		return r.TLS.PeerCertificates[0]
	}
	first := get()
	if _, e = a.Start(); e != nil {
		t.Fatal(e)
	}
	if v := waitJob(t, a); v.Job.State != "success" {
		t.Fatal(v)
	}
	expireCheck := func() { manager.mu.Lock(); manager.checked = time.Time{}; manager.mu.Unlock() }
	expireCheck()
	second := get()
	if first.SerialNumber.Cmp(second.SerialNumber) == 0 {
		t.Fatal("new TLS pair not hot loaded")
	}
	badCert, badKey := testPair(t, "other.fixture.test", 90)
	if e = a.publish(badCert, badKey); e == nil {
		t.Fatal("wrong-host pair accepted")
	}
	expireCheck()
	if get().SerialNumber.Cmp(second.SerialNumber) != 0 {
		t.Fatal("failed publish dropped valid TLS")
	}
	os.WriteFile(filepath.Join(a.directory, "current.json"), []byte(`{"generation":"../../private"}`), 0600)
	expireCheck()
	if get().SerialNumber.Cmp(second.SerialNumber) != 0 {
		t.Fatal("corrupt pointer caused bootstrap rollback")
	}
	manager.mu.Lock()
	manager.pair.Leaf.NotAfter = time.Now().Add(-time.Second)
	manager.mu.Unlock()
	if _, e = manager.GetCertificate(nil); e == nil {
		t.Fatal("expired TLS served")
	}
	if manager.Status().State != "expired" {
		t.Fatal("lost expired-certificate status")
	}
}
func TestUnixControlPolicyRestartAndNoSecrets(t *testing.T) {
	a := openTest(t, port(t), func(context.Context, func(string, string) (func(), error)) ([]byte, []byte, error) {
		return nil, nil, errors.New("not requested")
	})
	socket := filepath.Join(a.directory, "control.sock")
	done := make(chan error, 1)
	go func() { done <- a.Serve(socket) }()
	client := UnixClient{Socket: socket, Hostname: a.host}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var e error
	for ctx.Err() == nil {
		_, e = client.Control(ctx, Request{Action: "status"})
		if e == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if e != nil {
		t.Fatal(e)
	}
	v, e := client.Control(ctx, Request{Action: "auto", Enabled: true})
	if e != nil || !v.AutoRenew {
		t.Fatal(v, e)
	}
	wrong := client
	wrong.Hostname = "other.fixture.test"
	if _, e = wrong.Control(ctx, Request{Action: "status"}); e == nil {
		t.Fatal("wrong hostname trusted")
	}
	a.Close()
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	// Simulate the durable running marker from a killed process. No listener is recreated.
	os.WriteFile(filepath.Join(a.directory, "state.json"), []byte(`{"auto_renew":true,"job":{"state":"running","started_at":1,"port80_active":true}}`), 0600)
	next, e := Open(context.Background(), a.host, a.directory, a.address, a.issue)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	v = next.Status()
	if !v.AutoRenew || v.Job.Code != "interrupted" || v.Job.Port80Active {
		t.Fatal(v)
	}
	if _, e = ACME("other.fixture.test", a.directory, "http://untrusted.example/directory", ""); e == nil {
		t.Fatal("untrusted CA accepted")
	}
}
func TestRenewalRetainsExactlyCurrentAndPreviousCompleteGeneration(t *testing.T) {
	cert, key := testPair(t, "storage.fixture.test", 90)
	a := openTest(t, port(t), func(context.Context, func(string, string) (func(), error)) ([]byte, []byte, error) {
		return cert, key, nil
	})
	if e := a.publish(cert, key); e != nil {
		t.Fatal(e)
	}
	first, _ := manifest(a.directory)
	partial := filepath.Join(a.directory, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if e := os.Mkdir(partial, 0700); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(partial, "fullchain.pem"), cert, 0600)
	if e := a.publish(cert, key); e != nil {
		t.Fatal(e)
	}
	second, _ := manifest(a.directory)
	if _, e := os.Stat(filepath.Join(a.directory, first.Generation, "privkey.pem")); e != nil {
		t.Fatal("preceding complete generation deleted", e)
	}
	if _, e := os.Stat(partial); !os.IsNotExist(e) {
		t.Fatal("partial crash generation retained", e)
	}
	if e := a.publish(cert, key); e != nil {
		t.Fatal(e)
	}
	current, _ := manifest(a.directory)
	entries, _ := os.ReadDir(a.directory)
	count := 0
	for _, v := range entries {
		if generationPattern.MatchString(v.Name()) {
			count++
			if v.Name() != second.Generation && v.Name() != current.Generation {
				t.Fatal("old generation accumulated", v.Name())
			}
		}
	}
	if count != 2 {
		t.Fatal("unbounded renewal generations", count)
	}
}
