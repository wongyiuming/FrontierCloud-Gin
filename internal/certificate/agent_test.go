package certificate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestSharedHTTP01CancellationCollisionAndReplacement(t *testing.T) {
	a := openTest(t, port(t), func(context.Context, func(string, string) (func(), error)) ([]byte, []byte, error) {
		return nil, nil, errors.New("not requested")
	})
	directory := t.TempDir()
	if e := a.UseHTTP01Directory(directory); e != nil {
		t.Fatal(e)
	}
	// An existing business keeps ownership of the would-be temporary address.
	listener, e := net.Listen("tcp", a.address)
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	other := filepath.Join(directory, "existing_token")
	if e = os.WriteFile(other, []byte("another issuer"), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = a.present(context.Background(), "existing_token", "ours"); e == nil {
		t.Fatal("overwrote another issuer")
	}
	outside := filepath.Join(t.TempDir(), "private")
	os.WriteFile(outside, []byte("private"), 0600)
	if e = os.Symlink(outside, filepath.Join(directory, "symlink_token")); e != nil {
		t.Fatal(e)
	}
	if _, e = a.present(context.Background(), "symlink_token", "ours"); e == nil {
		t.Fatal("followed a token symlink")
	}
	ctx, cancel := context.WithCancel(context.Background())
	closeFn, e := a.present(ctx, "owned_token", "public proof")
	if e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(filepath.Join(directory, "owned_token"))
	if e != nil || info.Mode().Perm() != 0644 || a.Status().Job.Port80Active {
		t.Fatal("shared proof not public or bound a listener", e)
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for {
		_, e = os.Stat(filepath.Join(directory, "owned_token"))
		if errors.Is(e, os.ErrNotExist) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cancel retained own token")
		}
		time.Sleep(time.Millisecond)
	}
	closeFn()
	closeFn, e = a.present(context.Background(), "replacement_token", "ours")
	if e != nil {
		t.Fatal(e)
	}
	os.Remove(filepath.Join(directory, "replacement_token"))
	os.WriteFile(filepath.Join(directory, "replacement_token"), []byte("replacement issuer"), 0644)
	closeFn()
	for path, want := range map[string]string{other: "another issuer", outside: "private", filepath.Join(directory, "replacement_token"): "replacement issuer"} {
		b, e := os.ReadFile(path)
		if e != nil || string(b) != want {
			t.Fatal("changed unrelated proof/file", path, e)
		}
	}
}

func TestSharedHTTP01RestartReclaimsOnlyMatchingJournalProof(t *testing.T) {
	for _, matching := range []bool{false, true} {
		t.Run(strconv.FormatBool(matching), func(t *testing.T) {
			directory, state := t.TempDir(), t.TempDir()
			os.Chmod(state, 0700)
			proof := "owned public proof"
			h := sha256.Sum256([]byte(proof))
			journal := persisted{Job: Job{State: "running", StartedAt: time.Now().Unix()}, HTTP01: &http01Lease{Token: "interrupted_token", Proof: hex.EncodeToString(h[:]), Directory: directory}}
			b, _ := json.Marshal(journal)
			os.WriteFile(filepath.Join(state, "state.json"), b, 0600)
			if !matching {
				proof = "another issuer"
			}
			os.WriteFile(filepath.Join(directory, "interrupted_token"), []byte(proof), 0644)
			a, e := Open(context.Background(), "storage.fixture.test", state, port(t), func(context.Context, func(string, string) (func(), error)) ([]byte, []byte, error) {
				return nil, nil, errors.New("not requested")
			})
			if e != nil {
				t.Fatal(e)
			}
			defer a.Close()
			if e = a.UseHTTP01Directory(directory); e != nil {
				t.Fatal(e)
			}
			b, e = os.ReadFile(filepath.Join(directory, "interrupted_token"))
			if matching && !errors.Is(e, os.ErrNotExist) || !matching && (e != nil || string(b) != proof) {
				t.Fatal("unsafe interrupted proof cleanup", e)
			}
			if a.Status().Job.Code != "interrupted" || a.state.HTTP01 != nil {
				t.Fatal("interrupted journal not retired")
			}
		})
	}
}

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

func TestContainerTLSGroupCannotReadPrivateAccountOrJournal(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0750); e != nil {
		t.Fatal(e)
	}
	issuer := func(context.Context, func(string, string) (func(), error)) ([]byte, []byte, error) {
		return nil, nil, errors.New("unused")
	}
	if a, e := Open(context.Background(), "storage.fixture.test", dir, port(t), issuer); e == nil {
		a.Close()
		t.Fatal("private mode accepted a shared directory")
	}
	a, e := OpenContainer(context.Background(), "storage.fixture.test", dir, port(t), issuer)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	if _, e := accountKey(dir); e != nil {
		t.Fatal(e)
	}
	cert, key := testPair(t, "storage.fixture.test", 90)
	if e = a.publish(cert, key); e != nil {
		t.Fatal(e)
	}
	p, e := manifest(dir)
	if e != nil {
		t.Fatal(e)
	}
	for path, mode := range map[string]os.FileMode{
		"account.key": 0600, "state.json": 0600, "agent.lock": 0600,
		"current.json": 0640, p.Generation: 0750,
		filepath.Join(p.Generation, "fullchain.pem"): 0640,
		filepath.Join(p.Generation, "privkey.pem"):   0640,
	} {
		info, err := os.Stat(filepath.Join(dir, path))
		if err != nil || info.Mode().Perm() != mode {
			t.Fatal("invalid container sharing mode", path, err)
		}
	}
	if _, e = loadPair("storage.fixture.test", filepath.Join(dir, p.Generation, "fullchain.pem"), filepath.Join(dir, p.Generation, "privkey.pem")); e != nil {
		t.Fatal(e)
	}
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

func TestPersistedAutoRenewChecksImmediatelyOnRestart(t *testing.T) {
	for _, test := range []struct {
		name                         string
		enabled, cooldown, wantIssue bool
		days                         int
	}{
		{"missing", true, false, true, 0},
		{"near-expiry", true, false, true, 1},
		{"expired", true, false, true, -1},
		{"valid", true, false, false, 90},
		{"disabled", false, false, false, 0},
		{"cooldown", true, true, false, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			issued := make(chan struct{}, 1)
			cert, key := testPair(t, "storage.fixture.test", 90)
			issue := func(context.Context, func(string, string) (func(), error)) ([]byte, []byte, error) {
				issued <- struct{}{}
				return cert, key, nil
			}
			directory, address := t.TempDir(), port(t)
			if e := os.Chmod(directory, 0700); e != nil {
				t.Fatal(e)
			}
			first, e := Open(context.Background(), "storage.fixture.test", directory, address, issue)
			if e != nil {
				t.Fatal(e)
			}
			if test.days != 0 {
				if e = first.publish(cert, key); e != nil {
					t.Fatal(e)
				}
				pair, e := manifest(directory)
				if e != nil {
					t.Fatal(e)
				}
				oldCert, oldKey := testPair(t, first.host, test.days)
				if e = os.WriteFile(filepath.Join(directory, pair.Generation, "fullchain.pem"), oldCert, 0600); e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(directory, pair.Generation, "privkey.pem"), oldKey, 0600); e != nil {
					t.Fatal(e)
				}
			}
			first.state.AutoRenew = test.enabled
			if e = first.save(); e != nil {
				t.Fatal(e)
			}
			if test.cooldown {
				first.state.Job.StartedAt = time.Now().Unix()
				if e = first.save(); e != nil {
					t.Fatal(e)
				}
			}
			first.Close()
			next, e := Open(context.Background(), first.host, directory, address, issue)
			if e != nil {
				t.Fatal(e)
			}
			done := make(chan error, 1)
			go func() { done <- next.Serve(filepath.Join(directory, "control.sock")) }()
			defer func() {
				next.Close()
				if e := <-done; e != nil {
					t.Error(e)
				}
			}()
			select {
			case <-issued:
				if !test.wantIssue {
					t.Fatal("startup bypassed disabled policy, validity or cooldown")
				}
				if state := waitJob(t, next); state.Job.State != "success" {
					t.Fatal(state)
				}
			case <-time.After(500 * time.Millisecond):
				if test.wantIssue {
					t.Fatal("persisted renewal waited for the six-hour ticker")
				}
			}
		})
	}
}

func TestEnableAutoRenewChecksImmediatelyWithValidityAndCooldownGuards(t *testing.T) {
	for _, test := range []struct {
		name                string
		days                int
		cooldown, wantIssue bool
	}{
		{"missing", 0, false, true},
		{"near-expiry", 1, false, true},
		{"valid", 90, false, false},
		{"cooldown", 0, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			issued := make(chan struct{}, 1)
			cert, key := testPair(t, "storage.fixture.test", 90)
			a := openTest(t, port(t), func(context.Context, func(string, string) (func(), error)) ([]byte, []byte, error) {
				calls.Add(1)
				issued <- struct{}{}
				return cert, key, nil
			})
			if test.days != 0 {
				oldCert, oldKey := testPair(t, a.host, test.days)
				if e := a.publish(oldCert, oldKey); e != nil {
					t.Fatal(e)
				}
			}
			if test.cooldown {
				a.state.Job.StartedAt = time.Now().Unix()
				if e := a.save(); e != nil {
					t.Fatal(e)
				}
			}
			view, e := a.SetAutoRenew(true)
			if e != nil || !view.AutoRenew {
				t.Fatal(view, e)
			}
			select {
			case <-issued:
				if !test.wantIssue {
					t.Fatal("policy enable bypassed validity or cooldown")
				}
				if view = waitJob(t, a); view.Job.State != "success" {
					t.Fatal(view)
				}
			case <-time.After(500 * time.Millisecond):
				if test.wantIssue {
					t.Fatal("enabling policy waited for the periodic ticker")
				}
			}
			if _, e = a.SetAutoRenew(true); e != nil {
				t.Fatal(e)
			}
			time.Sleep(20 * time.Millisecond)
			want := int32(0)
			if test.wantIssue {
				want = 1
			}
			if calls.Load() != want {
				t.Fatal("repeated enable duplicated issuance", calls.Load())
			}
		})
	}
}
