package certmanager

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
)

func ipCacheKeys(m *Manager) []string {
	issuer, host := m.issuer.IssuerKey(), m.opt.host
	return []string{certmagic.StorageKeys.SitePrivateKey(issuer, host),
		certmagic.StorageKeys.SiteCert(issuer, host), certmagic.StorageKeys.SiteMeta(issuer, host)}
}

func waitIPChallengeReleased(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		listener, err := net.Listen("tcp", address)
		if err == nil {
			listener.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("rejected CA attempt did not release its temporary socket within one second")
}

func ipCacheBytes(t *testing.T, m *Manager) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	for _, key := range ipCacheKeys(m) {
		value, err := m.cfg.Storage.Load(context.Background(), key)
		if err != nil {
			t.Fatal(err)
		}
		result[key] = value
		t.Cleanup(func() { clear(value) })
	}
	return result
}

func replacementIPBytes(t *testing.T, ca *mockCA, host string) [][]byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().Add(-time.Minute)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(999), IPAddresses: []net.IP{net.ParseIP(host)},
		NotBefore: before, NotAfter: before.Add(160 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca.root, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	t.Cleanup(func() { clear(keyPEM) })
	meta, err := json.Marshal(certmagic.CertificateResource{SANs: []string{host}, IssuerData: json.RawMessage("{}")})
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{keyPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), meta}
}

type failIPSave struct {
	certmagic.Storage
	key            string
	mutate, failed bool
}

func (s *failIPSave) Store(ctx context.Context, key string, value []byte) error {
	if key == s.key && !s.failed {
		s.failed = true
		if s.mutate {
			if err := s.Storage.Store(ctx, key, value); err != nil {
				return err
			}
		}
		return errors.New("injected single IP save failure")
	}
	return s.Storage.Store(ctx, key, value)
}

func TestIPCertificatePartialSaveRestoresCompletePriorCache(t *testing.T) {
	for _, slot := range []string{"key", "certificate", "metadata"} {
		for _, mutate := range []bool{false, true} {
			name := slot + "/before-write"
			if mutate {
				name = slot + "/after-write"
			}
			t.Run(name, func(t *testing.T) {
				opt, ca, _ := ipFixture(t, "1.0.0.1")
				m, err := open(context.Background(), opt)
				if err != nil {
					t.Fatal(err)
				}
				defer m.Close()
				waitView(t, m, func(v certificate.View) bool { return v.State == Active })
				prior := ipCacheBytes(t, m)
				keys, next := ipCacheKeys(m), replacementIPBytes(t, ca, opt.host)
				index := map[string]int{"key": 0, "certificate": 1, "metadata": 2}[slot]
				m.storage.mu.Lock()
				m.storage.backend = &failIPSave{Storage: m.storage.backend, key: keys[index], mutate: mutate}
				m.storage.mu.Unlock()
				for part := 0; part < 2; part++ {
					if err = m.cfg.Storage.Store(context.Background(), keys[part], next[part]); err != nil {
						t.Fatal(err)
					}
				}
				if err = m.cfg.Storage.Store(context.Background(), keys[2], next[2]); err == nil {
					t.Fatal("partial backend save unexpectedly succeeded")
				}
				// The actual SDK performs these deletes after its metadata
				// Store fails. They must not remove any prior cache member.
				for _, key := range []string{keys[1], keys[0]} {
					if err = m.cfg.Storage.Delete(context.Background(), key); err != nil {
						t.Fatal(err)
					}
				}
				for _, key := range keys {
					actual, err := m.cfg.Storage.Load(context.Background(), key)
					if err != nil || !bytes.Equal(actual, prior[key]) {
						t.Fatal("failed save or SDK rollback damaged prior cache", slot, mutate, err)
					}
					clear(actual)
				}
				// Once storage recovers, the same normal SDK save sequence
				// accepts a complete valid replacement without cache removal.
				for part, key := range keys {
					if err = m.cfg.Storage.Store(context.Background(), key, next[part]); err != nil {
						t.Fatal("valid retry save failed", err)
					}
				}
				for part, key := range keys {
					actual, err := m.cfg.Storage.Load(context.Background(), key)
					if err != nil || !bytes.Equal(actual, next[part]) {
						t.Fatal("retry did not commit the full new cache", err)
					}
					clear(actual)
				}
			})
		}
	}
}

func TestIPCancelledStagedSavePreservesPriorCache(t *testing.T) {
	for _, certificateStaged := range []bool{false, true} {
		name := "after-key"
		if certificateStaged {
			name = "after-certificate"
		}
		t.Run(name, func(t *testing.T) {
			opt, ca, _ := ipFixture(t, "1.1.1.2")
			m, err := open(context.Background(), opt)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			waitView(t, m, func(v certificate.View) bool { return v.State == Active })
			prior := ipCacheBytes(t, m)
			keys, next := ipCacheKeys(m), replacementIPBytes(t, ca, opt.host)
			last := 0
			if certificateStaged {
				last = 1
			}
			for part := 0; part <= last; part++ {
				if err = m.cfg.Storage.Store(context.Background(), keys[part], next[part]); err != nil {
					t.Fatal(err)
				}
			}
			cancelled, cancel := context.WithCancel(context.Background())
			cancel()
			if err = m.cfg.Storage.Store(cancelled, keys[last+1], next[last+1]); !errors.Is(err, context.Canceled) {
				t.Fatal("cancelled staged transaction was accepted", err)
			}
			for part := last; part >= 0; part-- {
				if err = m.cfg.Storage.Delete(context.Background(), keys[part]); err != nil {
					t.Fatal(err)
				}
			}
			for _, key := range keys {
				actual, err := m.cfg.Storage.Load(context.Background(), key)
				if err != nil || !bytes.Equal(actual, prior[key]) {
					t.Fatal("cancelled staged save deleted prior cache", err)
				}
				clear(actual)
			}
		})
	}
}

// Cancel the caller's real SDK renewal context after one admitted Store. The
// SDK's next Store and all of its rollback Deletes receive that same cancelled
// context; only its final releaseLock uses context.WithoutCancel.
type cancelIPSDKSave struct {
	certmagic.Storage
	mu                sync.Mutex
	afterKey          string
	privateKey        string
	certificate       string
	cancel            context.CancelFunc
	rollbackKeys      []string
	rollbackCancelled bool
	unlockCancelled   bool
}

func (s *cancelIPSDKSave) Store(ctx context.Context, key string, value []byte) error {
	err := s.Storage.Store(ctx, key, value)
	s.mu.Lock()
	var cancel context.CancelFunc
	if err == nil && key == s.afterKey {
		cancel, s.cancel = s.cancel, nil
	}
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return err
}

func (s *cancelIPSDKSave) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	if key == s.privateKey || key == s.certificate {
		s.rollbackKeys = append(s.rollbackKeys, key)
		s.rollbackCancelled = s.rollbackCancelled && errors.Is(ctx.Err(), context.Canceled)
	}
	s.mu.Unlock()
	return s.Storage.Delete(ctx, key)
}

func (s *cancelIPSDKSave) Unlock(ctx context.Context, key string) error {
	s.mu.Lock()
	s.unlockCancelled = s.unlockCancelled || ctx.Err() != nil
	s.mu.Unlock()
	return s.Storage.Unlock(ctx, key)
}

func TestIPSDKCancelledRollbackCannotReachNextARILease(t *testing.T) {
	for _, certificateStaged := range []bool{false, true} {
		for _, unlockFails := range []bool{false, true} {
			name := "after-key"
			if certificateStaged {
				name = "after-certificate"
			}
			if unlockFails {
				name += "/unlock-failure"
			} else {
				name += "/unlock-success"
			}
			t.Run(name, func(t *testing.T) {
				opt, ca, _ := ipFixture(t, "1.0.0.2")
				originalIssuer := opt.issuer
				var interrupted *cancelIPSDKSave
				opt.issuer = func(cfg *certmagic.Config) *certmagic.ACMEIssuer {
					interrupted = &cancelIPSDKSave{Storage: cfg.Storage, rollbackCancelled: true}
					cfg.Storage = interrupted
					return originalIssuer(cfg)
				}
				m, err := open(context.Background(), opt)
				if err != nil {
					t.Fatal(err)
				}
				defer m.Close()
				before := waitView(t, m, func(v certificate.View) bool { return v.State == Active && v.ServingMatches })
				prior, keys := ipCacheBytes(t, m), ipCacheKeys(m)
				issue := "issue_cert_" + opt.host
				// A failed SDK unlock deliberately retains its local fence.
				// Resolve it even if a later assertion fails, so Close can join.
				defer m.storage.Unlock(context.Background(), issue)
				last := 0
				if certificateStaged {
					last = 1
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				interrupted.mu.Lock()
				interrupted.afterKey, interrupted.cancel = keys[last], cancel
				interrupted.privateKey, interrupted.certificate = keys[0], keys[1]
				interrupted.mu.Unlock()
				if unlockFails {
					m.storage.mu.Lock()
					m.storage.backend = &ipLeaseFailure{Storage: m.storage.backend, unlockKey: issue}
					m.storage.mu.Unlock()
				}
				// Force only this deterministic cancellation boundary into the
				// real SDK save path. Automatic retry has separate acceptance.
				if err = m.cfg.RenewCertSync(ctx, opt.host, true); err == nil ||
					!errors.Is(ctx.Err(), context.Canceled) || !strings.Contains(err.Error(), "Renew: saving assets: context canceled") {
					t.Fatal("real SDK renewal did not return caller cancellation", err)
				}
				interrupted.mu.Lock()
				rollback := append([]string(nil), interrupted.rollbackKeys...)
				cancelled, unlockCancelled := interrupted.rollbackCancelled, interrupted.unlockCancelled
				interrupted.mu.Unlock()
				if len(rollback) != last+1 || !cancelled || unlockCancelled {
					t.Fatal("SDK rollback or final unlock context differed from the locked contract", len(rollback), cancelled, unlockCancelled)
				}
				for index, key := range rollback {
					if key != keys[last-index] {
						t.Fatal("SDK rollback did not visit prior Stores in reverse order")
					}
				}
				if unlockFails {
					if ok, err := m.storage.TryLock(context.Background(), "ari_cancelled_fixture"); ok || err != nil {
						t.Fatal("failed SDK unlock released its incomplete save to ARI", ok, err)
					}
					if err = m.storage.Unlock(context.Background(), issue); err != nil {
						t.Fatal("failed SDK unlock could not be resolved", err)
					}
				}
				if err = m.storage.Lock(context.Background(), "ari_cancelled_fixture"); err != nil {
					t.Fatal(err)
				}
				defer m.storage.Unlock(context.Background(), "ari_cancelled_fixture")
				// The real ARI writer loads the old admitted metadata under its
				// new lease. It must never commit a cancelled save's staged pair.
				meta, err := m.cfg.Storage.Load(context.Background(), keys[2])
				if err != nil {
					t.Fatal(err)
				}
				if err = m.cfg.Storage.Store(context.Background(), keys[2], append(meta, '\n')); err != nil {
					t.Fatal("independent ARI metadata update failed", err)
				}
				for index, key := range keys {
					want := prior[key]
					if index == 2 {
						want = append(append([]byte(nil), want...), '\n')
					}
					actual, err := m.cfg.Storage.Load(context.Background(), key)
					if err != nil || !bytes.Equal(actual, want) {
						t.Fatal("cancelled SDK stage reached a later ARI generation", index, err)
					}
					clear(actual)
				}
				if served, err := probe(context.Background(), opt.serving, opt.host, ca.roots); err != nil || served != before.Fingerprint {
					t.Fatal("cancelled SDK save replaced the existing TLS generation", err)
				}
				ca.mu.Lock()
				accounts := ca.accounts
				ca.mu.Unlock()
				if accounts != 1 {
					t.Fatal("cancelled SDK save replaced the ACME account", accounts)
				}
				waitIPChallengeReleased(t, opt.challenge)
			})
		}
	}
}

func TestIPARILeaseSerializesStagedSaveAndCancellation(t *testing.T) {
	for _, certStaged := range []bool{false, true} {
		for _, cancelled := range []bool{false, true} {
			for _, wrapped := range []bool{false, true} {
				name := "key"
				if certStaged {
					name = "certificate"
				}
				if cancelled {
					name += "/cancel"
				} else {
					name += "/commit"
				}
				if wrapped {
					name += "/wrapped-context"
				} else {
					name += "/same-context"
				}
				t.Run(name, func(t *testing.T) {
					opt, ca, _ := ipFixture(t, "1.1.1.3")
					m, err := open(context.Background(), opt)
					if err != nil {
						t.Fatal(err)
					}
					defer m.Close()
					waitView(t, m, func(v certificate.View) bool { return v.State == Active })
					prior := ipCacheBytes(t, m)
					keys, next := ipCacheKeys(m), replacementIPBytes(t, ca, opt.host)
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					ariCtx := context.Context(ctx)
					if wrapped {
						type ariContextKey struct{}
						ariCtx = context.WithValue(ctx, ariContextKey{}, "independent ARI")
					}
					issue := "issue_cert_" + opt.host
					if err = m.storage.Lock(ctx, issue); err != nil {
						t.Fatal(err)
					}
					held := true
					defer func() {
						if held {
							_ = m.storage.Unlock(context.Background(), issue)
						}
					}()
					last := 0
					if certStaged {
						last = 1
					}
					for part := 0; part <= last; part++ {
						if err = m.cfg.Storage.Store(ctx, keys[part], next[part]); err != nil {
							t.Fatal(err)
						}
					}
					if ok, err := m.storage.TryLock(ariCtx, "ari_try_fixture"); ok || err != nil {
						t.Fatal("ARI TryLock entered another operation's save", ok, err)
					}
					done := make(chan error, 1)
					started := make(chan struct{})
					go func() {
						close(started)
						if err := m.storage.Lock(ariCtx, "ari_wait_fixture"); err != nil {
							done <- err
							return
						}
						defer m.storage.Unlock(context.Background(), "ari_wait_fixture")
						// Just like the real SDK, read the current resource only
						// after acquiring the ARI lease, then update its metadata.
						meta, err := m.cfg.Storage.Load(ariCtx, keys[2])
						if err == nil {
							err = m.cfg.Storage.Store(ariCtx, keys[2], append(meta, '\n'))
						}
						done <- err
					}()
					<-started
					select {
					case err := <-done:
						t.Fatal("ARI Store entered an incomplete save", err)
					case <-time.After(20 * time.Millisecond):
					}
					for _, key := range keys {
						actual, err := m.cfg.Storage.Load(ctx, key)
						if err != nil || !bytes.Equal(actual, prior[key]) {
							t.Fatal("ARI interleave changed the old cache before commit", err)
						}
						clear(actual)
					}
					expected := prior
					if cancelled {
						stopped, stop := context.WithCancel(ctx)
						stop()
						if err = m.cfg.Storage.Store(stopped, keys[last+1], next[last+1]); !errors.Is(err, context.Canceled) {
							t.Fatal("cancelled save accepted", err)
						}
						for part := last; part >= 0; part-- {
							if err = m.cfg.Storage.Delete(context.Background(), keys[part]); err != nil {
								t.Fatal(err)
							}
						}
					} else {
						for part := last + 1; part < len(keys); part++ {
							if err = m.cfg.Storage.Store(ctx, keys[part], next[part]); err != nil {
								t.Fatal(err)
							}
						}
						expected = map[string][]byte{keys[0]: next[0], keys[1]: next[1], keys[2]: next[2]}
					}
					if err = m.storage.Unlock(context.Background(), issue); err != nil {
						t.Fatal(err)
					}
					held = false
					select {
					case err := <-done:
						if err != nil {
							t.Fatal("independent ARI update failed after save released", err)
						}
					case <-ctx.Done():
						t.Fatal("ARI lease leaked after save completed", ctx.Err())
					}
					for part, key := range keys {
						want := expected[key]
						if part == 2 {
							want = append(append([]byte(nil), want...), '\n')
						}
						actual, err := m.cfg.Storage.Load(ctx, key)
						if err != nil || !bytes.Equal(actual, want) {
							t.Fatal("ARI or rollback damaged certificate cache", part, err)
						}
						clear(actual)
					}
					ca.mu.Lock()
					accounts := ca.accounts
					ca.mu.Unlock()
					if accounts != 1 {
						t.Fatal("ARI isolation changed the ACME account", accounts)
					}
				})
			}
		}
	}
}

type ipLeaseFailure struct {
	certmagic.Storage
	lockKey, unlockKey string
}

func (s *ipLeaseFailure) Lock(ctx context.Context, key string) error {
	if key == s.lockKey {
		s.lockKey = ""
		return errors.New("injected lease acquisition failure")
	}
	return s.Storage.Lock(ctx, key)
}

func (s *ipLeaseFailure) Unlock(ctx context.Context, key string) error {
	if key == s.unlockKey {
		s.unlockKey = ""
		return errors.New("injected lease release failure")
	}
	return s.Storage.Unlock(ctx, key)
}

func TestIPARIFirstLeaseAndFailureFences(t *testing.T) {
	opt, ca, _ := ipFixture(t, "1.1.1.4")
	m, err := open(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	waitView(t, m, func(v certificate.View) bool { return v.State == Active })
	issue, ari := "issue_cert_"+opt.host, "ari_first_fixture"
	defer func() {
		_ = m.storage.Unlock(context.Background(), issue)
		_ = m.storage.Unlock(context.Background(), ari)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = m.storage.Lock(ctx, ari); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- m.storage.Lock(ctx, issue) }()
	select {
	case err := <-done:
		t.Fatal("issuance bypassed an active ARI metadata operation", err)
	case <-time.After(20 * time.Millisecond):
	}
	keys := ipCacheKeys(m)
	meta, err := m.cfg.Storage.Load(ctx, keys[2])
	if err != nil {
		t.Fatal(err)
	}
	if err = m.cfg.Storage.Store(ctx, keys[2], append(meta, '\n')); err != nil {
		t.Fatal(err)
	}
	if err = m.storage.Unlock(ctx, ari); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	wait, stop := context.WithTimeout(ctx, 30*time.Millisecond)
	defer stop()
	if err = m.storage.Lock(wait, ari); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("local lease wait ignored cancellation", err)
	}
	if err = m.storage.Unlock(ctx, issue); err != nil {
		t.Fatal(err)
	}
	m.storage.mu.Lock()
	m.storage.backend = &ipLeaseFailure{Storage: m.storage.backend, lockKey: issue, unlockKey: issue}
	m.storage.mu.Unlock()
	if err = m.storage.Lock(ctx, issue); err == nil {
		t.Fatal("injected backend Lock failure was accepted")
	}
	if ok, err := m.storage.TryLock(ctx, ari); !ok || err != nil {
		t.Fatal("failed Lock leaked the local operation gate", ok, err)
	}
	if err = m.storage.Unlock(ctx, ari); err != nil {
		t.Fatal(err)
	}
	if err = m.storage.Lock(ctx, issue); err != nil {
		t.Fatal(err)
	}
	if err = m.storage.Unlock(ctx, issue); err == nil {
		t.Fatal("injected backend Unlock failure was accepted")
	}
	if ok, err := m.storage.TryLock(ctx, ari); ok || err != nil {
		t.Fatal("failed Unlock released a different operation owner", ok, err)
	}
	if err = m.storage.Unlock(ctx, issue); err != nil {
		t.Fatal("successful Unlock retry could not release the owned fence", err)
	}
	if ok, err := m.storage.TryLock(ctx, ari); !ok || err != nil {
		t.Fatal("successful Unlock retained the gate", ok, err)
	}
	if err = m.cfg.Storage.Store(ctx, keys[2], meta); err != nil {
		t.Fatal("independent ARI update failed after recovery", err)
	}
	if err = m.storage.Unlock(ctx, ari); err != nil {
		t.Fatal(err)
	}
	ca.mu.Lock()
	accounts := ca.accounts
	ca.mu.Unlock()
	if accounts != 1 {
		t.Fatal("lease failure reset the ACME account", accounts)
	}
}

func TestIPWatchdogDoesNotReleaseSDKOperationLease(t *testing.T) {
	opt, _, _ := ipFixture(t, "1.1.1.5")
	opt.attemptTimeout = 2 * time.Second
	m, err := open(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	waitView(t, m, func(v certificate.View) bool { return v.State == Active })
	issue := "issue_cert_" + opt.host
	if err = m.storage.Lock(context.Background(), issue); err != nil {
		t.Fatal(err)
	}
	defer m.storage.Unlock(context.Background(), issue)
	if err = m.beginAttempt(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	waitView(t, m, func(v certificate.View) bool { return v.LastError == "ca_timeout" })
	if ok, err := m.storage.TryLock(context.Background(), "ari_watchdog_fixture"); ok || err != nil {
		t.Fatal("challenge watchdog released the SDK save/ARI operation fence", ok, err)
	}
	waitIPChallengeReleased(t, opt.challenge)
}

func TestIPInvalidCACertificateAutomaticRecoveryAcceptance(t *testing.T) {
	if os.Getenv("FC_IP_CERTIFICATE_RETRY_ACCEPTANCE") != "1" {
		t.Skip("development-only real CertMagic automatic retry intervals")
	}
	for _, renewal := range []bool{false, true} {
		name := "initial"
		if renewal {
			name = "renewal"
		}
		t.Run(name, func(t *testing.T) {
			opt, ca, serving := ipFixture(t, "8.26.56.26")
			opt.retryDelay = time.Second
			opt.renewCheck = 100 * time.Millisecond
			if renewal {
				ca.ariWindowStart = time.Now().Add(8 * time.Second)
				ca.ariWindowEnd = ca.ariWindowStart.Add(6 * time.Second)
			} else {
				ca.ipValidity = 90 * 24 * time.Hour
			}
			m, err := open(context.Background(), opt)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			var before certificate.View
			var prior map[string][]byte
			if renewal {
				before = waitView(t, m, func(v certificate.View) bool { return v.State == Active && v.ServingMatches })
				prior = ipCacheBytes(t, m)
				ca.mu.Lock()
				ca.ipValidity = 90 * 24 * time.Hour
				ca.mu.Unlock()
			}
			deadline := time.Now().Add(35 * time.Second)
			var rejected certificate.View
			for time.Now().Before(deadline) {
				rejected = m.Status()
				if rejected.LastError == "certificate_issuance_invalid" &&
					(rejected.State == Failed || rejected.State == Degraded) {
					break
				}
				time.Sleep(30 * time.Millisecond)
			}
			if rejected.LastError != "certificate_issuance_invalid" {
				t.Fatal("CA long certificate was not rejected before SDK success", rejected)
			}
			waitIPChallengeReleased(t, opt.challenge)
			keys := ipCacheKeys(m)
			if renewal {
				if rejected.Fingerprint != before.Fingerprint || !rejected.HTTPSReady || !rejected.ServingMatches || rejected.LastRenewal != "failed" {
					t.Fatal("rejected CA renewal replaced or disabled valid short certificate", rejected)
				}
				if served, err := probe(context.Background(), opt.serving, opt.host, ca.roots); err != nil || served != before.Fingerprint {
					t.Fatal("old short certificate did not actually serve after rejected CA renewal", err)
				}
				for _, key := range keys {
					actual, err := m.cfg.Storage.Load(context.Background(), key)
					if err != nil || !bytes.Equal(actual, prior[key]) {
						t.Fatal("rejected CA renewal poisoned prior three-file cache", err)
					}
					clear(actual)
				}
			} else {
				if _, err := serving.GetCertificate(nil); err == nil {
					t.Fatal("initial invalid CA certificate was served")
				}
				for _, key := range keys {
					if m.cfg.Storage.Exists(context.Background(), key) {
						t.Fatal("initial rejected CA certificate left committed cache material")
					}
				}
			}
			ca.mu.Lock()
			rejectedCount, accounts := ca.issued, ca.accounts
			ca.ipValidity = 0
			ca.mu.Unlock()
			if accounts != 1 || renewal && rejectedCount != 2 || !renewal && rejectedCount != 1 {
				t.Fatal("unexpected rejection/account history", rejectedCount, accounts)
			}
			// No forced renewal or manual Manage/Obtain call: the original
			// SDK issuance/renewal task must complete its own scheduled retry.
			deadline = time.Now().Add(100 * time.Second)
			for time.Now().Before(deadline) {
				view := m.Status()
				if view.State == Active && view.ServingMatches && view.HTTPSReady &&
					view.Fingerprint != before.Fingerprint && view.NotAfter-view.NotBefore == int64(160*time.Hour/time.Second) {
					ca.mu.Lock()
					issued, currentAccounts := ca.issued, ca.accounts
					ca.mu.Unlock()
					if issued != rejectedCount+1 || currentAccounts != accounts {
						t.Fatal("automatic retry lost account or issued unexpectedly", issued, currentAccounts)
					}
					cached := ipCacheBytes(t, m)
					if _, err := Validate(opt.host, cached[keys[1]], cached[keys[0]], ca.roots, time.Now()); err != nil {
						t.Fatal("automatic retry did not leave a valid short certificate cache", err)
					}
					if served, err := probe(context.Background(), opt.serving, opt.host, ca.roots); err != nil || served != view.Fingerprint {
						t.Fatal("automatically recovered short certificate was not actually served", err)
					}
					released(t, opt.challenge)
					return
				}
				time.Sleep(50 * time.Millisecond)
			}
			t.Fatal("corrected CA did not recover through real automatic retry", m.Status())
		})
	}
}
