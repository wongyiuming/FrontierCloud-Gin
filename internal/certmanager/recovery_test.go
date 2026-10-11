package certmanager

import (
	"context"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
)

func TestCAFailuresPreserveValidIdentityAndPersistBackoff(t *testing.T) {
	for problem, code := range map[string]string{"caa": "caa", "connection": "http01_unreachable", "unauthorized": "authorization", "serverInternal": "ca_unavailable", "rejectedIdentifier": "domain_rejected"} {
		t.Run(problem, func(t *testing.T) {
			opt, ca, _ := fixture(t, Relay)
			m, err := open(context.Background(), opt)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			original := waitView(t, m, func(v certificate.View) bool { return v.State == Active })
			ca.mu.Lock()
			ca.problem = problem
			ca.mu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err = m.cfg.RenewCertSync(ctx, opt.host, true); err == nil {
				t.Fatal("CA rejection accepted")
			}
			view := waitView(t, m, func(v certificate.View) bool { return v.LastError == code })
			if view.Fingerprint != original.Fingerprint || !view.HTTPSReady || !view.ServingMatches || view.State != Degraded {
				t.Fatal("failed renewal changed valid service", view)
			}
			m.mu.Lock()
			retry := m.journal.RetryAt
			m.mu.Unlock()
			if retry < time.Now().Add(4*time.Minute).Unix() {
				t.Fatal("CA failure has no bounded retry cooldown")
			}
			released(t, opt.challenge)
			m.Close()
			ca.mu.Lock()
			ca.problem = ""
			before := ca.issued
			ca.mu.Unlock()
			restored, err := open(context.Background(), opt)
			if err != nil {
				t.Fatal(err)
			}
			defer restored.Close()
			view = waitView(t, restored, func(v certificate.View) bool { return v.HTTPSReady })
			if view.State != Degraded || view.LastError != code {
				t.Fatal("restart erased failed renewal diagnostics", view)
			}
			ca.mu.Lock()
			issued := ca.issued
			ca.mu.Unlock()
			if issued != before {
				t.Fatal("restart bypassed persistent CA cooldown")
			}
		})
	}
}

func TestServingRejectsBadIdentityAndRetainsValidPairOnBrokenRotation(t *testing.T) {
	opt, _, serving := fixture(t, Relay)
	m, err := open(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	waitView(t, m, func(v certificate.View) bool { return v.State == Active })
	old, err := serving.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = serving.GetCertificate(&tls.ClientHelloInfo{ServerName: "wrong.fixture.test"}); err == nil {
		t.Fatal("unmanaged SNI admitted")
	}
	g, err := pointer(opt.published)
	if err != nil {
		t.Fatal(err)
	}
	if err = atomic(filepath.Join(opt.published, g.Generation, "privkey.pem"), []byte("corrupt key"), 0640); err != nil {
		t.Fatal(err)
	}
	serving.mu.Lock()
	serving.checked = time.Time{}
	serving.mu.Unlock()
	retained, err := serving.GetCertificate(nil)
	if err != nil || fingerprint(retained) != fingerprint(old) {
		t.Fatal("broken rotation discarded live valid TLS", err)
	}
	empty := &Serving{host: opt.host, directory: opt.published, roots: opt.roots}
	if _, err = empty.GetCertificate(nil); err == nil {
		t.Fatal("restart trusted corrupt key")
	}
	serving.mu.Lock()
	serving.pair.Leaf.NotAfter = time.Now().Add(-time.Second)
	serving.mu.Unlock()
	if _, err = serving.GetCertificate(nil); err == nil {
		t.Fatal("expired cached certificate admitted")
	}
}

func TestLegacyOwnedGenerationAdoptionRestoresWithoutIssuance(t *testing.T) {
	opt, ca, _ := fixture(t, Relay)
	m, err := open(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	initial := waitView(t, m, func(v certificate.View) bool { return v.State == Active })
	cert, key, err := readGeneration(opt.published)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	m.Close()
	recovery := t.TempDir()
	for _, entry := range []struct {
		name string
		mode os.FileMode
	}{{"private", 0700}, {"published", 0750}, {"runtime", 0710}} {
		if err = os.Mkdir(filepath.Join(recovery, entry.name), entry.mode); err != nil {
			t.Fatal(err)
		}
	}
	opt.private = filepath.Join(recovery, "private")
	opt.published = filepath.Join(recovery, "published")
	opt.runtime = filepath.Join(recovery, "runtime")
	if _, err = publish(opt.private, opt.host, cert, key, opt.roots); err != nil {
		t.Fatal(err)
	}
	restored, err := open(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	view := waitView(t, restored, func(v certificate.View) bool { return v.State == Active })
	if view.Fingerprint != initial.Fingerprint {
		t.Fatal("legacy migration changed identity")
	}
	ca.mu.Lock()
	issued := ca.issued
	ca.mu.Unlock()
	if issued != 1 {
		t.Fatal("valid restored legacy generation caused reissuance", issued)
	}
}

func TestSymlinkAssetsNeverReadAsManagedCertificate(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "asset")
	if err := os.WriteFile(path, []byte("private fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(link, 1024); err == nil {
		t.Fatal("symlink certificate asset admitted")
	}
}

func TestBrokenPrivateCacheIsDiagnosedWithoutReplacingServingPair(t *testing.T) {
	opt, _, _ := fixture(t, Relay)
	m, err := open(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	original := waitView(t, m, func(v certificate.View) bool { return v.State == Active })
	key := certmagic.StorageKeys.SitePrivateKey(m.issuer.IssuerKey(), opt.host)
	old, err := m.cfg.Storage.Load(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(old)
	if err = m.cfg.Storage.Store(context.Background(), key, []byte("corrupt private cache")); err != nil {
		t.Fatal(err)
	}
	m.refresh()
	view := m.Status()
	if view.State != Degraded || view.LastError != "certificate_validation" || !view.HTTPSReady || view.Fingerprint != original.Fingerprint {
		t.Fatal("private cache corruption was hidden or replaced valid serving pair", view)
	}
	if err = m.cfg.Storage.Store(context.Background(), key, old); err != nil {
		t.Fatal(err)
	}
	m.refresh()
	view = m.Status()
	if view.State != Active || view.LastError != "" || !view.ServingMatches {
		t.Fatal("restored private cache did not recover", view)
	}
}

func TestPublishedDiskDamageRecoversFromVerifiedPrivateCache(t *testing.T) {
	opt, _, _ := fixture(t, Relay)
	m, err := open(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	original := waitView(t, m, func(v certificate.View) bool { return v.State == Active })
	before, err := pointer(opt.published)
	if err != nil {
		t.Fatal(err)
	}
	if err = atomic(filepath.Join(opt.published, before.Generation, "privkey.pem"), []byte("damaged disk asset"), 0640); err != nil {
		t.Fatal(err)
	}
	m.refresh()
	after, err := pointer(opt.published)
	if err != nil || before.Generation == after.Generation {
		t.Fatal("remembered status hid damaged serving assets", err)
	}
	cert, key, err := readGeneration(opt.published)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	pair, err := Validate(opt.host, cert, key, opt.roots, time.Now())
	if err != nil || fingerprint(pair) != original.Fingerprint {
		t.Fatal("disk recovery changed verified identity", err)
	}
	m.mu.Lock()
	m.view.Fingerprint = "different-generation"
	m.view.ServingMatches = true
	m.mu.Unlock()
	if m.Status().ServingMatches {
		t.Fatal("new generation reused previous serving proof")
	}
}

func TestCorruptLifecycleJournalKeepsControllerDiagnosticAndDisabledModeIntact(t *testing.T) {
	opt, _, _ := fixture(t, Relay)
	path := filepath.Join(opt.private, "lifecycle.json")
	broken := []byte("invalid persisted lifecycle")
	if err := os.WriteFile(path, broken, 0600); err != nil {
		t.Fatal(err)
	}
	opt.enabled = false
	disabled, err := open(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if view := disabled.Status(); view.State != Disabled || !view.ControllerRunning {
		t.Fatal("disabled mode depends on TLS journal", view)
	}
	disabled.Close()
	content, err := os.ReadFile(path)
	if err != nil || string(content) != string(broken) {
		t.Fatal("HTTP mode rewrote TLS recovery material", err)
	}
	opt.enabled = true
	managed, err := open(context.Background(), opt)
	if err != nil {
		t.Fatal("corrupt lifecycle caused a crash loop", err)
	}
	defer managed.Close()
	view := managed.Status()
	if !view.ControllerRunning || view.LastError != "journal_recovered" || view.HTTPSReady {
		t.Fatal("corrupt journal produced fake readiness", view)
	}
	archives, err := filepath.Glob(filepath.Join(opt.private, "lifecycle-invalid-*.json"))
	if err != nil || len(archives) != 1 {
		t.Fatal("original damaged journal not preserved", err)
	}
	content, err = os.ReadFile(archives[0])
	if err != nil || string(content) != string(broken) {
		t.Fatal("corrupt journal recovery lost original", err)
	}
	managed.mu.Lock()
	retry := managed.journal.RetryAt
	managed.mu.Unlock()
	if retry < time.Now().Add(4*time.Minute).Unix() {
		t.Fatal("journal recovery forgot conservative rate-limit cooldown")
	}
}
