package certmanager

// Only the opt-in test binary supplies a private ACME authority. Production
// installation retains its fixed public CA and certificate trust policy.
import (
	"context"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func TestAutomaticTLSInstallFixture(t *testing.T) {
	profile := Profile(os.Getenv("FRONTIERCLOUD_TEST_INSTALL_TLS_PROFILE"))
	if profile == "" {
		t.Skip("requires isolated native installation fixture")
	}
	if profile != Business && profile != Direct && profile != Relay || os.Geteuid() != 0 || os.Getegid() != 10001 {
		t.Fatal("invalid installation certificate fixture")
	}
	host, challenge, serving := "storage.fixture.test", "localhost:80", "storage.fixture.test:443"
	if profile == Business {
		host, challenge, serving = "business.fixture.test", "nginx:80", "business.fixture.test:443"
	} else if profile == Relay {
		serving = "storage.fixture.test:8443"
	}
	ca := newCA(t, host, challenge)
	if os.Getenv("FRONTIERCLOUD_TEST_INSTALL_CA_FAILURE") == "1" {
		ca.mu.Lock()
		ca.problem = "rejectedIdentifier"
		ca.mu.Unlock()
	}
	if e := os.WriteFile("/fixture/ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.root.Raw}), 0644); e != nil {
		t.Fatal(e)
	}
	opt := options{host: host, enabled: true, profile: profile, private: PrivateDirectory, published: PublishedDirectory, runtime: RuntimeDirectory, challenge: ":80", serving: serving, ca: ca.server.URL + "/directory", roots: ca.roots}
	if profile == Business {
		opt.ingress = "http://nginx/.well-known/acme-challenge/frontiercloud-readiness"
	}
	opt.issuer = func(cfg *certmagic.Config) *certmagic.ACMEIssuer {
		return certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{CA: opt.ca, Agreed: true, DisableTLSALPNChallenge: true, AltHTTPPort: 80, CertObtainTimeout: 20 * time.Second, Logger: zap.NewNop()})
	}
	m, e := open(context.Background(), opt)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	control := make(chan error, 1)
	go func() { control <- m.Serve() }()
	if e := os.WriteFile("/fixture/ca-ready", []byte("ready"), 0644); e != nil {
		t.Fatal(e)
	}
	// The operator fixture stops this exact controller after checking both the
	// native serving fingerprint and restart stability. It remains resident
	// throughout Compose --wait, as the production controller does.
	deadline := time.NewTimer(12 * time.Minute)
	defer deadline.Stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case e := <-control:
			t.Fatal("fixture controller stopped early", e)
		case <-deadline.C:
			t.Fatal("installation fixture exceeded bounded lifetime")
		case <-ticker.C:
			v := m.Status()
			marker := ""
			if v.State == Active && v.HTTPSReady && v.ServingMatches {
				marker = "issued-and-serving"
			} else if v.State == Failed && v.LastError == "domain_rejected" {
				marker = "ca-rejected"
			}
			if marker != "" {
				if e := os.WriteFile(filepath.Join("/fixture", marker), []byte("verified"), 0644); e != nil {
					t.Fatal(e)
				}
			}
		}
	}
}
