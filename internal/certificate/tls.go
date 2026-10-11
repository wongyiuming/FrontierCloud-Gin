// Package certificate keeps TLS keys on their storage host and publishes pairs atomically.
package certificate

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

type Pair struct {
	Generation string `json:"generation"`
}

var generationPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type View struct {
	Hostname    string `json:"hostname"`
	NotBefore   int64  `json:"not_before,omitempty"`
	NotAfter    int64  `json:"not_after,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	State       string `json:"state"`
	Managed     bool   `json:"managed"`
	AutoRenew   bool   `json:"auto_renew"`
	Validation  string `json:"validation,omitempty"`
	Job         Job    `json:"job"`
}
type TLS struct {
	mu                                 sync.Mutex
	host, directory, certFile, keyFile string
	pair                               *tls.Certificate
	checked                            time.Time
	generation                         string
}

func NewTLS(host, directory, certFile, keyFile string) (*TLS, error) {
	t := &TLS{host: host, directory: directory, certFile: certFile, keyFile: keyFile}
	if _, e := t.GetCertificate(nil); e != nil {
		return nil, e
	}
	return t, nil
}
func loadPair(host, certFile, keyFile string) (*tls.Certificate, error) {
	p, e := tls.LoadX509KeyPair(certFile, keyFile)
	if e != nil || len(p.Certificate) == 0 {
		return nil, errors.New("certificate pair unavailable")
	}
	leaf, e := x509.ParseCertificate(p.Certificate[0])
	if e != nil || leaf.VerifyHostname(host) != nil || time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
		return nil, errors.New("certificate hostname or validity mismatch")
	}
	p.Leaf = leaf
	return &p, nil
}
func pairView(host string, p *tls.Certificate) View {
	v := View{Hostname: host, State: "unavailable"}
	leaf := p.Leaf
	if leaf == nil {
		leaf, _ = x509.ParseCertificate(p.Certificate[0])
	}
	if leaf == nil || leaf.VerifyHostname(host) != nil {
		return v
	}
	h := sha256.Sum256(p.Certificate[0])
	v.NotBefore = leaf.NotBefore.Unix()
	v.NotAfter = leaf.NotAfter.Unix()
	v.Fingerprint = hex.EncodeToString(h[:])
	v.State = "valid"
	if !time.Now().Before(leaf.NotAfter) {
		v.State = "expired"
	} else if time.Now().Before(leaf.NotBefore) {
		v.State = "not_yet_valid"
	} else if time.Until(leaf.NotAfter) < 30*24*time.Hour {
		v.State = "renewal_due"
	}
	return v
}
func manifest(directory string) (Pair, error) {
	var p Pair
	f, e := os.Open(filepath.Join(directory, "current.json"))
	if e != nil {
		return p, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 257))
	if e != nil || len(b) > 256 || json.Unmarshal(b, &p) != nil || !generationPattern.MatchString(p.Generation) {
		return p, errors.New("invalid certificate generation")
	}
	return p, nil
}

// A renewal never reloads a half-written certificate/key pair or drops a good pair.
// Stat/parse work is bounded to once per five seconds, independent of TLS traffic.
func (t *TLS) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pair != nil && time.Since(t.checked) < 5*time.Second {
		return t.valid()
	}
	t.checked = time.Now()
	certFile, keyFile := t.certFile, t.keyFile
	next := "bootstrap"
	if t.directory != "" {
		if p, e := manifest(t.directory); e == nil {
			next = p.Generation
			certFile = filepath.Join(t.directory, next, "fullchain.pem")
			keyFile = filepath.Join(t.directory, next, "privkey.pem")
		} else if t.pair != nil && t.generation != "bootstrap" {
			return t.valid()
		}
	}
	if t.pair == nil || next != t.generation {
		if p, e := loadPair(t.host, certFile, keyFile); e == nil {
			t.pair = p
			t.generation = next
		} else if t.pair == nil {
			return nil, e
		}
	}
	return t.valid()
}
func (t *TLS) valid() (*tls.Certificate, error) {
	if t.pair == nil || time.Now().Before(t.pair.Leaf.NotBefore) || !time.Now().Before(t.pair.Leaf.NotAfter) {
		return nil, errors.New("certificate expired")
	}
	return t.pair, nil
}
func (t *TLS) Status() View {
	p, e := t.GetCertificate(nil)
	if e != nil {
		t.mu.Lock()
		p = t.pair
		t.mu.Unlock()
	}
	if p == nil {
		return View{Hostname: t.host, State: "unavailable", Managed: t.directory != ""}
	}
	v := pairView(t.host, p)
	v.Managed = t.directory != ""
	return v
}
