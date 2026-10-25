// Package certmanager manages node-local automatic TLS. ACME assets remain in
// private storage; complete serving generations occupy a separate volume.
package certmanager

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
)

const (
	PrivateDirectory   = "/var/lib/frontiercloud-certificate"
	PublishedDirectory = "/run/frontiercloud-tls"
	RuntimeDirectory   = "/run/frontiercloud-certificate"
	ControlSocket      = RuntimeDirectory + "/control.sock"
)

var generationName = regexp.MustCompile(`^[a-f0-9]{32}$`)

func readBounded(path string, limit int64) ([]byte, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("certificate asset is not a regular file")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) {
		return nil, errors.New("certificate asset changed during read")
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(b)) > limit {
		return nil, errors.New("certificate asset exceeds size limit")
	}
	return b, e
}

type generation struct {
	Generation string `json:"generation"`
	Previous   string `json:"previous,omitempty"`
}

// Validate uses Go's chain verifier, including DNS, time, key matching and
// server authentication. roots is only injected by in-process test fixtures;
// production uses the system trust store and has no insecure/CA-path option.
func Validate(host string, cert, key []byte, roots *x509.CertPool, now time.Time) (*tls.Certificate, error) {
	if len(cert) == 0 || len(cert) > 65536 || len(key) == 0 || len(key) > 16384 {
		return nil, errors.New("certificate pair size invalid")
	}
	p, err := tls.X509KeyPair(cert, key)
	if err != nil || len(p.Certificate) == 0 || len(p.Certificate) > 8 {
		return nil, errors.New("certificate/private key mismatch")
	}
	leaf, err := x509.ParseCertificate(p.Certificate[0])
	if err != nil {
		return nil, errors.New("certificate parse failed")
	}
	// Public IP issuance explicitly selects the CA's shortlived profile. Never
	// publish a silently substituted long-lived IP certificate from another
	// profile, including an otherwise trusted imported generation.
	if certificate.IsIP(host) && (leaf.NotAfter.Sub(leaf.NotBefore) <= 0 || leaf.NotAfter.Sub(leaf.NotBefore) > 7*24*time.Hour) {
		return nil, errors.New("IP certificate does not match the short-lived policy")
	}
	intermediates := x509.NewCertPool()
	for _, der := range p.Certificate[1:] {
		c, e := x509.ParseCertificate(der)
		if e != nil {
			return nil, errors.New("certificate chain parse failed")
		}
		intermediates.AddCert(c)
	}
	if _, err = leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, fmt.Errorf("certificate chain verification failed: %w", err)
	}
	p.Leaf = leaf
	return &p, nil
}

func fingerprint(p *tls.Certificate) string {
	h := sha256.Sum256(p.Certificate[0])
	return hex.EncodeToString(h[:])
}

func atomic(path string, b []byte, mode os.FileMode) error {
	r := make([]byte, 16)
	if _, e := rand.Read(r); e != nil {
		return e
	}
	next := path + ".next-" + hex.EncodeToString(r)
	f, e := os.OpenFile(next, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if e != nil {
		return e
	}
	defer os.Remove(next)
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e = os.Rename(next, path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}

func pointer(directory string) (generation, error) {
	var g generation
	b, e := readBounded(filepath.Join(directory, "current.json"), 256)
	if e != nil {
		return g, e
	}
	if e != nil || len(b) > 256 || json.Unmarshal(b, &g) != nil || !generationName.MatchString(g.Generation) {
		return g, errors.New("invalid TLS generation pointer")
	}
	return g, nil
}

func readGeneration(directory string) ([]byte, []byte, error) {
	g, e := pointer(directory)
	if e != nil {
		return nil, nil, e
	}
	return readNamedGeneration(directory, g.Generation)
}
func readNamedGeneration(directory, id string) ([]byte, []byte, error) {
	if !generationName.MatchString(id) {
		return nil, nil, errors.New("invalid TLS generation")
	}
	info, e := os.Lstat(filepath.Join(directory, id))
	if e != nil {
		return nil, nil, e
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("invalid TLS generation directory")
	}
	read := func(name string, limit int64) ([]byte, error) {
		return readBounded(filepath.Join(directory, id, name), limit)
	}
	c, e := read("fullchain.pem", 65536)
	if e != nil {
		return nil, nil, e
	}
	k, e := read("privkey.pem", 16384)
	return c, k, e
}

// The pointer changes only after both files have been durably written and
// validated. Consumers select one generation, never two independent files.
func publish(directory, host string, cert, key []byte, roots *x509.CertPool) (*tls.Certificate, error) {
	p, e := Validate(host, cert, key, roots, time.Now())
	if e != nil {
		return nil, e
	}
	previous := ""
	if g, e := pointer(directory); e == nil {
		previous = g.Generation
	}
	r := make([]byte, 16)
	if _, e = rand.Read(r); e != nil {
		return nil, e
	}
	id := hex.EncodeToString(r)
	dir := filepath.Join(directory, id)
	if e = os.Mkdir(dir, 0750); e != nil {
		return nil, e
	}
	if e = os.Chmod(dir, 0750); e != nil {
		return nil, e
	}
	committed := false
	defer func() {
		if !committed {
			g, e := pointer(directory)
			if e != nil || g.Generation != id {
				_ = os.RemoveAll(dir)
			}
		}
	}()
	if e = atomic(filepath.Join(dir, "fullchain.pem"), cert, 0640); e != nil {
		return nil, e
	}
	if e = atomic(filepath.Join(dir, "privkey.pem"), key, 0640); e != nil {
		return nil, e
	}
	b, _ := json.Marshal(generation{Generation: id, Previous: previous})
	if e = atomic(filepath.Join(directory, "current.json"), b, 0640); e != nil {
		return nil, e
	}
	committed = true
	return p, nil
}

// Only a verified serving handshake authorizes reclamation of older assets.
// Failed Nginx reloads retain the generation that its rollback config references.
func prune(directory string) {
	g, e := pointer(directory)
	if e != nil {
		return
	}
	entries, e := os.ReadDir(directory)
	if e != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() && generationName.MatchString(entry.Name()) && entry.Name() != g.Generation && entry.Name() != g.Previous {
			_ = os.RemoveAll(filepath.Join(directory, entry.Name()))
		}
	}
}
