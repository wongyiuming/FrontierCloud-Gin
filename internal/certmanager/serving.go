package certmanager

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"
	"time"
)

// Serving only reads complete published generations. Absence is a pending
// controller state, not permission to serve plaintext or create a fake key.
type Serving struct {
	mu                          sync.Mutex
	host, directory, generation string
	roots                       *x509.CertPool
	checked                     time.Time
	pair                        *tls.Certificate
}

func NewServing(host string) *Serving { return &Serving{host: host, directory: PublishedDirectory} }
func (s *Serving) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if hello != nil && hello.ServerName != "" && hello.ServerName != s.host {
		return nil, errors.New("unmanaged TLS server name")
	}
	now := time.Now()
	if now.Sub(s.checked) >= 5*time.Second || s.pair == nil {
		s.checked = now
		g, e := pointer(s.directory)
		if e == nil && (s.pair == nil || g.Generation != s.generation) {
			cert, key, e := readNamedGeneration(s.directory, g.Generation)
			if e == nil {
				if p, e := Validate(s.host, cert, key, s.roots, now); e == nil {
					s.pair = p
					s.generation = g.Generation
				}
			}
		}
	}
	if s.pair == nil {
		return nil, errors.New("automatic TLS certificate pending")
	}
	if now.Before(s.pair.Leaf.NotBefore) || !now.Before(s.pair.Leaf.NotAfter) {
		return nil, errors.New("automatic TLS certificate expired or not yet valid")
	}
	return s.pair, nil
}
