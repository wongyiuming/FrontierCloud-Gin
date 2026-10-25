package certmanager

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
)

// CertMagic's saveCertResource writes key, certificate, metadata in that order.
// Its storeTx rollback deletes earlier keys even if they previously existed.
// Only this node's three IP certificate keys are staged until the complete pair
// has passed the shipping verifier. Accounts, DNS certificates and other SDK
// records retain their existing storage behavior.
type ipCertificateStorage struct {
	host, privateKey, certificate, metadata string
	roots                                   *x509.CertPool
	capture                                 func() func(string)
	pending                                 *ipCertificateWrite
	rollback                                map[string]bool
	operation                               chan struct{}
}

type ipCertificateWrite struct {
	key, cert []byte
	finish    func(string)
}

// The locked SDK uses separate certificate-save and ARI-update lock names.
// Serialize those two operations locally too: ARI must not interpret staged
// material as its metadata target, or overwrite metadata of a new generation.
// This is bound to the SDK's Lock/Unlock lease, not context pointer identity.
func (s *ipCertificateStorage) acquireOperation(ctx context.Context, name string, try bool) (func(), bool, error) {
	if name != "issue_cert_"+s.host && !strings.HasPrefix(name, "ari_") {
		return nil, true, nil
	}
	if try {
		select {
		case s.operation <- struct{}{}:
		default:
			return nil, false, nil
		}
	} else {
		select {
		case s.operation <- struct{}{}:
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}
	return func() { <-s.operation }, true, nil
}

func (s *ipCertificateStorage) clearPending() {
	if s.pending != nil {
		clear(s.pending.key)
		clear(s.pending.cert)
		s.pending = nil
	}
}

func (s *ipCertificateStorage) reject(code string, prior []string) func() {
	var finish func(string)
	if s.pending != nil {
		finish = s.pending.finish
	}
	s.clearPending()
	s.rollback = make(map[string]bool, len(prior))
	for _, key := range prior {
		s.rollback[key] = true
	}
	if finish == nil {
		return nil
	}
	return func() { finish(code) }
}

// A rejected staged Store never changed those earlier keys. Absorb precisely
// the SDK's corresponding rollback deletes so it cannot erase the old pair.
func (s *ipCertificateStorage) rollbackDelete(key string) bool {
	if s.pending != nil && (key == s.privateKey || key == s.certificate) {
		// The next Store can be cancelled before it reaches admission. Its
		// earlier staged keys still never reached the backend, even when the
		// SDK performs rollback with a fresh cleanup context.
		prior := []string{s.privateKey}
		if len(s.pending.cert) > 0 {
			prior = append(prior, s.certificate)
		}
		s.reject("", prior)
	}
	if !s.rollback[key] {
		return false
	}
	delete(s.rollback, key)
	return true
}

func (s *ipCertificateStorage) store(ctx context.Context, backend certmagic.Storage, key string, value []byte, finish func(string)) (bool, error, func()) {
	switch key {
	case s.privateKey:
		s.clearPending()
		s.rollback = nil
		s.pending = &ipCertificateWrite{finish: finish}
		if len(value) == 0 || len(value) > 16384 {
			return true, errors.New("IP certificate private key admission refused"),
				s.reject("certificate_issuance_invalid", nil)
		}
		s.pending.key = append([]byte(nil), value...)
		return true, nil, nil
	case s.certificate:
		if s.pending == nil {
			return true, errors.New("IP certificate requires its staged private key"), nil
		}
		if _, err := Validate(s.host, value, s.pending.key, s.roots, time.Now()); err != nil {
			return true, errors.New("IP certificate cache admission refused"),
				s.reject("certificate_issuance_invalid", []string{s.privateKey})
		}
		s.pending.cert = append([]byte(nil), value...)
		return true, nil, nil
	case s.metadata:
		if s.pending == nil {
			// CertMagic independently persists ARI updates for an already
			// admitted certificate. These do not replace its key or chain.
			return false, nil, nil
		}
		if len(s.pending.cert) == 0 || len(value) == 0 || len(value) > 65536 || !json.Valid(value) {
			return true, errors.New("IP certificate metadata admission refused"),
				s.reject("certificate_issuance_invalid", []string{s.privateKey, s.certificate})
		}
		if err := s.commit(ctx, backend, value); err != nil {
			return true, err,
				s.reject("certificate_cache_unwritable", []string{s.privateKey, s.certificate})
		}
		s.clearPending()
		s.rollback = nil
		return true, nil, nil
	}
	return false, nil, nil
}

// This is the narrow counterpart of the SDK's three-file certificate save,
// not a new general storage transaction. All accesses run under Storage.mu.
// A backend failure restores existing bytes instead of deleting an old key.
func (s *ipCertificateStorage) commit(ctx context.Context, backend certmagic.Storage, metadata []byte) error {
	type item struct {
		key       string
		value     []byte
		old       []byte
		oldExists bool
		limit     int
	}
	items := []item{
		{key: s.privateKey, value: s.pending.key, limit: 16384},
		{key: s.certificate, value: s.pending.cert, limit: 65536},
		{key: s.metadata, value: metadata, limit: 65536},
	}
	defer func() {
		for _, entry := range items {
			clear(entry.old)
		}
	}()
	for index := range items {
		entry := &items[index]
		var err error
		entry.old, err = backend.Load(ctx, entry.key)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("IP certificate prior cache cannot be read")
		}
		entry.oldExists = err == nil
		if len(entry.old) > entry.limit {
			return errors.New("IP certificate prior cache exceeds limit")
		}
	}
	for index := range items {
		if err := backend.Store(ctx, items[index].key, items[index].value); err != nil {
			// The failing Store may itself have touched its target. Restore it
			// too, using a separate bound even when issuance was cancelled.
			recovery, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			restored := true
			for previous := index; previous >= 0; previous-- {
				entry := items[previous]
				if entry.oldExists {
					restored = backend.Store(recovery, entry.key, entry.old) == nil && restored
				} else if backend.Exists(recovery, entry.key) {
					// Only a file absent before this transaction is reclaimed.
					restored = backend.Delete(recovery, entry.key) == nil && restored
				}
			}
			cancel()
			if !restored {
				return errors.New("IP certificate cache restoration failed")
			}
			return errors.New("IP certificate cache write failed")
		}
	}
	return nil
}
