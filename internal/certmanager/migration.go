package certmanager

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
)

// Adopt only the previous product-owned certificate volume layout. This is a
// one-time internal storage conversion, not a configurable certificate path or
// a public import/upload API. Public-CA chain, domain, time and key verification
// must pass before either serving material or the old ACME account is reused.
func (m *Manager) adoptLegacy() error {
	cert, key, err := readGeneration(m.opt.private)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("legacy managed certificate volume is incomplete")
	}
	defer clear(key)
	_, err = Validate(m.opt.host, cert, key, m.opt.roots, time.Now())
	if err != nil {
		return errors.New("legacy managed certificate identity cannot be verified")
	}
	issuer := m.issuer.IssuerKey()
	metaKey := certmagic.StorageKeys.SiteMeta(issuer, m.opt.host)
	if !m.cfg.Storage.Exists(m.ctx, metaKey) {
		// Metadata is the commit marker. A restart after an interrupted import can
		// safely repeat writes while the exclusive controller lease is held.
		meta, err := json.Marshal(certmagic.CertificateResource{SANs: []string{m.opt.host}, IssuerData: json.RawMessage("{}")})
		if err != nil {
			return err
		}
		for _, entry := range []struct {
			key   string
			value []byte
		}{
			{certmagic.StorageKeys.SitePrivateKey(issuer, m.opt.host), key},
			{certmagic.StorageKeys.SiteCert(issuer, m.opt.host), cert},
			{metaKey, meta},
		} {
			if err = m.cfg.Storage.Store(m.ctx, entry.key, entry.value); err != nil {
				return errors.New("legacy certificate cache adoption could not be persisted")
			}
		}
	}
	account, err := readBounded(filepath.Join(m.opt.private, "account.key"), 16384)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("legacy ACME account unreadable")
	}
	defer clear(account)
	block, rest := pem.Decode(account)
	if block == nil || len(rest) != 0 {
		return errors.New("legacy ACME account invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	clear(block.Bytes)
	if err != nil {
		return errors.New("legacy ACME account invalid")
	}
	signer, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || signer.Curve.Params().BitSize != 256 {
		return errors.New("legacy ACME account type unsupported")
	}
	m.issuer.NewAccountFunc = func(_ context.Context, _ *certmagic.ACMEIssuer, a acme.Account) (acme.Account, error) {
		a.PrivateKey = signer
		return a, nil
	}
	return nil
}
