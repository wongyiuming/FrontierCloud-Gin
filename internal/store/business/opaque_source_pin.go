package business

// Unregistered source-pin persistence. It does not authenticate the source,
// authorize a user or enable preproduction import.
import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"database/sql"
	"errors"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func sourcePinVaultMatchesIdentity(v *vault.Vault, identity store.NodeIdentity) bool {
	encoded, err := v.Unseal(identity.PrivateKey)
	if err != nil {
		return false
	}
	seed, err := protocol.Decode(encoded)
	defer clear(seed)
	return err == nil && len(seed) == ed25519.SeedSize
}

// StoreOpaqueSourcePin returns the single durable sealed value. The caller
// must independently authenticate and compare the complete pin before use.
// It takes ingressWrite itself: do not call while holding a shared ingress
// lease. No ciphertext is ever replaced, including on a different pin.
func (r *Repository) StoreOpaqueSourcePin(ctx context.Context, expected store.NodeIdentity, v *vault.Vault, sealed string) (string, bool, error) {
	if ctx == nil || v == nil || expected.Role != "Master" || !nodeIDPattern.MatchString(expected.ID) || expected.PrivateKey == "" || expected.CreatedAt <= 0 || len(sealed) == 0 || len(sealed) > 8192 || !sourcePinVaultMatchesIdentity(v, expected) {
		return "", false, store.ErrNodeState
	}
	plain, err := v.Unseal(sealed)
	if err != nil || len(plain) == 0 || len(plain) > 4096 {
		return "", false, store.ErrNodeState
	}
	var stored string
	var created bool
	err = r.ingressWrite(ctx, func(q queryer) error {
		created = false
		actual, err := readNode(ctx, q, r.lock())
		if err != nil || actual != expected {
			return store.ErrNodeState
		}
		var raw []byte
		err = q.QueryRowContext(ctx, "SELECT sealed FROM sealed_tree_source_pin WHERE singleton=1"+r.lock()).Scan(&raw)
		if err == nil {
			if len(raw) == 0 || len(raw) > 8192 {
				return store.ErrNodeState
			}
			prior, e := v.Unseal(string(raw))
			if e != nil || subtle.ConstantTimeCompare([]byte(prior), []byte(plain)) != 1 {
				return store.ErrNodeState
			}
			stored = string(raw)
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err = q.ExecContext(ctx, "INSERT INTO sealed_tree_source_pin(singleton,sealed) VALUES(1,?)", []byte(sealed)); err != nil {
			return err
		}
		stored, created = sealed, true
		return nil
	})
	if err != nil {
		return "", false, err
	}
	return stored, created, nil
}

// LoadOpaqueSourcePin observes the identity and authenticated ciphertext in a
// single read transaction. A caller making an authorization decision must
// additionally hold the current ingress lease throughout its own verification.
func (r *Repository) LoadOpaqueSourcePin(ctx context.Context, expected store.NodeIdentity, v *vault.Vault) (string, bool, error) {
	if ctx == nil || v == nil || expected.Role != "Master" || !nodeIDPattern.MatchString(expected.ID) || expected.PrivateKey == "" || expected.CreatedAt <= 0 || !sourcePinVaultMatchesIdentity(v, expected) {
		return "", false, store.ErrNodeState
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback()
	actual, err := readNode(ctx, tx, "")
	if err != nil || actual != expected {
		return "", false, store.ErrNodeState
	}
	var raw []byte
	err = tx.QueryRowContext(ctx, "SELECT sealed FROM sealed_tree_source_pin WHERE singleton=1").Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil || len(raw) == 0 || len(raw) > 8192 {
		return "", false, store.ErrNodeState
	}
	plain, err := v.Unseal(string(raw))
	if err != nil || len(plain) == 0 || len(plain) > 4096 {
		return "", false, store.ErrNodeState
	}
	if err = tx.Commit(); err != nil {
		return "", false, err
	}
	return string(raw), true, nil
}
