package preprodimport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

func requireLegacyRequestConstraints(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT l."unique",l.partial,(SELECT group_concat(i.name, ',') FROM pragma_index_info(l.name) i) FROM pragma_index_list('legacy_key_requests') l`)
	if err != nil {
		return invalid("legacy request constraints")
	}
	defer rows.Close()
	found := map[string]bool{}
	for rows.Next() {
		var unique, partial int
		var cols sql.NullString
		if rows.Scan(&unique, &partial, &cols) != nil {
			return invalid("legacy request constraints")
		}
		if unique == 1 && partial == 0 && cols.Valid {
			found[cols.String] = true
		}
	}
	if rows.Err() != nil || !found["request_tag"] || !found["salt"] {
		return invalid("legacy request constraints")
	}
	return nil
}

func legacyRequestCipher(root, salt []byte) ([]byte, error) {
	if len(root) != 32 || bytes.Equal(root, make([]byte, 32)) || len(salt) != 32 {
		return nil, invalid("legacy request root")
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, root, salt, []byte("frontiercloud:legacy-request:v1")), key); err != nil {
		clear(key)
		return nil, invalid("legacy request key")
	}
	return key, nil
}

// ensureLegacyAuthorizedRequest persists an exact already-authorized scope.
// It does not authenticate the source channel, snapshot, operator or target;
// a future caller must prove those facts before calling, under its own fence.
// Records/salts must never be deleted or silently recreated.
func ensureLegacyAuthorizedRequest(ctx context.Context, db *sql.DB, root []byte, scope legacyObservationScope, now time.Time, guard func(context.Context) error) (bool, error) {
	if ctx == nil || db == nil || guard == nil || !legacyScopeValid(scope, now) || guard(ctx) != nil {
		return false, invalid("legacy request input")
	}
	tag := legacyVaultTag(root, "request", scope.Key.Challenge)
	raw, err := json.Marshal(scope)
	if err != nil {
		return false, invalid("legacy request scope")
	}
	defer clear(raw)
	salt := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, salt); err != nil {
		return false, invalid("legacy request random")
	}
	key, err := legacyRequestCipher(root, salt)
	if err != nil {
		return false, err
	}
	defer clear(key)
	aead, err := gcm(key)
	if err != nil {
		return false, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return false, invalid("legacy request random")
	}
	cipher := aead.Seal(nil, nonce, raw, []byte(tag))
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err = requireLegacyRequestConstraints(ctx, tx); err != nil {
		return false, err
	}
	if err = requireLegacyVaultConstraints(ctx, tx); err != nil {
		return false, err
	}
	var verifier string
	if tx.QueryRowContext(ctx, "SELECT verifier FROM legacy_key_vault_meta WHERE singleton=1").Scan(&verifier) != nil || subtle.ConstantTimeCompare([]byte(verifier), []byte(legacyVaultTag(root, "verifier", scope.Key.TargetNode))) != 1 {
		return false, invalid("legacy request vault identity")
	}
	var priorSalt, priorNonce, priorCipher []byte
	var consumed int
	err = tx.QueryRowContext(ctx, "SELECT salt,nonce,cipher,consumed FROM legacy_key_requests WHERE request_tag=?", tag).Scan(&priorSalt, &priorNonce, &priorCipher, &consumed)
	if err == nil {
		prior, e := decodeLegacyRequest(root, tag, priorSalt, priorNonce, priorCipher)
		defer clear(prior)
		if e != nil || !bytes.Equal(prior, raw) || (consumed != 0 && consumed != 1) {
			return false, invalid("legacy request conflict")
		}
		if consumed == 1 {
			var row legacyVaultRow
			if tx.QueryRowContext(ctx, "SELECT object_tag,file_tag,challenge_tag,salt,nonce,cipher FROM legacy_key_vault WHERE object_tag=?", legacyVaultTag(root, "object", scope.Key.MediaID)).Scan(&row.ObjectTag, &row.FileTag, &row.ChallengeTag, &row.Salt, &row.Nonce, &row.Cipher) != nil {
				return false, invalid("legacy consumed request missing vault")
			}
			payload, e := openLegacyVault(root, row, scope, scope.TargetSigningKey)
			if e != nil {
				return false, e
			}
			clear(payload.Key)
		} else {
			var exists int
			if tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM legacy_key_vault WHERE object_tag=?)", legacyVaultTag(root, "object", scope.Key.MediaID)).Scan(&exists) != nil || exists != 0 {
				return false, invalid("legacy vault orphan")
			}
		}
		if ctx.Err() != nil || time.Now().Unix() >= scope.Key.ExpiresUnix || guard(ctx) != nil {
			return false, invalid("legacy request expired or fence lost")
		}
		if err = tx.Commit(); err != nil {
			return false, err
		}
		return consumed == 1, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	var orphan int
	if tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM legacy_key_vault WHERE object_tag=?)", legacyVaultTag(root, "object", scope.Key.MediaID)).Scan(&orphan) != nil || orphan != 0 {
		return false, invalid("legacy vault orphan")
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO legacy_key_requests(request_tag,salt,nonce,cipher,consumed) VALUES(?,?,?,?,0)", tag, salt, nonce, cipher); err != nil {
		return false, invalid("legacy request conflict")
	}
	if ctx.Err() != nil || time.Now().Unix() >= scope.Key.ExpiresUnix || guard(ctx) != nil {
		return false, invalid("legacy request expired or fence lost")
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return false, nil
}

func decodeLegacyRequest(root []byte, tag string, salt, nonce, ciphertext []byte) ([]byte, error) {
	if !id64.MatchString(tag) || len(nonce) != 12 || len(ciphertext) < 16 || len(ciphertext) > 8192 {
		return nil, invalid("legacy request row")
	}
	key, err := legacyRequestCipher(root, salt)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	raw, err := aead.Open(nil, nonce, ciphertext, []byte(tag))
	if err != nil {
		return nil, invalid("legacy request authentication")
	}
	return raw, nil
}

func checkLegacyRequestTx(ctx context.Context, tx *sql.Tx, root []byte, scope legacyObservationScope) (string, int, error) {
	if err := requireLegacyRequestConstraints(ctx, tx); err != nil {
		return "", 0, err
	}
	tag := legacyVaultTag(root, "request", scope.Key.Challenge)
	var salt, nonce, ciphertext []byte
	var consumed int
	if tx.QueryRowContext(ctx, "SELECT salt,nonce,cipher,consumed FROM legacy_key_requests WHERE request_tag=?", tag).Scan(&salt, &nonce, &ciphertext, &consumed) != nil || (consumed != 0 && consumed != 1) {
		return "", 0, invalid("legacy request missing")
	}
	raw, err := decodeLegacyRequest(root, tag, salt, nonce, ciphertext)
	if err != nil {
		return "", 0, err
	}
	defer clear(raw)
	want, err := json.Marshal(scope)
	if err != nil || !bytes.Equal(raw, want) {
		return "", 0, invalid("legacy request binding")
	}
	return tag, consumed, nil
}

// recoverLegacyCommitStatus reads one previously authorized exact request and
// its target-signed vault record in the same snapshot, even after its original
// request expired. It never returns the key, creates a request or renews
// permission. The caller must hold current identity/tree fences and separately
// authenticate the scope, target key and source observation.
func recoverLegacyCommitStatus(ctx context.Context, db *sql.DB, root []byte, scope legacyObservationScope, guard func(context.Context) error) (bool, error) {
	if ctx == nil || db == nil || guard == nil || !legacyScopeValid(scope, time.Unix(scope.Key.IssuedUnix, 0)) || guard(ctx) != nil {
		return false, invalid("legacy recovery input")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err = requireLegacyVaultConstraints(ctx, tx); err != nil {
		return false, err
	}
	var verifier string
	if tx.QueryRowContext(ctx, "SELECT verifier FROM legacy_key_vault_meta WHERE singleton=1").Scan(&verifier) != nil || subtle.ConstantTimeCompare([]byte(verifier), []byte(legacyVaultTag(root, "verifier", scope.Key.TargetNode))) != 1 {
		return false, invalid("legacy recovery vault identity")
	}
	_, consumed, err := checkLegacyRequestTx(ctx, tx, root, scope)
	if err != nil {
		return false, err
	}
	var row legacyVaultRow
	err = tx.QueryRowContext(ctx, "SELECT object_tag,file_tag,challenge_tag,salt,nonce,cipher FROM legacy_key_vault WHERE object_tag=?", legacyVaultTag(root, "object", scope.Key.MediaID)).Scan(&row.ObjectTag, &row.FileTag, &row.ChallengeTag, &row.Salt, &row.Nonce, &row.Cipher)
	if consumed == 0 {
		if !errors.Is(err, sql.ErrNoRows) {
			return false, invalid("legacy vault orphan")
		}
	} else {
		if err != nil {
			return false, invalid("legacy consumed request missing vault")
		}
		payload, e := openLegacyVault(root, row, scope, scope.TargetSigningKey)
		if e != nil {
			return false, e
		}
		clear(payload.Key)
	}
	if ctx.Err() != nil || guard(ctx) != nil {
		return false, invalid("legacy recovery fence lost")
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return consumed == 1, nil
}
