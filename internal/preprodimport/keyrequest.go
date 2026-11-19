package preprodimport

// This is an isolated transaction prototype, not an authorization service.
// Its caller must independently authenticate and authorize both node keys,
// snapshot and request. No endpoint or production export uses this code.

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"
)

const requestPayloadBytes = 2048

type keyRequestPayload struct {
	Scope  keyScope `json:"scope"`
	Source []byte   `json:"source"`
	Target []byte   `json:"target"`
}

func requestMAC(root []byte, label string, data ...[]byte) []byte {
	h := hmac.New(sha256.New, root)
	_, _ = h.Write([]byte("frontiercloud:preprod-key-request:" + label + ":v1\x00"))
	for _, b := range data {
		_, _ = h.Write(b)
	}
	return h.Sum(nil)
}

func requestIndex(root []byte, challenge string) string {
	return hex.EncodeToString(requestMAC(root, "index", []byte(challenge)))
}

// All columns used as identity or nonce reservations require real, nonpartial
// unique constraints. Schema and permanent reservation lifecycle remain a
// future integration task.
func requireRequestConstraints(ctx context.Context, tx *sql.Tx) error {
	for table, required := range map[string][]string{
		"preprod_key_requests":         {"request_tag", "nonce"},
		"preprod_key_request_consumed": {"request_tag"},
	} {
		rows, err := tx.QueryContext(ctx, `SELECT l."unique",l.partial,(SELECT group_concat(i.name, ',') FROM pragma_index_info(l.name) i) FROM pragma_index_list('`+table+`') l`)
		if err != nil {
			return invalid("request constraints")
		}
		found := map[string]bool{}
		for rows.Next() {
			var unique, partial int
			var columns sql.NullString
			if err = rows.Scan(&unique, &partial, &columns); err != nil {
				rows.Close()
				return invalid("request constraints")
			}
			if unique == 1 && partial == 0 && columns.Valid {
				found[columns.String] = true
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return invalid("request constraints")
		}
		for _, c := range required {
			if !found[c] {
				return invalid("request constraints")
			}
		}
	}
	return nil
}

func requestCipher(root []byte) (cipher.AEAD, error) {
	if len(root) != 32 || bytes.Equal(root, make([]byte, 32)) {
		return nil, invalid("request root")
	}
	key := requestMAC(root, "encryption")
	defer clear(key)
	return gcm(key)
}

// saveAuthorizedRequest only persists an already authorized synthetic request.
// A real caller must bind authorization and source identity outside this helper.
func saveAuthorizedRequest(ctx context.Context, db *sql.DB, root []byte, scope keyScope, source ed25519.PublicKey, target []byte, now time.Time) error {
	if db == nil || !scope.valid(now) || len(source) != ed25519.PublicKeySize || len(target) != 32 {
		return invalid("request input")
	}
	aead, err := requestCipher(root)
	if err != nil {
		return err
	}
	tag := requestIndex(root, scope.Challenge)
	encoded, err := json.Marshal(keyRequestPayload{scope, source, target})
	if err != nil || len(encoded) == 0 || len(encoded) > requestPayloadBytes-2 {
		return invalid("request payload")
	}
	defer clear(encoded)
	plain := make([]byte, requestPayloadBytes)
	defer clear(plain)
	binary.BigEndian.PutUint16(plain[:2], uint16(len(encoded)))
	copy(plain[2:], encoded)
	nonce := make([]byte, 12)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return invalid("request nonce")
	}
	ciphertext := aead.Seal(nil, nonce, plain, []byte(tag))
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = requireRequestConstraints(ctx, tx); err != nil {
		return err
	}
	if err = requireVaultConstraints(ctx, tx); err != nil {
		return err
	}
	var verifier string
	if err = tx.QueryRowContext(ctx, "SELECT verifier FROM preprod_key_vault_meta WHERE singleton=1").Scan(&verifier); err != nil || subtle.ConstantTimeCompare([]byte(verifier), []byte(vaultTag(root, "verifier", scope.TargetNode))) != 1 {
		return invalid("request vault identity")
	}
	var oldNonce, oldCipher []byte
	err = tx.QueryRowContext(ctx, "SELECT nonce,cipher FROM preprod_key_requests WHERE request_tag=?", tag).Scan(&oldNonce, &oldCipher)
	if err == nil {
		old, openErr := openRequestedScope(root, tag, oldNonce, oldCipher)
		oldHash, hashErr := scopeDigest(old.Scope)
		newHash, newErr := scopeDigest(scope)
		if openErr != nil || hashErr != nil || newErr != nil || subtle.ConstantTimeCompare(oldHash, newHash) != 1 || subtle.ConstantTimeCompare(old.Source, source) != 1 || subtle.ConstantTimeCompare(old.Target, target) != 1 {
			return invalid("existing request binding")
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO preprod_key_requests(request_tag,nonce,cipher) VALUES (?,?,?)", tag, nonce, ciphertext); err != nil {
		return err
	}
	return tx.Commit()
}

func openRequestedScope(root []byte, tag string, nonce, ciphertext []byte) (keyRequestPayload, error) {
	var payload keyRequestPayload
	if !id64.MatchString(tag) || len(nonce) != 12 || len(ciphertext) != requestPayloadBytes+16 {
		return payload, invalid("request row")
	}
	aead, err := requestCipher(root)
	if err != nil {
		return payload, err
	}
	plain, err := aead.Open(nil, nonce, ciphertext, []byte(tag))
	if err != nil {
		return payload, invalid("request authentication")
	}
	defer clear(plain)
	n := int(binary.BigEndian.Uint16(plain[:2]))
	if n == 0 || n > requestPayloadBytes-2 {
		return payload, invalid("request length")
	}
	for _, b := range plain[n+2:] {
		if b != 0 {
			return payload, invalid("request padding")
		}
	}
	d := json.NewDecoder(bytes.NewReader(plain[2 : n+2]))
	d.DisallowUnknownFields()
	if err = d.Decode(&payload); err != nil {
		return keyRequestPayload{}, invalid("request payload")
	}
	var extra any
	if err = d.Decode(&extra); !errors.Is(err, io.EOF) || !payload.Scope.valid(time.Unix(payload.Scope.IssuedUnix, 0)) || len(payload.Source) != ed25519.PublicKeySize || len(payload.Target) != 32 || subtle.ConstantTimeCompare([]byte(tag), []byte(requestIndex(root, payload.Scope.Challenge))) != 1 {
		return keyRequestPayload{}, invalid("request binding")
	}
	return payload, nil
}

// recoverAuthorizedRequest is local crash recovery only. It requires the
// original challenge and independently pinned public keys; a recovered record
// alone does not prove that the request was externally authorized, and a
// whole-database rollback remains undetectable without an external anchor.
func recoverAuthorizedRequest(ctx context.Context, db *sql.DB, root []byte, targetNode, challenge string, source ed25519.PublicKey, target []byte) (keyScope, bool, bool, error) {
	var empty keyScope
	if db == nil || len(root) != 32 || !id32.MatchString(targetNode) || !id64.MatchString(challenge) || len(source) != ed25519.PublicKeySize || len(target) != 32 {
		return empty, false, false, invalid("request recovery input")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return empty, false, false, err
	}
	defer tx.Rollback()
	if err = requireRequestConstraints(ctx, tx); err != nil {
		return empty, false, false, err
	}
	if err = requireVaultConstraints(ctx, tx); err != nil {
		return empty, false, false, err
	}
	var verifier string
	if err = tx.QueryRowContext(ctx, "SELECT verifier FROM preprod_key_vault_meta WHERE singleton=1").Scan(&verifier); err != nil || subtle.ConstantTimeCompare([]byte(verifier), []byte(vaultTag(root, "verifier", targetNode))) != 1 {
		return empty, false, false, invalid("request recovery identity")
	}
	tag := requestIndex(root, challenge)
	var nonce, ciphertext []byte
	err = tx.QueryRowContext(ctx, "SELECT nonce,cipher FROM preprod_key_requests WHERE request_tag=?", tag).Scan(&nonce, &ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return empty, false, false, nil
	}
	if err != nil {
		return empty, false, false, err
	}
	payload, err := openRequestedScope(root, tag, nonce, ciphertext)
	if err != nil || payload.Scope.TargetNode != targetNode || subtle.ConstantTimeCompare(payload.Source, source) != 1 || subtle.ConstantTimeCompare(payload.Target, target) != 1 {
		return empty, false, false, invalid("request recovery binding")
	}
	var receipt []byte
	err = tx.QueryRowContext(ctx, "SELECT receipt FROM preprod_key_request_consumed WHERE request_tag=?", tag).Scan(&receipt)
	consumed := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return empty, false, false, err
	}
	if consumed {
		hash, hashErr := scopeDigest(payload.Scope)
		if hashErr != nil || subtle.ConstantTimeCompare(receipt, requestMAC(root, "consumed", []byte(tag), hash)) != 1 {
			return empty, false, false, invalid("request recovery receipt")
		}
		var row keyVaultRow
		if err = tx.QueryRowContext(ctx, "SELECT object_tag,grant_tag,file_tag,salt,nonce,cipher FROM preprod_key_vault WHERE object_tag=?", vaultTag(root, "object", payload.Scope.MediaID)).Scan(&row.ObjectTag, &row.GrantTag, &row.FileTag, &row.Salt, &row.Nonce, &row.Cipher); err != nil {
			return empty, false, false, invalid("request recovery vault")
		}
		key, openErr := openVaultKey(root, row, payload.Scope, source, target)
		if openErr != nil {
			return empty, false, false, invalid("request recovery vault binding")
		}
		clear(key)
	} else {
		var existing int
		err = tx.QueryRowContext(ctx, "SELECT 1 FROM preprod_key_vault WHERE object_tag=?", vaultTag(root, "object", payload.Scope.MediaID)).Scan(&existing)
		if err == nil {
			return empty, false, false, invalid("request recovery orphan vault")
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return empty, false, false, err
		}
	}
	if err = tx.Commit(); err != nil {
		return empty, false, false, err
	}
	return payload.Scope, true, consumed, nil
}

// importAuthorizedFileKeyGrant atomically consumes an existing authenticated
// exact request with the vault write. Consumed challenge reservations must
// remain intact; full database rollback is not detected by this prototype.
func importAuthorizedFileKeyGrant(ctx context.Context, db *sql.DB, root []byte, scope keyScope, target *ecdh.PrivateKey, source ed25519.PublicKey, grant keyGrant, now time.Time) (bool, error) {
	if db == nil || target == nil || !scope.valid(now) {
		return false, invalid("authorized import input")
	}
	fileKey, err := openFileKey(grant, scope, target, source, now)
	if err != nil {
		return false, err
	}
	defer clear(fileKey)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	already, err := importAuthorizedFileKeyGrantTx(ctx, tx, root, scope, target, source, grant, fileKey)
	if err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return already, nil
}

// The caller must authenticate the grant and owns the transaction boundary.
func importAuthorizedFileKeyGrantTx(ctx context.Context, tx *sql.Tx, root []byte, scope keyScope, target *ecdh.PrivateKey, source ed25519.PublicKey, grant keyGrant, fileKey []byte) (bool, error) {
	var err error
	if err = requireRequestConstraints(ctx, tx); err != nil {
		return false, err
	}
	tag := requestIndex(root, scope.Challenge)
	var nonce, ciphertext []byte
	if err = tx.QueryRowContext(ctx, "SELECT nonce,cipher FROM preprod_key_requests WHERE request_tag=?", tag).Scan(&nonce, &ciphertext); err != nil {
		return false, invalid("request missing")
	}
	request, err := openRequestedScope(root, tag, nonce, ciphertext)
	if err != nil {
		return false, err
	}
	hash, err := scopeDigest(scope)
	if err != nil {
		return false, err
	}
	requestHash, err := scopeDigest(request.Scope)
	if err != nil || subtle.ConstantTimeCompare(hash, requestHash) != 1 || subtle.ConstantTimeCompare(request.Source, source) != 1 || subtle.ConstantTimeCompare(request.Target, target.PublicKey().Bytes()) != 1 {
		return false, invalid("request mismatch")
	}
	receipt := requestMAC(root, "consumed", []byte(tag), hash)
	var existing []byte
	err = tx.QueryRowContext(ctx, "SELECT receipt FROM preprod_key_request_consumed WHERE request_tag=?", tag).Scan(&existing)
	consumed := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if consumed && subtle.ConstantTimeCompare(existing, receipt) != 1 {
		return false, invalid("request receipt")
	}
	proof := keyProof{Grant: grant, SourcePublic: append([]byte(nil), source...), TargetPublic: target.PublicKey().Bytes()}
	already, err := installVaultKeyTx(ctx, tx, root, scope, fileKey, proof, source, target)
	if err != nil {
		return false, err
	}
	if consumed != already {
		return false, invalid("request vault consistency")
	}
	if !consumed {
		if _, err = tx.ExecContext(ctx, "INSERT INTO preprod_key_request_consumed(request_tag,receipt) VALUES (?,?)", tag, receipt); err != nil {
			return false, err
		}
	}
	return already, nil
}
