package preprodimport

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/subtle"
	"database/sql"
	"errors"
	"time"
)

func requireVaultConstraints(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT l."unique",l.partial,(SELECT group_concat(i.name, ',') FROM pragma_index_info(l.name) i) FROM pragma_index_list('preprod_key_vault') l`)
	if err != nil {
		return invalid("vault constraints")
	}
	defer rows.Close()
	found := map[string]bool{}
	for rows.Next() {
		var unique, partial int
		var columns sql.NullString
		if err = rows.Scan(&unique, &partial, &columns); err != nil {
			return invalid("vault constraints")
		}
		if unique == 1 && partial == 0 && columns.Valid {
			found[columns.String] = true
		}
	}
	if rows.Err() != nil || !found["object_tag"] || !found["grant_tag"] || !found["file_tag"] || !found["salt"] {
		return invalid("vault constraints")
	}
	return nil
}

// installVaultKey is an unconnected transaction primitive for an already
// authenticated file key. The caller must supply a separately initialized,
// fenced vault schema and independently protected vault root. It is not a
// runtime resolver, manifest authorization, backup protocol, or deployment.
// Schema creation is intentionally absent until the encrypted-tree transaction
// and production lifecycle are designed together.
func installVaultKey(ctx context.Context, db *sql.DB, root []byte, scope keyScope, fileKey []byte, proof keyProof, source ed25519.PublicKey, target *ecdh.PrivateKey, now time.Time) (alreadyCommitted bool, err error) {
	if db == nil || len(root) != 32 || len(fileKey) != 32 || target == nil || !scope.valid(now) || verifyKeyProof(proof, scope, source, target.PublicKey().Bytes()) != nil {
		return false, invalid("vault transaction input")
	}
	authenticatedKey, err := openFileKey(proof.Grant, scope, target, source, now)
	if err != nil {
		return false, err
	}
	defer clear(authenticatedKey)
	if subtle.ConstantTimeCompare(authenticatedKey, fileKey) != 1 {
		return false, invalid("grant file key mismatch")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	alreadyCommitted, err = installVaultKeyTx(ctx, tx, root, scope, fileKey, proof, source, target)
	if err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return alreadyCommitted, nil
}

// installVaultKeyTx requires the caller to authenticate the grant and owns no
// transaction boundary. It lets a future authorization record be consumed in
// the same transaction as its key binding.
func installVaultKeyTx(ctx context.Context, tx *sql.Tx, root []byte, scope keyScope, fileKey []byte, proof keyProof, source ed25519.PublicKey, target *ecdh.PrivateKey) (bool, error) {
	var err error
	if err = requireVaultConstraints(ctx, tx); err != nil {
		return false, err
	}
	var verifier string
	if err = tx.QueryRowContext(ctx, "SELECT verifier FROM preprod_key_vault_meta WHERE singleton=1").Scan(&verifier); err != nil || subtle.ConstantTimeCompare([]byte(verifier), []byte(vaultTag(root, "verifier", scope.TargetNode))) != 1 {
		return false, invalid("vault identity")
	}
	newRow, err := sealVaultKey(root, scope, fileKey, proof)
	if err != nil {
		return false, err
	}
	var previous keyVaultRow
	err = tx.QueryRowContext(ctx, "SELECT object_tag,grant_tag,file_tag,salt,nonce,cipher FROM preprod_key_vault WHERE object_tag=?", newRow.ObjectTag).Scan(&previous.ObjectTag, &previous.GrantTag, &previous.FileTag, &previous.Salt, &previous.Nonce, &previous.Cipher)
	if err == nil {
		// A retry after an uncertain commit is successful only when the exact
		// authenticated scope and file key were committed previously.
		priorKey, openErr := openVaultKey(root, previous, scope, source, target.PublicKey().Bytes())
		if openErr != nil {
			return false, invalid("existing key binding")
		}
		defer clear(priorKey)
		if subtle.ConstantTimeCompare(priorKey, fileKey) != 1 {
			return false, invalid("existing key mismatch")
		}
		return true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	// The future schema must retain UNIQUE grant_tag, file_tag and salt reservations
	// for the lifetime of the vault, including after logical deletion.
	if _, err = tx.ExecContext(ctx, "INSERT INTO preprod_key_vault(object_tag,grant_tag,file_tag,salt,nonce,cipher) VALUES (?,?,?,?,?,?)", newRow.ObjectTag, newRow.GrantTag, newRow.FileTag, newRow.Salt, newRow.Nonce, newRow.Cipher); err != nil {
		return false, err
	}
	return false, nil
}

// importFileKeyGrant composes signature/target/scope validation with the
// transaction. It remains package-private until trusted source authorization,
// the encrypted-tree schema, key protection and lifecycle are integrated.
func importFileKeyGrant(ctx context.Context, db *sql.DB, root []byte, scope keyScope, target *ecdh.PrivateKey, source ed25519.PublicKey, grant keyGrant, now time.Time) (bool, error) {
	fileKey, err := openFileKey(grant, scope, target, source, now)
	if err != nil {
		return false, err
	}
	defer clear(fileKey)
	proof := keyProof{Grant: grant, SourcePublic: append([]byte(nil), source...), TargetPublic: target.PublicKey().Bytes()}
	return installVaultKey(ctx, db, root, scope, fileKey, proof, source, target, now)
}

// recoverVaultCommit reports an exact already-committed binding after a lost
// response, including after grant expiry. It never returns a key, inserts a
// row, or accepts a changed binding; external status authorization is still
// required before exposing even this boolean in a future runtime.
func recoverVaultCommit(ctx context.Context, db *sql.DB, root []byte, scope keyScope, source ed25519.PublicKey, target []byte) (bool, error) {
	if db == nil || len(root) != 32 || !scope.valid(time.Unix(scope.IssuedUnix, 0)) {
		return false, invalid("vault recovery input")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err = requireVaultConstraints(ctx, tx); err != nil {
		return false, err
	}
	var verifier string
	if err = tx.QueryRowContext(ctx, "SELECT verifier FROM preprod_key_vault_meta WHERE singleton=1").Scan(&verifier); err != nil || subtle.ConstantTimeCompare([]byte(verifier), []byte(vaultTag(root, "verifier", scope.TargetNode))) != 1 {
		return false, invalid("vault recovery identity")
	}
	var row keyVaultRow
	err = tx.QueryRowContext(ctx, "SELECT object_tag,grant_tag,file_tag,salt,nonce,cipher FROM preprod_key_vault WHERE object_tag=?", vaultTag(root, "object", scope.MediaID)).Scan(&row.ObjectTag, &row.GrantTag, &row.FileTag, &row.Salt, &row.Nonce, &row.Cipher)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	fileKey, err := openVaultKey(root, row, scope, source, target)
	if err != nil {
		return false, invalid("vault recovery binding")
	}
	clear(fileKey)
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// recoverVaultScope recovers only an authenticated stored scope, not the key,
// when a caller lost its local request state after a commit. The caller must
// independently authenticate both pinned public keys and target node identity.
// It is not proof that the original request or snapshot was authorized.
func recoverVaultScope(ctx context.Context, db *sql.DB, root []byte, targetNode, mediaID string, source ed25519.PublicKey, target []byte) (keyScope, bool, error) {
	var empty keyScope
	if db == nil || len(root) != 32 || !id32.MatchString(targetNode) || !id64.MatchString(mediaID) {
		return empty, false, invalid("vault scope recovery input")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return empty, false, err
	}
	defer tx.Rollback()
	if err = requireVaultConstraints(ctx, tx); err != nil {
		return empty, false, err
	}
	var verifier string
	if err = tx.QueryRowContext(ctx, "SELECT verifier FROM preprod_key_vault_meta WHERE singleton=1").Scan(&verifier); err != nil || subtle.ConstantTimeCompare([]byte(verifier), []byte(vaultTag(root, "verifier", targetNode))) != 1 {
		return empty, false, invalid("vault scope recovery identity")
	}
	var row keyVaultRow
	err = tx.QueryRowContext(ctx, "SELECT object_tag,grant_tag,file_tag,salt,nonce,cipher FROM preprod_key_vault WHERE object_tag=?", vaultTag(root, "object", mediaID)).Scan(&row.ObjectTag, &row.GrantTag, &row.FileTag, &row.Salt, &row.Nonce, &row.Cipher)
	if errors.Is(err, sql.ErrNoRows) {
		return empty, false, nil
	}
	if err != nil {
		return empty, false, err
	}
	payload, err := decodeVaultRow(root, row, source, target)
	if err != nil {
		return empty, false, err
	}
	defer clear(payload.Key)
	if payload.Scope.MediaID != mediaID || payload.Scope.TargetNode != targetNode {
		return empty, false, invalid("vault scope recovery binding")
	}
	if err = tx.Commit(); err != nil {
		return empty, false, err
	}
	return payload.Scope, true, nil
}
