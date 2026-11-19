package preprodimport

// Synthetic owner journal. This guards accidental cross-operation reuse in a
// cooperating process; an untrusted node can delete or roll it back. Durable
// external authority, owner fencing, and authenticated renewal remain gates.
// The separate journal key must never be the tree root or media premaster.
import (
	"bytes"
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
)

func reserveSyntheticStagePublish(ctx context.Context, db *sql.DB, key []byte, r stagePublishRequest, signature []byte) error {
	if ctx == nil || db == nil || len(key) != 32 || bytes.Equal(key, make([]byte, 32)) {
		return invalid("stage publish journal")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = requireSyntheticJournalDurability(ctx, tx); err != nil {
		return err
	}
	var verifier string
	if err = tx.QueryRowContext(ctx, "SELECT verifier FROM preprod_owner_publish_meta WHERE singleton=1").Scan(&verifier); err != nil || subtle.ConstantTimeCompare([]byte(verifier), []byte(vaultTag(key, "stage-journal-verifier", "v1"))) != 1 {
		return invalid("stage publish journal key")
	}
	rows, err := tx.QueryContext(ctx, `SELECT l."unique",l.partial,(SELECT group_concat(i.name, ',') FROM pragma_index_info(l.name) i) FROM pragma_index_list('preprod_owner_publish_intents') l`)
	if err != nil {
		return invalid("stage publish journal constraints")
	}
	found := map[string]bool{}
	for rows.Next() {
		var unique, partial int
		var columns sql.NullString
		if rows.Scan(&unique, &partial, &columns) != nil {
			rows.Close()
			return invalid("stage publish journal constraints")
		}
		if unique == 1 && partial == 0 && columns.Valid {
			found[columns.String] = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil || !found["operation_id"] || !found["blob_id"] {
		return invalid("stage publish journal constraints")
	}
	rows, err = tx.QueryContext(ctx, `SELECT l."unique",l.partial,(SELECT group_concat(i.name, ',') FROM pragma_index_info(l.name) i) FROM pragma_index_list('preprod_owner_publish_authorizations') l`)
	if err != nil {
		return invalid("stage authorization constraints")
	}
	challengeUnique := false
	for rows.Next() {
		var unique, partial int
		var columns sql.NullString
		if rows.Scan(&unique, &partial, &columns) != nil {
			rows.Close()
			return invalid("stage authorization constraints")
		}
		if unique == 1 && partial == 0 && columns.Valid && columns.String == "challenge_tag" {
			challengeUnique = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil || !challengeUnique {
		return invalid("stage authorization constraints")
	}
	stable := r
	stable.PlanDigest = ""
	stable.Challenge = ""
	stable.IssuedUnix = 0
	stable.ExpiresUnix = 0
	raw, err := json.Marshal(stable)
	if err != nil {
		return err
	}
	defer clear(raw)
	binding := hex.EncodeToString(requestMAC(key, "stage-publish-intent", raw))
	operation := vaultTag(key, "stage-publish-operation", r.OperationID)
	blobTag := vaultTag(key, "stage-publish-blob", r.BlobID)
	var blob, stored string
	err = tx.QueryRowContext(ctx, "SELECT blob_id,binding FROM preprod_owner_publish_intents WHERE operation_id=?", operation).Scan(&blob, &stored)
	if err == sql.ErrNoRows {
		if _, err = tx.ExecContext(ctx, "INSERT INTO preprod_owner_publish_intents(operation_id,blob_id,binding) VALUES(?,?,?)", operation, blobTag, binding); err != nil {
			return invalid("stage publish intent conflict")
		}
	} else if err != nil || subtle.ConstantTimeCompare([]byte(blob), []byte(blobTag)) != 1 || subtle.ConstantTimeCompare([]byte(stored), []byte(binding)) != 1 {
		return invalid("stage publish intent mismatch")
	}
	authorization, err := json.Marshal(signedStagePublishRequest{Request: r, Signature: signature})
	if err != nil {
		return err
	}
	defer clear(authorization)
	challenge := vaultTag(key, "stage-publish-challenge", r.Challenge)
	authTag := hex.EncodeToString(requestMAC(key, "stage-publish-authorization", authorization))
	var previousOp, previousAuth string
	err = tx.QueryRowContext(ctx, "SELECT operation_id,authorization FROM preprod_owner_publish_authorizations WHERE challenge_tag=?", challenge).Scan(&previousOp, &previousAuth)
	if err == sql.ErrNoRows {
		if _, err = tx.ExecContext(ctx, "INSERT INTO preprod_owner_publish_authorizations(challenge_tag,operation_id,authorization) VALUES(?,?,?)", challenge, operation, authTag); err != nil {
			return invalid("stage authorization conflict")
		}
	} else if err != nil || subtle.ConstantTimeCompare([]byte(previousOp), []byte(operation)) != 1 || subtle.ConstantTimeCompare([]byte(previousAuth), []byte(authTag)) != 1 {
		return invalid("stage authorization replay")
	}
	return tx.Commit()
}

// This is only a necessary local durability precondition, not a proof that
// the filesystem honors flushes or that an untrusted owner cannot roll back.
func requireSyntheticJournalDurability(ctx context.Context, tx *sql.Tx) error {
	var synchronous int
	if err := tx.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil || synchronous < 2 {
		return invalid("stage journal synchronous mode")
	}
	var mode string
	if err := tx.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil || (mode != "delete" && mode != "wal" && mode != "truncate" && mode != "persist") {
		return invalid("stage journal mode")
	}
	rows, err := tx.QueryContext(ctx, "PRAGMA database_list")
	if err != nil {
		return invalid("stage journal database")
	}
	defer rows.Close()
	var filename string
	for rows.Next() {
		var seq int
		var name, file string
		if rows.Scan(&seq, &name, &file) != nil {
			return invalid("stage journal database")
		}
		if name == "main" {
			filename = file
		}
	}
	if rows.Err() != nil || !filepath.IsAbs(filename) {
		return invalid("stage journal database")
	}
	resolved, err := filepath.EvalSymlinks(filename)
	if err != nil || resolved != filepath.Clean(filename) {
		return invalid("stage journal database path")
	}
	info, err := os.Lstat(filename)
	if err != nil || !privateOwned(info, false) {
		return invalid("stage journal file")
	}
	parent, err := os.Lstat(filepath.Dir(filename))
	if err != nil || !privateOwned(parent, true) {
		return invalid("stage journal directory")
	}
	return nil
}
