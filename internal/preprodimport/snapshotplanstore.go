package preprodimport

// Private synthetic persistence. Real use requires durable identity pinning,
// source authorization, complete reservation lifecycle and rollback anchors.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"
)

type completeSnapshotEvidence struct {
	Plan    signedSnapshotPlan    `json:"plan"`
	Batches []signedSnapshotGrant `json:"batches"`
}

const maxSnapshotEvidenceBytes = 8 * 1024 * 1024

func requirePlanConstraints(ctx context.Context, tx *sql.Tx) error {
	for table, required := range map[string][]string{"preprod_snapshot_plans": {"plan_tag", "salt"}, "preprod_snapshot_batch_links": {"batch_tag"}} {
		rows, err := tx.QueryContext(ctx, `SELECT l."unique",l.partial,(SELECT group_concat(i.name, ',') FROM pragma_index_info(l.name) i) FROM pragma_index_list('`+table+`') l`)
		if err != nil {
			return invalid("snapshot plan constraints")
		}
		found := map[string]bool{}
		for rows.Next() {
			var unique, partial int
			var cols sql.NullString
			if err = rows.Scan(&unique, &partial, &cols); err != nil {
				rows.Close()
				return invalid("snapshot plan constraints")
			}
			if unique == 1 && partial == 0 && cols.Valid {
				found[cols.String] = true
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return invalid("snapshot plan constraints")
		}
		for _, name := range required {
			if !found[name] {
				return invalid("snapshot plan constraints")
			}
		}
	}
	return nil
}

func openPlanEvidence(root []byte, tag string, salt, nonce, ciphertext []byte) ([]byte, error) {
	if len(root) != 32 || bytes.Equal(root, make([]byte, 32)) || !id64.MatchString(tag) || len(salt) != 32 || len(nonce) != 12 || len(ciphertext) < 4096+16 || len(ciphertext) > maxSnapshotEvidenceBytes+4096+16 {
		return nil, invalid("snapshot plan row")
	}
	key := requestMAC(root, "snapshot-plan-encryption", salt)
	defer clear(key)
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, ciphertext, []byte(tag))
	if err != nil {
		return nil, invalid("snapshot plan authentication")
	}
	defer clear(plain)
	if len(plain)%4096 != 0 {
		return nil, invalid("snapshot plan padding")
	}
	n := int(binary.BigEndian.Uint32(plain[:4]))
	if n <= 0 || n > len(plain)-4 || n > maxSnapshotEvidenceBytes {
		return nil, invalid("snapshot plan length")
	}
	for _, b := range plain[n+4:] {
		if b != 0 {
			return nil, invalid("snapshot plan padding")
		}
	}
	return append([]byte(nil), plain[4:n+4]...), nil
}

// Caller verifies signatures, full coverage and pins, then saves once in the
// same transaction as request consumption and key insertion.
func saveCompletePlanTx(ctx context.Context, tx *sql.Tx, root []byte, plan signedSnapshotPlan, batches []signedSnapshotGrant, now time.Time) error {
	if len(root) != 32 || bytes.Equal(root, make([]byte, 32)) {
		return invalid("snapshot plan root")
	}
	if err := requirePlanConstraints(ctx, tx); err != nil {
		return err
	}
	digest, err := snapshotPlanDigest(plan.Body, now)
	if err != nil {
		return err
	}
	tag := vaultTag(root, "snapshot-plan", hex.EncodeToString(digest))
	encoded, err := json.Marshal(completeSnapshotEvidence{Plan: plan, Batches: batches})
	if err != nil || len(encoded) == 0 || len(encoded) > maxSnapshotEvidenceBytes {
		return invalid("snapshot plan evidence size")
	}
	defer clear(encoded)
	var salt, nonce, ciphertext []byte
	err = tx.QueryRowContext(ctx, "SELECT salt,nonce,cipher FROM preprod_snapshot_plans WHERE plan_tag=?", tag).Scan(&salt, &nonce, &ciphertext)
	if err == nil {
		plain, openErr := openPlanEvidence(root, tag, salt, nonce, ciphertext)
		if openErr != nil {
			return openErr
		}
		defer clear(plain)
		if subtle.ConstantTimeCompare(plain, encoded) != 1 {
			return invalid("snapshot plan evidence changed")
		}
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if errors.Is(err, sql.ErrNoRows) {
		salt = make([]byte, 32)
		nonce = make([]byte, 12)
		if _, err = io.ReadFull(rand.Reader, salt); err != nil {
			return invalid("snapshot plan salt")
		}
		if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
			return invalid("snapshot plan nonce")
		}
		key := requestMAC(root, "snapshot-plan-encryption", salt)
		defer clear(key)
		aead, err := gcm(key)
		if err != nil {
			return err
		}
		n := (len(encoded) + 4 + 4095) / 4096 * 4096
		plain := make([]byte, n)
		defer clear(plain)
		binary.BigEndian.PutUint32(plain[:4], uint32(len(encoded)))
		copy(plain[4:], encoded)
		ciphertext = aead.Seal(nil, nonce, plain, []byte(tag))
		if _, err = tx.ExecContext(ctx, "INSERT INTO preprod_snapshot_plans(plan_tag,salt,nonce,cipher) VALUES(?,?,?,?)", tag, salt, nonce, ciphertext); err != nil {
			return err
		}
	}
	for _, batch := range plan.Body.Batches {
		batchTag := vaultTag(root, "snapshot-plan-batch", batch.Digest)
		if _, err = tx.ExecContext(ctx, "INSERT INTO preprod_snapshot_batch_links(batch_tag,plan_tag) VALUES(?,?) ON CONFLICT(batch_tag) DO NOTHING", batchTag, tag); err != nil {
			return err
		}
		var previous string
		if err = tx.QueryRowContext(ctx, "SELECT plan_tag FROM preprod_snapshot_batch_links WHERE batch_tag=?", batchTag).Scan(&previous); err != nil || subtle.ConstantTimeCompare([]byte(previous), []byte(tag)) != 1 {
			return invalid("snapshot plan batch rebound")
		}
	}
	return nil
}

// recoverCompletePlan returns authenticated historical evidence for a status
// check, even after expiry. It never renews authorization or installs a key.
// Caller authorization, identity pinning and cross-store rollback protection
// remain independent obligations.
func recoverCompletePlan(ctx context.Context, db *sql.DB, root []byte, scope keyScope, trust snapshotPlanTrust) (signedSnapshotPlan, []signedSnapshotGrant, bool, error) {
	var empty signedSnapshotPlan
	if db == nil || len(root) != 32 || !scope.valid(time.Unix(scope.IssuedUnix, 0)) {
		return empty, nil, false, invalid("snapshot plan recovery input")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return empty, nil, false, err
	}
	defer tx.Rollback()
	if err = requirePlanConstraints(ctx, tx); err != nil {
		return empty, nil, false, err
	}
	var verifier string
	if err = tx.QueryRowContext(ctx, "SELECT verifier FROM preprod_key_vault_meta WHERE singleton=1").Scan(&verifier); err != nil || subtle.ConstantTimeCompare([]byte(verifier), []byte(vaultTag(root, "verifier", scope.TargetNode))) != 1 {
		return empty, nil, false, invalid("snapshot plan recovery identity")
	}
	batchTag := vaultTag(root, "snapshot-plan-batch", scope.Snapshot)
	var planTag string
	err = tx.QueryRowContext(ctx, "SELECT plan_tag FROM preprod_snapshot_batch_links WHERE batch_tag=?", batchTag).Scan(&planTag)
	if errors.Is(err, sql.ErrNoRows) {
		return empty, nil, false, nil
	}
	if err != nil {
		return empty, nil, false, err
	}
	var salt, nonce, ciphertext []byte
	if err = tx.QueryRowContext(ctx, "SELECT salt,nonce,cipher FROM preprod_snapshot_plans WHERE plan_tag=?", planTag).Scan(&salt, &nonce, &ciphertext); err != nil {
		return empty, nil, false, invalid("snapshot plan recovery missing")
	}
	plain, err := openPlanEvidence(root, planTag, salt, nonce, ciphertext)
	if err != nil {
		return empty, nil, false, err
	}
	defer clear(plain)
	var evidence completeSnapshotEvidence
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&evidence); err != nil {
		return empty, nil, false, invalid("snapshot plan recovery payload")
	}
	var extra any
	if err = decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return empty, nil, false, invalid("snapshot plan recovery payload")
	}
	atIssue := time.Unix(scope.IssuedUnix, 0)
	if err = verifyPinnedSnapshotPlan(trust, evidence.Plan, evidence.Batches, atIssue); err != nil {
		return empty, nil, false, err
	}
	digest, err := snapshotPlanDigest(evidence.Plan.Body, atIssue)
	if err != nil || subtle.ConstantTimeCompare([]byte(planTag), []byte(vaultTag(root, "snapshot-plan", hex.EncodeToString(digest)))) != 1 {
		return empty, nil, false, invalid("snapshot plan recovery binding")
	}
	matched := false
	for _, batch := range evidence.Batches {
		if verifySnapshotGrant(batch, trust.SourcePublic, trust.TargetPublic, scope, atIssue) == nil {
			matched = true
			break
		}
	}
	if !matched {
		return empty, nil, false, invalid("snapshot plan recovery batch")
	}
	if err = tx.Commit(); err != nil {
		return empty, nil, false, err
	}
	return evidence.Plan, evidence.Batches, true, nil
}
