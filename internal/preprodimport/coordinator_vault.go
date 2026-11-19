package preprodimport

import (
	"bytes"
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"time"
)

// verifyInstalledKeyPlan observes a committed, authenticated key request and
// its original signed plan. It never returns a file key or decrypts content.
// All vault rows are checked in one read transaction. This is not a cross-store
// atomic commit, source authority, rollback protection, or a publication permit.
func verifyInstalledKeyPlan(ctx context.Context, db *sql.DB, root []byte, trust snapshotPlanTrust, plan signedSnapshotPlan, batches []signedSnapshotGrant, scope keyScope, now time.Time) error {
	if ctx == nil || db == nil || len(root) != 32 || bytes.Equal(root, make([]byte, 32)) || !scope.valid(now) || scope.TargetNode != trust.TargetNode || scope.SourceNode != trust.SourceNode || scope.SourceKeyID != trust.SourceKeyID {
		return invalid("coordinator vault scope")
	}
	if err := verifyPinnedSnapshotPlan(trust, plan, batches, now); err != nil {
		return err
	}
	var member *signedSnapshotGrant
	for i := range batches {
		digest, err := snapshotGrantDigest(batches[i].Body, now)
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(scope.Snapshot), []byte(hex.EncodeToString(digest))) == 1 {
			member = &batches[i]
			break
		}
	}
	if member == nil {
		return invalid("coordinator vault batch")
	}
	if err := verifySnapshotGrant(*member, trust.SourcePublic, trust.TargetPublic, scope, now); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
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
	if err = requirePlanConstraints(ctx, tx); err != nil {
		return err
	}
	if err = requireSnapshotProofConstraints(ctx, tx); err != nil {
		return err
	}
	var verifier string
	if err = tx.QueryRowContext(ctx, "SELECT verifier FROM preprod_key_vault_meta WHERE singleton=1").Scan(&verifier); err != nil || subtle.ConstantTimeCompare([]byte(verifier), []byte(vaultTag(root, "verifier", scope.TargetNode))) != 1 {
		return invalid("coordinator vault identity")
	}
	tag := requestIndex(root, scope.Challenge)
	var nonce, ciphertext []byte
	if err = tx.QueryRowContext(ctx, "SELECT nonce,cipher FROM preprod_key_requests WHERE request_tag=?", tag).Scan(&nonce, &ciphertext); err != nil {
		return invalid("coordinator vault request")
	}
	request, err := openRequestedScope(root, tag, nonce, ciphertext)
	if err != nil || request.Scope != scope || subtle.ConstantTimeCompare(request.Source, trust.SourcePublic) != 1 || subtle.ConstantTimeCompare(request.Target, trust.TargetPublic) != 1 {
		return invalid("coordinator vault request")
	}
	hash, err := scopeDigest(scope)
	if err != nil {
		return err
	}
	var consumed []byte
	if err = tx.QueryRowContext(ctx, "SELECT receipt FROM preprod_key_request_consumed WHERE request_tag=?", tag).Scan(&consumed); err != nil || subtle.ConstantTimeCompare(consumed, requestMAC(root, "consumed", []byte(tag), hash)) != 1 {
		return invalid("coordinator vault request consumption")
	}
	var row keyVaultRow
	if err = tx.QueryRowContext(ctx, "SELECT object_tag,grant_tag,file_tag,salt,nonce,cipher FROM preprod_key_vault WHERE object_tag=?", vaultTag(root, "object", scope.MediaID)).Scan(&row.ObjectTag, &row.GrantTag, &row.FileTag, &row.Salt, &row.Nonce, &row.Cipher); err != nil {
		return invalid("coordinator vault key")
	}
	fileKey, err := openVaultKey(root, row, scope, trust.SourcePublic, trust.TargetPublic)
	if err != nil {
		return err
	}
	clear(fileKey)
	planTag := vaultTag(root, "snapshot-plan", trust.PlanDigest)
	var storedTag string
	if err = tx.QueryRowContext(ctx, "SELECT plan_tag FROM preprod_snapshot_batch_links WHERE batch_tag=?", vaultTag(root, "snapshot-plan-batch", scope.Snapshot)).Scan(&storedTag); err != nil || subtle.ConstantTimeCompare([]byte(storedTag), []byte(planTag)) != 1 {
		return invalid("coordinator vault plan link")
	}
	var salt []byte
	if err = tx.QueryRowContext(ctx, "SELECT salt,nonce,cipher FROM preprod_snapshot_plans WHERE plan_tag=?", planTag).Scan(&salt, &nonce, &ciphertext); err != nil {
		return invalid("coordinator vault plan")
	}
	actual, err := openPlanEvidence(root, planTag, salt, nonce, ciphertext)
	if err != nil {
		return err
	}
	defer clear(actual)
	expected, err := json.Marshal(completeSnapshotEvidence{Plan: plan, Batches: batches})
	if err != nil {
		return err
	}
	defer clear(expected)
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return invalid("coordinator vault plan mismatch")
	}
	proofTag := vaultTag(root, "snapshot-proof", scope.Snapshot)
	if err = tx.QueryRowContext(ctx, "SELECT salt,nonce,cipher FROM preprod_snapshot_proofs WHERE snapshot_tag=?", proofTag).Scan(&salt, &nonce, &ciphertext); err != nil {
		return invalid("coordinator vault proof")
	}
	proof, err := openSnapshotProof(root, proofTag, salt, nonce, ciphertext)
	if err != nil {
		return err
	}
	defer clear(proof)
	proofExpected, err := json.Marshal(*member)
	if err != nil {
		return err
	}
	defer clear(proofExpected)
	if subtle.ConstantTimeCompare(proof, proofExpected) != 1 {
		return invalid("coordinator vault proof mismatch")
	}
	return tx.Commit()
}
