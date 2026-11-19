package preprodimport

// These private primitives are an isolated authorization prototype. They do
// not authenticate a production node, authorize snapshot creation, export a
// production key, or make staged data eligible for runtime import.

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
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

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

const maxSnapshotGrantEntries = 2048

type snapshotGrantEntry struct {
	MediaID         string               `json:"media_id"`
	SourceObjectID  string               `json:"source_object_id"`
	TargetOwnerID   string               `json:"target_owner_id"`
	TargetBlobID    string               `json:"target_blob_id"`
	TargetReadAlias string               `json:"target_read_alias"`
	ContentSHA256   string               `json:"content_sha256"`
	StoredBytes     int64                `json:"stored_bytes"`
	Challenge       string               `json:"challenge"`
	Descriptor      mediacrypto.Metadata `json:"descriptor"`
}

type snapshotGrantBody struct {
	Version      int                  `json:"version"`
	SourceNode   string               `json:"source_node"`
	SourceKeyID  string               `json:"source_key_id"`
	TargetNode   string               `json:"target_node"`
	TargetPublic []byte               `json:"target_public"`
	Generation   string               `json:"generation"`
	BatchIndex   int                  `json:"batch_index"`
	BatchCount   int                  `json:"batch_count"`
	IssuedUnix   int64                `json:"issued_unix"`
	ExpiresUnix  int64                `json:"expires_unix"`
	Entries      []snapshotGrantEntry `json:"entries"`
}

type signedSnapshotGrant struct {
	Body      snapshotGrantBody `json:"body"`
	Signature []byte            `json:"signature"`
}

// snapshotGrantDigest uses a fixed struct encoding and requires entries sorted
// by media ID. Callers must treat this versioned encoding as an internal
// prototype; it is not the existing production snapshot format.
func snapshotGrantDigest(body snapshotGrantBody, now time.Time) ([]byte, error) {
	n := now.Unix()
	if body.Version != 1 || !id32.MatchString(body.SourceNode) || !id64.MatchString(body.SourceKeyID) || !id32.MatchString(body.TargetNode) || body.SourceNode == body.TargetNode || len(body.TargetPublic) != 32 || !id64.MatchString(body.Generation) || body.BatchCount <= 0 || body.BatchCount > 64 || body.BatchIndex < 0 || body.BatchIndex >= body.BatchCount || body.IssuedUnix <= 0 || body.IssuedUnix > n || body.ExpiresUnix <= n || body.ExpiresUnix <= body.IssuedUnix || body.ExpiresUnix-body.IssuedUnix > 300 || len(body.Entries) == 0 || len(body.Entries) > maxSnapshotGrantEntries {
		return nil, invalid("snapshot grant input")
	}
	seenMedia := map[string]bool{}
	seenObjects := map[string]bool{}
	seenBlobs := map[string]bool{}
	seenFiles := map[string]bool{}
	seenChallenges := map[string]bool{}
	previous := ""
	for _, e := range body.Entries {
		if !id64.MatchString(e.MediaID) || e.MediaID <= previous || !id64.MatchString(e.SourceObjectID) || !id32.MatchString(e.TargetOwnerID) || !id64.MatchString(e.TargetBlobID) || e.TargetBlobID == e.MediaID || e.TargetBlobID == e.SourceObjectID || !id64.MatchString(e.TargetReadAlias) || e.TargetReadAlias == e.TargetBlobID || e.TargetReadAlias == e.MediaID || e.TargetReadAlias == e.SourceObjectID || !id64.MatchString(e.ContentSHA256) || !id64.MatchString(e.Challenge) || e.Descriptor.Validate() != nil || e.StoredBytes != e.Descriptor.CiphertextSize || seenObjects[e.SourceObjectID] || seenBlobs[e.TargetBlobID] || seenBlobs[e.TargetReadAlias] || seenFiles[e.Descriptor.FileID] || seenChallenges[e.Challenge] {
			return nil, invalid("snapshot grant entry")
		}
		previous = e.MediaID
		seenMedia[e.MediaID] = true
		seenObjects[e.SourceObjectID] = true
		seenBlobs[e.TargetBlobID] = true
		seenBlobs[e.TargetReadAlias] = true
		seenFiles[e.Descriptor.FileID] = true
		seenChallenges[e.Challenge] = true
	}
	for _, e := range body.Entries {
		// An opaque locator must not repeat any historical source identifier in
		// the same grant, including another object's potentially path-hash ID.
		if seenObjects[e.TargetBlobID] || seenMedia[e.TargetBlobID] || seenObjects[e.TargetReadAlias] || seenMedia[e.TargetReadAlias] {
			return nil, invalid("snapshot blob collision")
		}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, invalid("snapshot grant encoding")
	}
	h := sha256.New()
	_, _ = h.Write([]byte("frontiercloud:preprod-authorized-snapshot:v1\x00"))
	_, _ = h.Write(raw)
	return h.Sum(nil), nil
}

// signApprovedSnapshot assumes an independently authenticated, immutable and
// already-authorized snapshot. Signing arbitrary caller data is not an access
// control mechanism; no production-facing entry point calls this primitive.
func signApprovedSnapshot(body snapshotGrantBody, signer ed25519.PrivateKey, now time.Time) (signedSnapshotGrant, error) {
	if len(signer) != ed25519.PrivateKeySize {
		return signedSnapshotGrant{}, invalid("snapshot signing key")
	}
	digest, err := snapshotGrantDigest(body, now)
	if err != nil {
		return signedSnapshotGrant{}, err
	}
	return signedSnapshotGrant{Body: body, Signature: ed25519.Sign(signer, digest)}, nil
}

func verifySnapshotGrant(g signedSnapshotGrant, source ed25519.PublicKey, target []byte, scope keyScope, now time.Time) error {
	if len(source) != ed25519.PublicKeySize || len(target) != 32 || len(g.Signature) != ed25519.SignatureSize || !scope.valid(now) || subtle.ConstantTimeCompare(g.Body.TargetPublic, target) != 1 {
		return invalid("snapshot grant identity")
	}
	digest, err := snapshotGrantDigest(g.Body, now)
	if err != nil || !ed25519.Verify(source, digest, g.Signature) || subtle.ConstantTimeCompare([]byte(scope.Snapshot), []byte(hex.EncodeToString(digest))) != 1 {
		return invalid("snapshot grant signature")
	}
	b := g.Body
	if b.SourceNode != scope.SourceNode || b.SourceKeyID != scope.SourceKeyID || b.TargetNode != scope.TargetNode || b.IssuedUnix != scope.IssuedUnix || b.ExpiresUnix != scope.ExpiresUnix {
		return invalid("snapshot grant scope")
	}
	for _, e := range b.Entries {
		if e.MediaID != scope.MediaID {
			continue
		}
		if e.SourceObjectID != scope.SourceObjectID || e.TargetOwnerID != scope.TargetOwnerID || e.TargetBlobID != scope.TargetBlobID || e.TargetReadAlias != scope.TargetReadAlias || e.ContentSHA256 != scope.ContentSHA256 || e.StoredBytes != scope.StoredBytes || e.Challenge != scope.Challenge || e.Descriptor != scope.Descriptor {
			return invalid("snapshot grant object")
		}
		return nil
	}
	return invalid("snapshot grant object absent")
}

// No real export is enabled: source identity pinning, source-side authorization
// and immutable source bytes must be established by a future caller first.
func sealSnapshotBoundDerivedFileKey(g signedSnapshotGrant, scope keyScope, manager *mediacrypto.Manager, target *ecdh.PublicKey, source ed25519.PublicKey, signer ed25519.PrivateKey, now time.Time) (keyGrant, error) {
	if target == nil || len(signer) != ed25519.PrivateKeySize || subtle.ConstantTimeCompare(signer.Public().(ed25519.PublicKey), source) != 1 {
		return keyGrant{}, invalid("snapshot signer")
	}
	if err := verifySnapshotGrant(g, source, target.Bytes(), scope, now); err != nil {
		return keyGrant{}, err
	}
	return sealDerivedFileKey(scope, manager, target, signer, now)
}

// importSnapshotAuthorizedFileKeyGrant composes a synthetic signed snapshot
// proof with request consumption and vault insertion in one transaction. It
// verifies all declared batches but does not establish trusted node pins,
// source authorization, an immutable source snapshot, that the signed plan
// includes every authorized source object, or a rollback-resistant anchor.
func importSnapshotAuthorizedFileKeyGrant(ctx context.Context, db *sql.DB, root []byte, trust snapshotPlanTrust, plan signedSnapshotPlan, batches []signedSnapshotGrant, snapshot signedSnapshotGrant, scope keyScope, target *ecdh.PrivateKey, grant keyGrant, now time.Time) (bool, error) {
	if db == nil || target == nil {
		return false, invalid("snapshot target")
	}
	if subtle.ConstantTimeCompare(trust.TargetPublic, target.PublicKey().Bytes()) != 1 {
		return false, invalid("snapshot target pin")
	}
	if err := verifyPinnedSnapshotPlan(trust, plan, batches, now); err != nil {
		return false, err
	}
	source := trust.SourcePublic
	if err := verifySnapshotGrant(snapshot, source, target.PublicKey().Bytes(), scope, now); err != nil {
		return false, err
	}
	member := false
	for _, batch := range plan.Body.Batches {
		if subtle.ConstantTimeCompare([]byte(batch.Digest), []byte(scope.Snapshot)) == 1 {
			member = true
			break
		}
	}
	if !member {
		return false, invalid("snapshot absent from plan")
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
	if err = saveCompletePlanTx(ctx, tx, root, plan, batches, now); err != nil {
		return false, err
	}
	if err = saveSnapshotProofTx(ctx, tx, root, snapshot, scope, source, target.PublicKey().Bytes()); err != nil {
		return false, err
	}
	already, err := importAuthorizedFileKeyGrantTx(ctx, tx, root, scope, target, source, grant, fileKey)
	if err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return already, nil
}

// Snapshot proofs are encrypted and padded on the trusted target Master. The
// future schema must permanently retain salts across deletion and recovery;
// whole-database rollback detection requires an independent monotonic anchor.
func saveSnapshotProofTx(ctx context.Context, tx *sql.Tx, root []byte, snapshot signedSnapshotGrant, scope keyScope, source ed25519.PublicKey, target []byte) error {
	if len(root) != 32 || bytes.Equal(root, make([]byte, 32)) {
		return invalid("snapshot proof root")
	}
	if err := requireSnapshotProofConstraints(ctx, tx); err != nil {
		return err
	}
	tag := vaultTag(root, "snapshot-proof", scope.Snapshot)
	encoded, err := json.Marshal(snapshot)
	if err != nil || len(encoded) == 0 || len(encoded) > 2*1024*1024 {
		return invalid("snapshot proof size")
	}
	defer clear(encoded)
	var salt, nonce, ciphertext []byte
	err = tx.QueryRowContext(ctx, "SELECT salt,nonce,cipher FROM preprod_snapshot_proofs WHERE snapshot_tag=?", tag).Scan(&salt, &nonce, &ciphertext)
	if err == nil {
		plain, openErr := openSnapshotProof(root, tag, salt, nonce, ciphertext)
		if openErr != nil {
			return openErr
		}
		defer clear(plain)
		if subtle.ConstantTimeCompare(plain, encoded) != 1 {
			return invalid("snapshot proof changed")
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	// Ensure the originally signed object is verifiable independently at its
	// signed issue time, even when later read only for recovery after expiry.
	if err = verifySnapshotGrant(snapshot, source, target, scope, time.Unix(scope.IssuedUnix, 0)); err != nil {
		return err
	}
	salt = make([]byte, 32)
	nonce = make([]byte, 12)
	if _, err = io.ReadFull(rand.Reader, salt); err != nil {
		return invalid("snapshot proof salt")
	}
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return invalid("snapshot proof nonce")
	}
	key := requestMAC(root, "snapshot-proof-encryption", salt)
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
	_, err = tx.ExecContext(ctx, "INSERT INTO preprod_snapshot_proofs(snapshot_tag,salt,nonce,cipher) VALUES (?,?,?,?)", tag, salt, nonce, ciphertext)
	return err
}

func requireSnapshotProofConstraints(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT l."unique",l.partial,(SELECT group_concat(i.name, ',') FROM pragma_index_info(l.name) i) FROM pragma_index_list('preprod_snapshot_proofs') l`)
	if err != nil {
		return invalid("snapshot proof constraints")
	}
	found := map[string]bool{}
	for rows.Next() {
		var unique, partial int
		var cols sql.NullString
		if err = rows.Scan(&unique, &partial, &cols); err != nil {
			rows.Close()
			return invalid("snapshot proof constraints")
		}
		if unique == 1 && partial == 0 && cols.Valid {
			found[cols.String] = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil || !found["snapshot_tag"] || !found["salt"] {
		return invalid("snapshot proof constraints")
	}
	return nil
}

func openSnapshotProof(root []byte, tag string, salt, nonce, ciphertext []byte) ([]byte, error) {
	if len(root) != 32 || bytes.Equal(root, make([]byte, 32)) || !id64.MatchString(tag) || len(salt) != 32 || len(nonce) != 12 || len(ciphertext) < 4096+16 || len(ciphertext) > 2*1024*1024+4096+16 {
		return nil, invalid("snapshot proof row")
	}
	key := requestMAC(root, "snapshot-proof-encryption", salt)
	defer clear(key)
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, ciphertext, []byte(tag))
	if err != nil {
		return nil, invalid("snapshot proof authentication")
	}
	defer clear(plain)
	if len(plain)%4096 != 0 {
		return nil, invalid("snapshot proof padding")
	}
	n := int(binary.BigEndian.Uint32(plain[:4]))
	if n <= 0 || n > len(plain)-4 || n > 2*1024*1024 {
		return nil, invalid("snapshot proof length")
	}
	for _, b := range plain[n+4:] {
		if b != 0 {
			return nil, invalid("snapshot proof padding")
		}
	}
	return append([]byte(nil), plain[4:n+4]...), nil
}

// recoverSnapshotProof authenticates the originally stored proof for a status
// operation, including after its delivery expiry. It does not install a key,
// renew a grant, authorize a caller, or prove cross-database commit/anti-rollback.
func recoverSnapshotProof(ctx context.Context, db *sql.DB, root []byte, scope keyScope, source ed25519.PublicKey, target []byte) (signedSnapshotGrant, bool, error) {
	var empty signedSnapshotGrant
	if db == nil || len(root) != 32 || !scope.valid(time.Unix(scope.IssuedUnix, 0)) {
		return empty, false, invalid("snapshot recovery input")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return empty, false, err
	}
	defer tx.Rollback()
	if err = requireSnapshotProofConstraints(ctx, tx); err != nil {
		return empty, false, err
	}
	var verifier string
	if err = tx.QueryRowContext(ctx, "SELECT verifier FROM preprod_key_vault_meta WHERE singleton=1").Scan(&verifier); err != nil || subtle.ConstantTimeCompare([]byte(verifier), []byte(vaultTag(root, "verifier", scope.TargetNode))) != 1 {
		return empty, false, invalid("snapshot recovery identity")
	}
	tag := vaultTag(root, "snapshot-proof", scope.Snapshot)
	var salt, nonce, ciphertext []byte
	err = tx.QueryRowContext(ctx, "SELECT salt,nonce,cipher FROM preprod_snapshot_proofs WHERE snapshot_tag=?", tag).Scan(&salt, &nonce, &ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return empty, false, nil
	}
	if err != nil {
		return empty, false, err
	}
	plain, err := openSnapshotProof(root, tag, salt, nonce, ciphertext)
	if err != nil {
		return empty, false, err
	}
	defer clear(plain)
	var snapshot signedSnapshotGrant
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if err = d.Decode(&snapshot); err != nil {
		return empty, false, invalid("snapshot recovery payload")
	}
	var extra any
	if err = d.Decode(&extra); !errors.Is(err, io.EOF) {
		return empty, false, invalid("snapshot recovery payload")
	}
	if err = verifySnapshotGrant(snapshot, source, target, scope, time.Unix(scope.IssuedUnix, 0)); err != nil {
		return empty, false, err
	}
	if err = tx.Commit(); err != nil {
		return empty, false, err
	}
	return snapshot, true, nil
}
