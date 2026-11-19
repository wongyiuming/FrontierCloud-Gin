package preprodimport

// Isolated legacy-source compatibility. A target-signed observation records
// what the target observed on its independently authenticated channel; it is
// never represented as a signature made by the source. No route or runtime
// resolver invokes this code. Real use additionally requires pinned source
// SSH/TLS identities, operator authorization, current target identity, a
// complete snapshot and an owner/tree publication coordinator.
import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"golang.org/x/crypto/hkdf"
)

type legacyObservationScope struct {
	Key                  keyScope `json:"key"`
	Kind                 string   `json:"kind"`
	SourceSnapshotDigest string   `json:"source_snapshot_digest"`
	SourceHostPin        string   `json:"source_host_pin"`
	SourceTLSPin         string   `json:"source_tls_pin"`
	TargetSigningKey     []byte   `json:"target_signing_key"`
}

type legacyObservationBody struct {
	Scope          legacyObservationScope   `json:"scope"`
	Grant          mediacrypto.SessionGrant `json:"grant"`
	Envelope       mediacrypto.KeyEnvelope  `json:"envelope"`
	ReceiverPublic []byte                   `json:"receiver_public"`
	Commitment     []byte                   `json:"commitment"`
}
type legacyObservation struct {
	Body      legacyObservationBody `json:"body"`
	Signature []byte                `json:"signature"`
}
type legacyVaultPayload struct {
	Observation legacyObservation `json:"observation"`
	Key         []byte            `json:"key"`
}
type legacyVaultRow struct {
	ObjectTag, FileTag, ChallengeTag string
	Salt, Nonce, Cipher              []byte
}

func legacyObservationBytes(body legacyObservationBody) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, invalid("legacy observation")
	}
	return append([]byte("frontiercloud:legacy-target-observation:v1\x00"), raw...), nil
}
func legacyCommitment(scope legacyObservationScope, key []byte) ([]byte, error) {
	raw, err := json.Marshal(scope)
	if err != nil {
		return nil, invalid("legacy scope")
	}
	h := sha256.New()
	h.Write([]byte("frontiercloud:legacy-file-key-commitment:v1\x00"))
	h.Write(raw)
	h.Write(key)
	return h.Sum(nil), nil
}
func legacyScopeValid(scope legacyObservationScope, now time.Time) bool {
	// Legacy lyrics are deliberately excluded; their separate authorization and
	// lifecycle must be implemented before they can enter this vault.
	return scope.Key.valid(now) && (scope.Kind == "audio" || scope.Kind == "video") && id64.MatchString(scope.SourceSnapshotDigest) && id64.MatchString(scope.SourceHostPin) && id64.MatchString(scope.SourceTLSPin) && len(scope.TargetSigningKey) == ed25519.PublicKeySize
}
func legacyVaultTag(root []byte, label, value string) string {
	return vaultTag(root, "legacy-"+label, value)
}

func requireLegacyVaultConstraints(ctx context.Context, tx *sql.Tx) error {
	var synchronous int
	if tx.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous) != nil || synchronous < 2 {
		return invalid("legacy vault durability")
	}
	rows, err := tx.QueryContext(ctx, `SELECT l."unique",l.partial,(SELECT group_concat(i.name, ',') FROM pragma_index_info(l.name) i) FROM pragma_index_list('legacy_key_vault') l`)
	if err != nil {
		return invalid("legacy vault constraints")
	}
	defer rows.Close()
	found := map[string]bool{}
	for rows.Next() {
		var unique, partial int
		var columns sql.NullString
		if rows.Scan(&unique, &partial, &columns) != nil {
			return invalid("legacy vault constraints")
		}
		if unique == 1 && partial == 0 && columns.Valid {
			found[columns.String] = true
		}
	}
	if rows.Err() != nil || !found["object_tag"] || !found["file_tag"] || !found["challenge_tag"] || !found["salt"] {
		return invalid("legacy vault constraints")
	}
	return nil
}

func sealLegacyVault(root []byte, payload legacyVaultPayload) (legacyVaultRow, error) {
	var row legacyVaultRow
	if len(root) != 32 || bytes.Equal(root, make([]byte, 32)) || len(payload.Key) != 32 {
		return row, invalid("legacy vault key")
	}
	row.ObjectTag = legacyVaultTag(root, "object", payload.Observation.Body.Scope.Key.MediaID)
	row.FileTag = legacyVaultTag(root, "file", payload.Observation.Body.Scope.Key.Descriptor.FileID)
	row.ChallengeTag = legacyVaultTag(root, "challenge", payload.Observation.Body.Scope.Key.Challenge)
	row.Salt = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, row.Salt); err != nil {
		return row, invalid("legacy vault random")
	}
	key := make([]byte, 32)
	defer clear(key)
	if _, err := io.ReadFull(hkdf.New(sha256.New, root, row.Salt, []byte("frontiercloud:legacy-observation-vault:v1")), key); err != nil {
		return row, invalid("legacy vault derivation")
	}
	aead, err := gcm(key)
	if err != nil {
		return row, err
	}
	row.Nonce = make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, row.Nonce); err != nil {
		return row, invalid("legacy vault random")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return row, invalid("legacy vault payload")
	}
	defer clear(raw)
	row.Cipher = aead.Seal(nil, row.Nonce, raw, []byte(row.ObjectTag+":"+row.FileTag+":"+row.ChallengeTag))
	return row, nil
}

func openLegacyVault(root []byte, row legacyVaultRow, expected legacyObservationScope, targetPublic ed25519.PublicKey) (legacyVaultPayload, error) {
	var out legacyVaultPayload
	if len(root) != 32 || len(row.Salt) != 32 || len(row.Nonce) != 12 || len(row.Cipher) < 16 || len(row.Cipher) > 16384 || len(targetPublic) != ed25519.PublicKeySize || row.ObjectTag != legacyVaultTag(root, "object", expected.Key.MediaID) || row.FileTag != legacyVaultTag(root, "file", expected.Key.Descriptor.FileID) || row.ChallengeTag != legacyVaultTag(root, "challenge", expected.Key.Challenge) {
		return out, invalid("legacy vault row")
	}
	key := make([]byte, 32)
	defer clear(key)
	if _, err := io.ReadFull(hkdf.New(sha256.New, root, row.Salt, []byte("frontiercloud:legacy-observation-vault:v1")), key); err != nil {
		return out, invalid("legacy vault derivation")
	}
	aead, err := gcm(key)
	if err != nil {
		return out, err
	}
	raw, err := aead.Open(nil, row.Nonce, row.Cipher, []byte(row.ObjectTag+":"+row.FileTag+":"+row.ChallengeTag))
	if err != nil {
		return out, invalid("legacy vault authentication")
	}
	defer clear(raw)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&out) != nil || dec.Decode(new(any)) != io.EOF || len(out.Key) != 32 {
		clear(out.Key)
		return legacyVaultPayload{}, invalid("legacy vault payload")
	}
	want, _ := json.Marshal(expected)
	got, _ := json.Marshal(out.Observation.Body.Scope)
	signed, err := legacyObservationBytes(out.Observation.Body)
	commit, e := legacyCommitment(expected, out.Key)
	if err != nil || e != nil || !bytes.Equal(want, got) || subtle.ConstantTimeCompare(expected.TargetSigningKey, targetPublic) != 1 || !ed25519.Verify(targetPublic, signed, out.Observation.Signature) || subtle.ConstantTimeCompare(commit, out.Observation.Body.Commitment) != 1 {
		clear(out.Key)
		return legacyVaultPayload{}, invalid("legacy vault proof")
	}
	return out, nil
}

// observeLegacyKeyAndStoreGuarded is called only within a future authenticated source
// acquisition flow. It authenticates the session envelope and atomically
// stores a target-signed observation and encrypted key in an explicitly
// provisioned, independent target vault. Existing records are never replaced.
// Snapshot/channel authorization and cross-table uniqueness are external hard
// gates; this function is intentionally package-private and unregistered.
func observeLegacyKeyAndStoreGuarded(ctx context.Context, db *sql.DB, root []byte, scope legacyObservationScope, receiver *legacyReceiver, grant mediacrypto.SessionGrant, response mediacrypto.Metadata, envelope mediacrypto.KeyEnvelope, signer ed25519.PrivateKey, now time.Time, guard func(context.Context) error) (bool, error) {
	if ctx == nil || db == nil || guard == nil || guard(ctx) != nil || len(root) != 32 || bytes.Equal(root, make([]byte, 32)) || !legacyScopeValid(scope, now) || len(signer) != ed25519.PrivateKeySize || subtle.ConstantTimeCompare(signer.Public().(ed25519.PublicKey), scope.TargetSigningKey) != 1 {
		return false, invalid("legacy observation input")
	}
	fileKey, err := receiver.open(grant, response, scope.Key.Descriptor, envelope, now)
	if err != nil {
		return false, err
	}
	defer clear(fileKey)
	commit, err := legacyCommitment(scope, fileKey)
	if err != nil {
		return false, err
	}
	body := legacyObservationBody{Scope: scope, Grant: grant, Envelope: envelope, ReceiverPublic: receiver.private.PublicKey().Bytes(), Commitment: commit}
	signed, err := legacyObservationBytes(body)
	if err != nil {
		return false, err
	}
	signature := ed25519.Sign(signer, signed)
	if !ed25519.Verify(scope.TargetSigningKey, signed, signature) {
		return false, invalid("legacy target signature")
	}
	payload := legacyVaultPayload{Observation: legacyObservation{Body: body, Signature: signature}, Key: fileKey}
	row, err := sealLegacyVault(root, payload)
	if err != nil {
		return false, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err = requireLegacyVaultConstraints(ctx, tx); err != nil {
		return false, err
	}
	var verifier string
	if tx.QueryRowContext(ctx, "SELECT verifier FROM legacy_key_vault_meta WHERE singleton=1").Scan(&verifier) != nil || subtle.ConstantTimeCompare([]byte(verifier), []byte(legacyVaultTag(root, "verifier", scope.Key.TargetNode))) != 1 {
		return false, invalid("legacy vault identity")
	}
	requestTag, consumed, err := checkLegacyRequestTx(ctx, tx, root, scope)
	if err != nil {
		return false, err
	}
	var old legacyVaultRow
	err = tx.QueryRowContext(ctx, "SELECT object_tag,file_tag,challenge_tag,salt,nonce,cipher FROM legacy_key_vault WHERE object_tag=?", row.ObjectTag).Scan(&old.ObjectTag, &old.FileTag, &old.ChallengeTag, &old.Salt, &old.Nonce, &old.Cipher)
	if err == nil {
		if consumed != 1 {
			return false, invalid("legacy vault orphan")
		}
		prior, e := openLegacyVault(root, old, scope, scope.TargetSigningKey)
		if e != nil {
			return false, e
		}
		defer clear(prior.Key)
		if subtle.ConstantTimeCompare(prior.Key, fileKey) != 1 {
			return false, invalid("legacy key conflict")
		}
		if ctx.Err() != nil || time.Now().Unix() >= grant.ExpiresAt || time.Now().Unix() >= scope.Key.ExpiresUnix || guard(ctx) != nil {
			return false, invalid("legacy observation expired")
		}
		if err = tx.Commit(); err != nil {
			return false, err
		}
		return true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if consumed != 0 {
		return false, invalid("legacy consumed request missing vault")
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO legacy_key_vault(object_tag,file_tag,challenge_tag,salt,nonce,cipher) VALUES(?,?,?,?,?,?)", row.ObjectTag, row.FileTag, row.ChallengeTag, row.Salt, row.Nonce, row.Cipher); err != nil {
		return false, invalid("legacy vault conflict")
	}
	update, err := tx.ExecContext(ctx, "UPDATE legacy_key_requests SET consumed=1 WHERE request_tag=? AND consumed=0", requestTag)
	if err != nil {
		return false, invalid("legacy request consume")
	}
	count, err := update.RowsAffected()
	if err != nil || count != 1 {
		return false, invalid("legacy request consume")
	}
	if ctx.Err() != nil || time.Now().Unix() >= grant.ExpiresAt || time.Now().Unix() >= scope.Key.ExpiresUnix || guard(ctx) != nil {
		return false, invalid("legacy observation expired")
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return false, nil
}
