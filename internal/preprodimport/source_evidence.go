package preprodimport

// Encrypted migration-only source evidence. This stores no plaintext paths,
// does not register an import endpoint, and cannot authorize tree publication.
// The caller must hold its real identity/ingress guard through the transaction.
import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/snapshotcrypt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const maxSourceEvidenceBytes = 64 * 1024 * 1024

type sourceEvidenceRecord struct {
	Version        int                                `json:"version"`
	Digest         string                             `json:"digest"`
	PreviousDigest string                             `json:"previous_digest,omitempty"`
	Challenge      string                             `json:"challenge"`
	Pin            sourceAuthorityPin                 `json:"pin"`
	Envelope       store.EncryptedMediaSourceSnapshot `json:"envelope"`
	Complete       completeSnapshot                   `json:"complete"`
}

type sourceEvidenceRef struct{ Digest string }

func sourceEvidenceTag(root []byte, digest string) (string, error) {
	if len(root) != 32 || bytes.Equal(root, make([]byte, 32)) || !id64.MatchString(digest) {
		return "", invalid("source evidence key")
	}
	return vaultTag(root, "source-evidence", digest), nil
}

func requireSourceEvidenceConstraints(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT l."unique",l.partial,(SELECT group_concat(i.name, ',') FROM pragma_index_info(l.name) i) FROM pragma_index_list('preprod_source_evidence') l`)
	if err != nil {
		return invalid("source evidence constraints")
	}
	defer rows.Close()
	found := map[string]bool{}
	for rows.Next() {
		var unique, partial int
		var cols sql.NullString
		if rows.Scan(&unique, &partial, &cols) != nil {
			return invalid("source evidence constraints")
		}
		if unique == 1 && partial == 0 && cols.Valid {
			found[cols.String] = true
		}
	}
	if rows.Err() != nil || !found["evidence_tag"] || !found["salt"] || !found["challenge_tag"] {
		return invalid("source evidence constraints")
	}
	return nil
}

// The source evidence shares the target vault root and target identity. A
// wrong first-use key must not create an unrecoverable competing record.
func requireSourceEvidenceVaultIdentity(ctx context.Context, tx *sql.Tx, root []byte, target string) error {
	if len(root) != 32 || bytes.Equal(root, make([]byte, 32)) || !id32.MatchString(target) {
		return invalid("source evidence vault identity")
	}
	var verifier string
	if tx.QueryRowContext(ctx, "SELECT verifier FROM legacy_key_vault_meta WHERE singleton=1").Scan(&verifier) != nil || subtle.ConstantTimeCompare([]byte(verifier), []byte(legacyVaultTag(root, "verifier", target))) != 1 {
		return invalid("source evidence vault identity")
	}
	return nil
}

func sealSourceEvidence(root []byte, tag string, raw []byte) ([]byte, []byte, []byte, error) {
	if len(raw) == 0 || len(raw) > maxSourceEvidenceBytes {
		return nil, nil, nil, invalid("source evidence size")
	}
	salt, nonce := make([]byte, 32), make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, nil, err
	}
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, err
	}
	key := requestMAC(root, "source-evidence-encryption", salt)
	defer clear(key)
	aead, err := gcm(key)
	if err != nil {
		return nil, nil, nil, err
	}
	plain := make([]byte, (len(raw)+4+4095)/4096*4096)
	defer clear(plain)
	binary.BigEndian.PutUint32(plain[:4], uint32(len(raw)))
	copy(plain[4:], raw)
	return salt, nonce, aead.Seal(nil, nonce, plain, []byte(tag)), nil
}
func openSourceEvidence(root []byte, tag string, salt, nonce, ciphertext []byte) ([]byte, error) {
	if len(root) != 32 || bytes.Equal(root, make([]byte, 32)) || !id64.MatchString(tag) || len(salt) != 32 || len(nonce) != 12 || len(ciphertext) < 4096+16 || len(ciphertext) > maxSourceEvidenceBytes+4096+16 {
		return nil, invalid("source evidence row")
	}
	key := requestMAC(root, "source-evidence-encryption", salt)
	defer clear(key)
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, ciphertext, []byte(tag))
	if err != nil {
		return nil, invalid("source evidence authentication")
	}
	defer clear(plain)
	if len(plain)%4096 != 0 {
		return nil, invalid("source evidence padding")
	}
	n := int(binary.BigEndian.Uint32(plain[:4]))
	if n <= 0 || n > maxSourceEvidenceBytes || n > len(plain)-4 {
		return nil, invalid("source evidence length")
	}
	for _, v := range plain[4+n:] {
		if v != 0 {
			return nil, invalid("source evidence padding")
		}
	}
	return append([]byte(nil), plain[4:4+n]...), nil
}

func readSourceEvidenceTx(ctx context.Context, tx *sql.Tx, root []byte, receiver *ecdh.PrivateKey, pin sourceAuthorityPin, ref sourceEvidenceRef) (sourceEvidenceRecord, store.SignedMediaSourceSnapshot, error) {
	var empty sourceEvidenceRecord
	var no store.SignedMediaSourceSnapshot
	tag, err := sourceEvidenceTag(root, ref.Digest)
	if err != nil {
		return empty, no, err
	}
	var salt, nonce, ciphertext []byte
	var challengeTag string
	if err = tx.QueryRowContext(ctx, "SELECT salt,nonce,cipher,challenge_tag FROM preprod_source_evidence WHERE evidence_tag=?", tag).Scan(&salt, &nonce, &ciphertext, &challengeTag); err != nil {
		return empty, no, err
	}
	raw, err := openSourceEvidence(root, tag, salt, nonce, ciphertext)
	if err != nil {
		return empty, no, err
	}
	defer clear(raw)
	var record sourceEvidenceRecord
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&record) != nil {
		return empty, no, invalid("source evidence record")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF || record.Version != 1 || record.Digest != ref.Digest || challengeTag != vaultTag(root, "source-evidence-challenge", record.Challenge) || !reflect.DeepEqual(record.Pin, pin) || record.PreviousDigest != "" && !id64.MatchString(record.PreviousDigest) {
		return empty, no, invalid("source evidence binding")
	}
	signed, err := snapshotcrypt.Open(record.Envelope, receiver)
	if err != nil {
		return empty, no, invalid("source evidence envelope")
	}
	// Signature verification at issuance checks the original signature only.
	// It makes no claim about acceptance time and never renews authorization.
	checked, digest, err := authenticateCompleteSource(record.Envelope, receiver, pin, record.Challenge, time.Unix(signed.Snapshot.IssuedUnix, 0), record.Complete)
	if err != nil || digest != ref.Digest {
		return empty, no, invalid("source evidence verification")
	}
	return record, checked, nil
}

// verifySourceEvidenceChainTx verifies the complete encrypted predecessor
// chain in one read transaction. A missing predecessor is never a successful
// recovery. The bound prevents hostile or corrupt records causing unbounded
// verification work; exceeding it must not silently authorize renewal.
func verifySourceEvidenceChainTx(ctx context.Context, tx *sql.Tx, root []byte, receiver *ecdh.PrivateKey, pin sourceAuthorityPin, ref sourceEvidenceRef) (sourceEvidenceRecord, store.SignedMediaSourceSnapshot, string, error) {
	var empty sourceEvidenceRecord
	var no store.SignedMediaSourceSnapshot
	first, firstSigned, err := readSourceEvidenceTx(ctx, tx, root, receiver, pin, ref)
	if err != nil {
		return empty, no, "", err
	}
	seen := map[string]bool{ref.Digest: true}
	origin, previous := ref.Digest, first.PreviousDigest
	for steps := 0; previous != ""; steps++ {
		if steps >= 31 || seen[previous] {
			return empty, no, "", invalid("source evidence chain")
		}
		seen[previous] = true
		older, signed, e := readSourceEvidenceTx(ctx, tx, root, receiver, pin, sourceEvidenceRef{Digest: previous})
		if e != nil || !reflect.DeepEqual(older.Complete, first.Complete) || !reflect.DeepEqual(signed.Snapshot.Sections, firstSigned.Snapshot.Sections) {
			return empty, no, "", invalid("source evidence predecessor")
		}
		origin, previous = older.Digest, older.PreviousDigest
	}
	return first, firstSigned, origin, nil
}

func insertSourceEvidenceTx(ctx context.Context, tx *sql.Tx, root []byte, record sourceEvidenceRecord) error {
	tag, err := sourceEvidenceTag(root, record.Digest)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	defer clear(raw)
	var salt, nonce, ciphertext []byte
	var challengeTag string
	wantChallengeTag := vaultTag(root, "source-evidence-challenge", record.Challenge)
	err = tx.QueryRowContext(ctx, "SELECT salt,nonce,cipher,challenge_tag FROM preprod_source_evidence WHERE evidence_tag=?", tag).Scan(&salt, &nonce, &ciphertext, &challengeTag)
	if err == nil {
		old, e := openSourceEvidence(root, tag, salt, nonce, ciphertext)
		if e != nil {
			return e
		}
		defer clear(old)
		if challengeTag != wantChallengeTag || !bytes.Equal(old, raw) {
			return invalid("source evidence changed")
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	salt, nonce, ciphertext, err = sealSourceEvidence(root, tag, raw)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO preprod_source_evidence(evidence_tag,salt,nonce,cipher,challenge_tag) VALUES(?,?,?,?,?)", tag, salt, nonce, ciphertext, wantChallengeTag)
	return err
}

// saveSourceEvidence persists the exact verified encrypted envelope, complete
// projection and independent pin. It returns only a digest reference, never a
// permission to publish. Schema installation and identity authorization are
// separate gates; this function is not registered in product runtime.
func saveSourceEvidence(ctx context.Context, db *sql.DB, root []byte, receiver *ecdh.PrivateKey, pin sourceAuthorityPin, envelope store.EncryptedMediaSourceSnapshot, challenge string, complete completeSnapshot, now time.Time, guard func(context.Context) error) (sourceEvidenceRef, error) {
	var empty sourceEvidenceRef
	if ctx == nil || db == nil || receiver == nil || guard == nil || guard(ctx) != nil {
		return empty, invalid("source evidence input")
	}
	started := time.Now()
	signed, digest, err := authenticateCompleteSource(envelope, receiver, pin, challenge, now, complete)
	if err != nil {
		return empty, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err = requireSyntheticJournalDurability(ctx, tx); err != nil {
		return empty, err
	}
	if err = requireSourceEvidenceConstraints(ctx, tx); err != nil {
		return empty, err
	}
	if err = requireSourceEvidenceVaultIdentity(ctx, tx, root, pin.TargetNode); err != nil {
		return empty, err
	}
	record := sourceEvidenceRecord{Version: 1, Digest: digest, Challenge: challenge, Pin: pin, Envelope: envelope, Complete: complete}
	if err = insertSourceEvidenceTx(ctx, tx, root, record); err != nil {
		return empty, err
	}
	if guard(ctx) != nil || now.Add(time.Since(started)).Unix() >= signed.Snapshot.ExpiresUnix {
		return empty, invalid("source evidence guard")
	}
	if err = tx.Commit(); err != nil {
		return empty, err
	}
	return sourceEvidenceRef{Digest: digest}, nil
}

// renewSourceEvidence requires a fresh source signature at the actual current
// caller time and exact same nine SQL sections, pin and projection. Both old
// and new originals survive in the same DB transaction, with an encrypted
// link to the verified original. Each renewal is independently compared to
// that original, so the evidence chain does not grow indefinitely. This intentionally fails if even non-authoritative observed fields
// change; deciding which changing fields can be ignored is a later contract.
func renewSourceEvidence(ctx context.Context, db *sql.DB, root []byte, receiver *ecdh.PrivateKey, pin sourceAuthorityPin, previous sourceEvidenceRef, envelope store.EncryptedMediaSourceSnapshot, challenge string, complete completeSnapshot, now time.Time, guard func(context.Context) error) (sourceEvidenceRef, error) {
	var empty sourceEvidenceRef
	if ctx == nil || db == nil || receiver == nil || guard == nil || guard(ctx) != nil {
		return empty, invalid("source renewal input")
	}
	started := time.Now()
	current, digest, err := authenticateCompleteSource(envelope, receiver, pin, challenge, now, complete)
	if err != nil {
		return empty, err
	}
	if digest == previous.Digest {
		return empty, invalid("source renewal unchanged")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err = requireSyntheticJournalDurability(ctx, tx); err != nil {
		return empty, err
	}
	if err = requireSourceEvidenceConstraints(ctx, tx); err != nil {
		return empty, err
	}
	if err = requireSourceEvidenceVaultIdentity(ctx, tx, root, pin.TargetNode); err != nil {
		return empty, err
	}
	old, oldSigned, origin, err := verifySourceEvidenceChainTx(ctx, tx, root, receiver, pin, previous)
	if err != nil {
		return empty, err
	}
	if !reflect.DeepEqual(old.Complete, complete) || !reflect.DeepEqual(oldSigned.Snapshot.Sections, current.Snapshot.Sections) {
		return empty, invalid("source renewal facts changed")
	}
	record := sourceEvidenceRecord{Version: 1, Digest: digest, PreviousDigest: origin, Challenge: challenge, Pin: pin, Envelope: envelope, Complete: complete}
	if err = insertSourceEvidenceTx(ctx, tx, root, record); err != nil {
		return empty, err
	}
	if guard(ctx) != nil || now.Add(time.Since(started)).Unix() >= current.Snapshot.ExpiresUnix {
		return empty, invalid("source renewal guard")
	}
	if err = tx.Commit(); err != nil {
		return empty, err
	}
	return sourceEvidenceRef{Digest: digest}, nil
}

// recoverSourceEvidence verifies the historical signature and externally
// pinned identity, but grants no current authorization and returns no paths.
func recoverSourceEvidence(ctx context.Context, db *sql.DB, root []byte, receiver *ecdh.PrivateKey, pin sourceAuthorityPin, ref sourceEvidenceRef, guard func(context.Context) error) (bool, error) {
	if ctx == nil || db == nil || receiver == nil || guard == nil || guard(ctx) != nil {
		return false, invalid("source evidence recovery input")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err = requireSyntheticJournalDurability(ctx, tx); err != nil {
		return false, err
	}
	if err = requireSourceEvidenceConstraints(ctx, tx); err != nil {
		return false, err
	}
	if err = requireSourceEvidenceVaultIdentity(ctx, tx, root, pin.TargetNode); err != nil {
		return false, err
	}
	if _, _, _, err = verifySourceEvidenceChainTx(ctx, tx, root, receiver, pin, ref); err != nil {
		return false, err
	}
	if guard(ctx) != nil {
		return false, invalid("source evidence recovery guard")
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// verifyFreshSourceEvidence is a point-in-time migration observation: it
// requires the stored latest envelope to be currently valid, validates every
// predecessor in the same SQLite read transaction, and returns the original
// digest used by pending lyric evidence. It neither publishes nor holds a
// cross-database transaction; callers must maintain their real identity/tree
// leases and revalidate before any future authorized commit.
func verifyFreshSourceEvidence(ctx context.Context, db *sql.DB, root []byte, receiver *ecdh.PrivateKey, pin sourceAuthorityPin, ref sourceEvidenceRef, now time.Time, guard func(context.Context) error) (string, error) {
	if ctx == nil || db == nil || receiver == nil || guard == nil || guard(ctx) != nil {
		return "", invalid("fresh source evidence input")
	}
	started := time.Now()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if err = requireSyntheticJournalDurability(ctx, tx); err != nil {
		return "", err
	}
	if err = requireSourceEvidenceConstraints(ctx, tx); err != nil {
		return "", err
	}
	if err = requireSourceEvidenceVaultIdentity(ctx, tx, root, pin.TargetNode); err != nil {
		return "", err
	}
	latest, current, origin, err := verifySourceEvidenceChainTx(ctx, tx, root, receiver, pin, ref)
	if err != nil {
		return "", err
	}
	// The chain verifier has already authenticated the full projection and
	// decrypted the record; recheck only the current signature and lifetime.
	digest, err := verifyMediaSourceSnapshot(current, pin, latest.Challenge, now)
	if err != nil || digest != ref.Digest {
		return "", invalid("fresh source evidence authorization")
	}
	if guard(ctx) != nil || now.Add(time.Since(started)).Unix() >= current.Snapshot.ExpiresUnix {
		return "", invalid("fresh source evidence guard")
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return origin, nil
}
