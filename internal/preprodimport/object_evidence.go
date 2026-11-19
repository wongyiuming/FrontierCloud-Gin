package preprodimport

// SSH object observations are retained separately from source snapshot facts.
// They are encrypted evidence, never a publish authorization. The expensive
// snapshot and signature checks happen without an externally held tree lease;
// a caller-provided real identity guard is required only for the short commit.
// This isolated schema and API are not installed in the runtime.
import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/snapshotcrypt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type objectEvidenceRecord struct {
	Version      int                                `json:"version"`
	SourceDigest string                             `json:"source_digest"`
	ObjectID     string                             `json:"object_id"`
	Scope        objectProofScope                   `json:"scope"`
	Envelope     store.EncryptedMediaSourceSnapshot `json:"envelope"`
}
type objectEvidenceRef struct{ Digest string }

// A future caller must acquire a real owner/identity guard in the established
// order. The lease is acquired only after expensive evidence verification and
// released after the short transaction; this seam is not a runtime entry.
type objectEvidenceLease interface {
	Check(context.Context) error
	Release()
}
type objectEvidenceAcquire func(context.Context) (objectEvidenceLease, error)

func acquireObjectEvidenceLease(ctx context.Context, acquire objectEvidenceAcquire) (objectEvidenceLease, error) {
	if acquire == nil {
		return nil, invalid("object evidence guard")
	}
	lease, err := acquire(ctx)
	valid := lease != nil
	if valid {
		v := reflect.ValueOf(lease)
		switch v.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			valid = !v.IsNil()
		}
	}
	if err != nil || !valid {
		if valid {
			lease.Release()
		}
		return nil, invalid("object evidence guard")
	}
	if lease.Check(ctx) != nil {
		lease.Release()
		return nil, invalid("object evidence guard")
	}
	return lease, nil
}

func objectEvidenceKey(root []byte, target string) ([]byte, error) {
	if len(root) != 32 || bytes.Equal(root, make([]byte, 32)) || !id32.MatchString(target) {
		return nil, invalid("object evidence key")
	}
	return requestMAC(root, "ssh-object-evidence-root", []byte(target)), nil
}
func objectEvidenceTag(root []byte, digest string) (string, error) {
	if len(root) != 32 || !id64.MatchString(digest) {
		return "", invalid("object evidence digest")
	}
	return vaultTag(root, "ssh-object-evidence", digest), nil
}
func objectEvidenceConstraints(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT l."unique",l.partial,(SELECT group_concat(i.name, ',') FROM pragma_index_info(l.name) i) FROM pragma_index_list('preprod_object_evidence') l`)
	if err != nil {
		return invalid("object evidence constraints")
	}
	defer rows.Close()
	found := map[string]bool{}
	for rows.Next() {
		var unique, partial int
		var cols sql.NullString
		if rows.Scan(&unique, &partial, &cols) != nil {
			return invalid("object evidence constraints")
		}
		if unique == 1 && partial == 0 && cols.Valid {
			found[cols.String] = true
		}
	}
	if rows.Err() != nil || !found["evidence_tag"] || !found["salt"] || !found["challenge_tag"] {
		return invalid("object evidence constraints")
	}
	return nil
}
func evidenceObjectMedia(complete completeSnapshot, pin sourceAuthorityPin, id string) (Media, error) {
	var out Media
	found := false
	for _, v := range complete.Projection.Media {
		if v.MediaID == id {
			if found {
				return out, invalid("object evidence duplicate")
			}
			out = v
			found = true
		}
	}
	for _, v := range complete.Projection.Lyrics {
		if v.ID == id {
			if found || v.Builtin || v.Encryption != nil {
				return out, invalid("object evidence lyric")
			}
			out = Media{MediaID: v.ID, ObjectID: v.ID, SourceID: pin.SourceNode, Path: v.Path, Kind: "lyric", Size: v.Size, SHA256: v.SHA256}
			found = true
		}
	}
	if !found {
		return out, invalid("object evidence absent")
	}
	return out, nil
}
func decodeObjectEvidenceProof(envelope store.EncryptedMediaSourceSnapshot, receiver *ecdh.PrivateKey) (signedSSHObjectProof, error) {
	var signed signedSSHObjectProof
	raw, err := snapshotcrypt.OpenObjectProof(envelope, receiver)
	if err != nil {
		return signed, invalid("object evidence envelope")
	}
	defer clear(raw)
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&signed) != nil || d.Decode(new(any)) != io.EOF {
		return signed, invalid("object evidence proof")
	}
	return signed, nil
}

// This experimental cap fails closed; larger legitimate snapshots need a
// paged verifier before this isolated seam can be enabled.
const objectEvidenceMaxSourceCipherBytes = 4 * 1024 * 1024
const objectEvidenceMaxObjectCipherBytes = 2 * 1024 * 1024

// A bounded encrypted row can be copied from a short SQLite snapshot. Its
// contents remain ciphertext until the snapshot has closed.
type objectSourceRow struct {
	ref                 sourceEvidenceRef
	salt, nonce, cipher []byte
	challenge           string
}

func readObjectSourceRow(ctx context.Context, tx *sql.Tx, root []byte, ref sourceEvidenceRef) (objectSourceRow, error) {
	var out objectSourceRow
	out.ref = ref
	tag, err := sourceEvidenceTag(root, ref.Digest)
	if err != nil {
		return out, err
	}
	var n int64
	if tx.QueryRowContext(ctx, "SELECT length(cipher) FROM preprod_source_evidence WHERE evidence_tag=?", tag).Scan(&n) != nil || n < 4096+16 || n > objectEvidenceMaxSourceCipherBytes {
		return out, invalid("object evidence source size")
	}
	if tx.QueryRowContext(ctx, "SELECT salt,nonce,cipher,challenge_tag FROM preprod_source_evidence WHERE evidence_tag=?", tag).Scan(&out.salt, &out.nonce, &out.cipher, &out.challenge) != nil || int64(len(out.cipher)) != n {
		return out, invalid("object evidence source missing")
	}
	return out, nil
}
func copyObjectSourceRow(ctx context.Context, db *sql.DB, root []byte, pin sourceAuthorityPin, ref sourceEvidenceRef) (objectSourceRow, error) {
	var empty objectSourceRow
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err = requireSyntheticJournalDurability(ctx, tx); err != nil {
		return empty, err
	}
	var mode string
	if tx.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode) != nil || mode != "wal" {
		return empty, invalid("object evidence requires WAL")
	}
	if err = requireSourceEvidenceConstraints(ctx, tx); err != nil {
		return empty, err
	}
	if err = requireSourceEvidenceVaultIdentity(ctx, tx, root, pin.TargetNode); err != nil {
		return empty, err
	}
	row, err := readObjectSourceRow(ctx, tx, root, ref)
	if err != nil {
		return empty, err
	}
	if err = tx.Commit(); err != nil {
		return empty, err
	}
	return row, nil
}

// decodeObjectSourceRow is called only after the SQL read snapshot is closed.
func decodeObjectSourceRow(root []byte, receiver *ecdh.PrivateKey, pin sourceAuthorityPin, row objectSourceRow) (sourceEvidenceRecord, store.SignedMediaSourceSnapshot, error) {
	var empty sourceEvidenceRecord
	var no store.SignedMediaSourceSnapshot
	tag, err := sourceEvidenceTag(root, row.ref.Digest)
	if err != nil {
		return empty, no, err
	}
	raw, err := openSourceEvidence(root, tag, row.salt, row.nonce, row.cipher)
	if err != nil {
		return empty, no, err
	}
	defer clear(raw)
	var rec sourceEvidenceRecord
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&rec) != nil || d.Decode(new(any)) != io.EOF || rec.Version != 1 || rec.Digest != row.ref.Digest || row.challenge != vaultTag(root, "source-evidence-challenge", rec.Challenge) || !reflect.DeepEqual(rec.Pin, pin) || rec.PreviousDigest != "" && !id64.MatchString(rec.PreviousDigest) {
		return empty, no, invalid("object evidence source binding")
	}
	signed, err := snapshotcrypt.Open(rec.Envelope, receiver)
	if err != nil {
		return empty, no, invalid("object evidence source envelope")
	}
	checked, digest, err := authenticateCompleteSource(rec.Envelope, receiver, pin, rec.Challenge, time.Unix(signed.Snapshot.IssuedUnix, 0), rec.Complete)
	if err != nil || digest != row.ref.Digest {
		return empty, no, invalid("object evidence source signature")
	}
	return rec, checked, nil
}
func sameObjectSourceRow(a, b objectSourceRow) bool {
	return a.ref == b.ref && a.challenge == b.challenge && bytes.Equal(a.salt, b.salt) && bytes.Equal(a.nonce, b.nonce) && bytes.Equal(a.cipher, b.cipher)
}
func checkObjectSourceRows(ctx context.Context, tx *sql.Tx, root []byte, rows []objectSourceRow) error {
	for _, expected := range rows {
		current, err := readObjectSourceRow(ctx, tx, root, expected.ref)
		if err != nil || !sameObjectSourceRow(expected, current) {
			return invalid("object evidence source changed")
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return nil
}

var objectEvidenceSingle = make(chan struct{}, 1)

func enterObjectEvidence(ctx context.Context) (context.Context, func(), error) {
	if ctx == nil {
		return nil, nil, invalid("object evidence context")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	select {
	case objectEvidenceSingle <- struct{}{}:
		return ctx, func() { <-objectEvidenceSingle; cancel() }, nil
	case <-ctx.Done():
		cancel()
		return nil, nil, invalid("object evidence budget")
	}
}

// prepareObjectEvidence copies each bounded source record using a short read
// snapshot, then authenticates it and the object proof outside every snapshot.
// Final commit compares all exact copied ciphertext in one new transaction.
func prepareObjectEvidence(ctx context.Context, db *sql.DB, root []byte, receiver *ecdh.PrivateKey, pin sourceAuthorityPin, record objectEvidenceRecord, fresh bool) ([]objectSourceRow, int64, int64, error) {
	if ctx == nil || db == nil || receiver == nil || record.Version != 1 || !id64.MatchString(record.SourceDigest) || !id64.MatchString(record.ObjectID) {
		return nil, 0, 0, invalid("object evidence input")
	}
	row, err := copyObjectSourceRow(ctx, db, root, pin, sourceEvidenceRef{Digest: record.SourceDigest})
	if err != nil {
		return nil, 0, 0, err
	}
	source, signed, err := decodeObjectSourceRow(root, receiver, pin, row)
	if err != nil {
		return nil, 0, 0, err
	}
	rows := []objectSourceRow{row}
	if source.PreviousDigest != "" {
		olderRow, e := copyObjectSourceRow(ctx, db, root, pin, sourceEvidenceRef{Digest: source.PreviousDigest})
		if e != nil {
			return nil, 0, 0, e
		}
		older, oldSigned, e := decodeObjectSourceRow(root, receiver, pin, olderRow)
		if e != nil || older.PreviousDigest != "" || !reflect.DeepEqual(older.Complete, source.Complete) || !reflect.DeepEqual(oldSigned.Snapshot.Sections, signed.Snapshot.Sections) {
			return nil, 0, 0, invalid("object evidence predecessor")
		}
		rows = append(rows, olderRow)
	}
	if ctx.Err() != nil {
		return nil, 0, 0, ctx.Err()
	}
	media, err := evidenceObjectMedia(source.Complete, pin, record.ObjectID)
	if err != nil {
		return nil, 0, 0, err
	}
	// A signed proof cannot redirect a source owner to an arbitrary target.
	// The mapping has already been authenticated as part of the full snapshot.
	matches := 0
	for _, mapping := range source.Complete.Projection.Mappings {
		if mapping.SourceID == media.SourceID {
			matches++
			if mapping.TargetID != record.Scope.TargetOwnerID || (media.Kind == "lyric" && mapping.Role != "master") {
				return nil, 0, 0, invalid("object evidence owner mapping")
			}
		}
	}
	if matches != 1 {
		return nil, 0, 0, invalid("object evidence owner mapping")
	}
	proof, err := decodeObjectEvidenceProof(record.Envelope, receiver)
	if err != nil {
		return nil, 0, 0, err
	}
	now := time.Unix(proof.Proof.IssuedUnix, 0)
	if fresh {
		now = time.Now()
	}
	if _, err = verifyMediaSourceSnapshot(signed, pin, source.Challenge, now); err != nil {
		return nil, 0, 0, invalid("object evidence source expired")
	}
	if err = verifySSHObjectProof(record.Envelope, receiver, pin, signed.Snapshot, record.SourceDigest, media, record.Scope, now); err != nil {
		return nil, 0, 0, err
	}
	if ctx.Err() != nil {
		return nil, 0, 0, ctx.Err()
	}
	if fresh && time.Now().Unix() >= proof.Proof.ExpiresUnix {
		return nil, 0, 0, invalid("object evidence expired")
	}
	return rows, proof.Proof.ExpiresUnix, signed.Snapshot.ExpiresUnix, nil
}
func objectEvidenceExpired(now time.Time, proofExpiry, sourceExpiry int64) bool {
	return now.Unix() >= proofExpiry || now.Unix() >= sourceExpiry
}

// saveObjectEvidence authenticates outside SQL snapshots and owner leases. It
// then holds the acquired guard only during exact ciphertext comparison and a
// WAL read-to-write CAS. A conflicting commit fails rather than skipping recheck.
func saveObjectEvidence(ctx context.Context, db *sql.DB, root []byte, receiver *ecdh.PrivateKey, pin sourceAuthorityPin, source sourceEvidenceRef, objectID string, scope objectProofScope, envelope store.EncryptedMediaSourceSnapshot, budget objectEvidenceDiskBudget, acquire objectEvidenceAcquire) (objectEvidenceRef, error) {
	var empty objectEvidenceRef
	if db == nil || acquire == nil || !budget.valid() {
		return empty, invalid("object evidence input")
	}
	ctx, done, err := enterObjectEvidence(ctx)
	if err != nil {
		return empty, err
	}
	defer done()
	record := objectEvidenceRecord{Version: 1, SourceDigest: source.Digest, ObjectID: objectID, Scope: scope, Envelope: envelope}
	rows, expiry, sourceExpiry, err := prepareObjectEvidence(ctx, db, root, receiver, pin, record, true)
	if err != nil {
		return empty, err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return empty, err
	}
	defer clear(raw)
	digest := sha256.Sum256(raw)
	ref := objectEvidenceRef{Digest: hex.EncodeToString(digest[:])}
	tag, err := objectEvidenceTag(root, ref.Digest)
	if err != nil {
		return empty, err
	}
	key, err := objectEvidenceKey(root, pin.TargetNode)
	if err != nil {
		return empty, err
	}
	defer clear(key)
	lease, err := acquireObjectEvidenceLease(ctx, acquire)
	if err != nil {
		return empty, err
	}
	defer lease.Release()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err = requireSyntheticJournalDurability(ctx, tx); err != nil {
		return empty, err
	}
	if err = objectEvidenceConstraints(ctx, tx); err != nil {
		return empty, err
	}
	if err = requireSourceEvidenceVaultIdentity(ctx, tx, root, pin.TargetNode); err != nil {
		return empty, err
	}
	// Promote the short transaction to a writer before checking available disk
	// and comparing the source rows. Rollback leaves even a matched row intact.
	if _, err = tx.ExecContext(ctx, "UPDATE preprod_object_evidence SET cipher=cipher WHERE evidence_tag=?", tag); err != nil {
		return empty, err
	}
	// Bounds cover this candidate's padded row and index/page churn; it is a
	// preflight estimate rather than a reservation against unrelated writers.
	estimated := int64(8*1024*1024 + 4*(len(raw)+4096))
	if err = checkObjectEvidenceDiskBudget(ctx, tx, budget, estimated); err != nil {
		return empty, err
	}
	if err = checkObjectSourceRows(ctx, tx, root, rows); err != nil {
		return empty, err
	}
	var salt, nonce, cipher []byte
	var challengeTag string
	want := vaultTag(root, "object-evidence-challenge", scope.Challenge)
	var evidenceSize int64
	sizeErr := tx.QueryRowContext(ctx, "SELECT length(cipher) FROM preprod_object_evidence WHERE evidence_tag=?", tag).Scan(&evidenceSize)
	if sizeErr == nil && (evidenceSize < 4096+16 || evidenceSize > objectEvidenceMaxObjectCipherBytes) {
		return empty, invalid("object evidence size")
	}
	if sizeErr != nil && !errors.Is(sizeErr, sql.ErrNoRows) {
		return empty, sizeErr
	}
	err = tx.QueryRowContext(ctx, "SELECT salt,nonce,cipher,challenge_tag FROM preprod_object_evidence WHERE evidence_tag=?", tag).Scan(&salt, &nonce, &cipher, &challengeTag)
	if err == nil {
		old, e := openSourceEvidence(key, tag, salt, nonce, cipher)
		if e != nil {
			return empty, e
		}
		same := bytes.Equal(old, raw)
		clear(old)
		if !same || challengeTag != want {
			return empty, invalid("object evidence conflict")
		}
		result, e := tx.ExecContext(ctx, "UPDATE preprod_object_evidence SET cipher=cipher WHERE evidence_tag=?", tag)
		if e != nil {
			return empty, e
		}
		n, e := result.RowsAffected()
		if e != nil || n != 1 {
			return empty, invalid("object evidence retry")
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		salt, nonce, cipher, err = sealSourceEvidence(key, tag, raw)
		if err != nil {
			return empty, err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO preprod_object_evidence(evidence_tag,salt,nonce,cipher,challenge_tag) VALUES(?,?,?,?,?)", tag, salt, nonce, cipher, want); err != nil {
			return empty, err
		}
	} else {
		return empty, err
	}
	if err = checkObjectEvidenceDiskBudget(ctx, tx, budget, estimated); err != nil {
		return empty, err
	}
	if lease.Check(ctx) != nil || objectEvidenceExpired(time.Now(), expiry, sourceExpiry) || ctx.Err() != nil {
		return empty, invalid("object evidence expired")
	}
	if err = tx.Commit(); err != nil {
		return empty, err
	}
	return ref, nil
}

// recoverObjectEvidence verifies the original signed observations outside SQL
// snapshots, then compares the exact ciphertext rows under a short lease. It
// returns only historical status and never a current publication permission.
func recoverObjectEvidence(ctx context.Context, db *sql.DB, root []byte, receiver *ecdh.PrivateKey, pin sourceAuthorityPin, ref objectEvidenceRef, acquire objectEvidenceAcquire) (bool, error) {
	if db == nil || acquire == nil {
		return false, invalid("object evidence recovery")
	}
	ctx, done, err := enterObjectEvidence(ctx)
	if err != nil {
		return false, err
	}
	defer done()
	tag, err := objectEvidenceTag(root, ref.Digest)
	if err != nil {
		return false, err
	}
	key, err := objectEvidenceKey(root, pin.TargetNode)
	if err != nil {
		return false, err
	}
	defer clear(key)
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return false, err
	}
	if err = objectEvidenceConstraints(ctx, tx); err != nil {
		tx.Rollback()
		return false, err
	}
	var salt, nonce, cipher []byte
	var challengeTag string
	var evidenceSize int64
	if tx.QueryRowContext(ctx, "SELECT length(cipher) FROM preprod_object_evidence WHERE evidence_tag=?", tag).Scan(&evidenceSize) != nil || evidenceSize < 4096+16 || evidenceSize > objectEvidenceMaxObjectCipherBytes {
		tx.Rollback()
		return false, invalid("object evidence size")
	}
	err = tx.QueryRowContext(ctx, "SELECT salt,nonce,cipher,challenge_tag FROM preprod_object_evidence WHERE evidence_tag=?", tag).Scan(&salt, &nonce, &cipher, &challengeTag)
	if err != nil {
		tx.Rollback()
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	raw, err := openSourceEvidence(key, tag, salt, nonce, cipher)
	if err != nil {
		return false, err
	}
	defer clear(raw)
	var record objectEvidenceRecord
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&record) != nil || d.Decode(new(any)) != io.EOF || challengeTag != vaultTag(root, "object-evidence-challenge", record.Scope.Challenge) {
		return false, invalid("object evidence binding")
	}
	sum := sha256.Sum256(raw)
	if ref.Digest != hex.EncodeToString(sum[:]) {
		return false, invalid("object evidence digest")
	}
	rows, _, _, err := prepareObjectEvidence(ctx, db, root, receiver, pin, record, false)
	if err != nil {
		return false, err
	}
	lease, err := acquireObjectEvidenceLease(ctx, acquire)
	if err != nil {
		return false, err
	}
	defer lease.Release()
	tx, err = db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err = checkObjectSourceRows(ctx, tx, root, rows); err != nil {
		return false, err
	}
	var s2, n2, c2 []byte
	var ct2 string
	var finalSize int64
	if tx.QueryRowContext(ctx, "SELECT length(cipher) FROM preprod_object_evidence WHERE evidence_tag=?", tag).Scan(&finalSize) != nil || finalSize != evidenceSize {
		return false, invalid("object evidence changed")
	}
	if tx.QueryRowContext(ctx, "SELECT salt,nonce,cipher,challenge_tag FROM preprod_object_evidence WHERE evidence_tag=?", tag).Scan(&s2, &n2, &c2, &ct2) != nil || !bytes.Equal(s2, salt) || !bytes.Equal(n2, nonce) || !bytes.Equal(c2, cipher) || ct2 != challengeTag || lease.Check(ctx) != nil || ctx.Err() != nil {
		return false, invalid("object evidence changed")
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}
