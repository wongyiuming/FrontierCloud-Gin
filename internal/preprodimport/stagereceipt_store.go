package preprodimport

// Synthetic-only durable receipt evidence. This does not authorize a tree
// publish, authenticate source snapshots, or supply rollback protection.
import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"time"
)

type stageEvidence struct {
	Version      int                           `json:"version"`
	AcceptedUnix int64                         `json:"accepted_unix"`
	Receipts     map[string]signedStageReceipt `json:"receipts"`
}

func stageEvidenceTag(root []byte, requests map[string]stageReceiptRequest) (string, error) {
	if len(root) != 32 || bytes.Equal(root, make([]byte, 32)) {
		return "", invalid("stage evidence root")
	}
	m, ok := requests["master"]
	if !ok || !validStageReceiptRequest(m) {
		return "", invalid("stage evidence binding")
	}
	return vaultTag(root, "stage-evidence", m.Generation+":"+m.PlanDigest), nil
}

func requireStageEvidenceConstraints(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT l."unique",l.partial,(SELECT group_concat(i.name, ',') FROM pragma_index_info(l.name) i) FROM pragma_index_list('preprod_stage_evidence') l`)
	if err != nil {
		return invalid("stage evidence constraints")
	}
	defer rows.Close()
	found := map[string]bool{}
	for rows.Next() {
		var unique, partial int
		var cols sql.NullString
		if rows.Scan(&unique, &partial, &cols) != nil {
			return invalid("stage evidence constraints")
		}
		if unique == 1 && partial == 0 && cols.Valid {
			found[cols.String] = true
		}
	}
	if rows.Err() != nil || !found["evidence_tag"] || !found["salt"] {
		return invalid("stage evidence constraints")
	}
	return nil
}

func sealStageEvidence(root []byte, tag string, raw []byte) ([]byte, []byte, []byte, error) {
	if len(raw) == 0 || len(raw) > maxSnapshotEvidenceBytes {
		return nil, nil, nil, invalid("stage evidence size")
	}
	salt, nonce := make([]byte, 32), make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, nil, err
	}
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, err
	}
	key := requestMAC(root, "stage-evidence-encryption", salt)
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

func openStageEvidence(root []byte, tag string, salt, nonce, ciphertext []byte) ([]byte, error) {
	if len(root) != 32 || bytes.Equal(root, make([]byte, 32)) || !id64.MatchString(tag) || len(salt) != 32 || len(nonce) != 12 || len(ciphertext) < 4096+16 || len(ciphertext) > maxSnapshotEvidenceBytes+4096+16 {
		return nil, invalid("stage evidence row")
	}
	key := requestMAC(root, "stage-evidence-encryption", salt)
	defer clear(key)
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, ciphertext, []byte(tag))
	if err != nil {
		return nil, invalid("stage evidence authentication")
	}
	defer clear(plain)
	if len(plain)%4096 != 0 {
		return nil, invalid("stage evidence padding")
	}
	n := int(binary.BigEndian.Uint32(plain[:4]))
	if n <= 0 || n > len(plain)-4 || n > maxSnapshotEvidenceBytes {
		return nil, invalid("stage evidence length")
	}
	for _, v := range plain[n+4:] {
		if v != 0 {
			return nil, invalid("stage evidence padding")
		}
	}
	return append([]byte(nil), plain[4:n+4]...), nil
}

// saveStageEvidence persists an already pinned and complete set only once.
// Table and unique constraints must already exist; no schema is created here.
func saveStageEvidence(ctx context.Context, db *sql.DB, root []byte, expected map[string]stageReceiptRequest, receipts map[string]signedStageReceipt, pins map[string]ed25519.PublicKey, now time.Time) error {
	if ctx == nil || db == nil {
		return invalid("stage evidence input")
	}
	if err := verifyCompleteStageReceipts(expected, receipts, pins, now); err != nil {
		return err
	}
	tag, err := stageEvidenceTag(root, expected)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(stageEvidence{Version: 1, AcceptedUnix: now.Unix(), Receipts: receipts})
	if err != nil {
		return err
	}
	defer clear(raw)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = requireStageEvidenceConstraints(ctx, tx); err != nil {
		return err
	}
	var salt, nonce, ciphertext []byte
	err = tx.QueryRowContext(ctx, "SELECT salt,nonce,cipher FROM preprod_stage_evidence WHERE evidence_tag=?", tag).Scan(&salt, &nonce, &ciphertext)
	if err == nil {
		plain, e := openStageEvidence(root, tag, salt, nonce, ciphertext)
		if e != nil {
			return e
		}
		defer clear(plain)
		var old stageEvidence
		if json.Unmarshal(plain, &old) != nil || old.Version != 1 || old.AcceptedUnix <= 0 {
			return invalid("stage evidence contents")
		}
		if e = verifyCompleteStageReceipts(expected, old.Receipts, pins, time.Unix(old.AcceptedUnix, 0)); e != nil {
			return e
		}
		oldRaw, e := json.Marshal(old.Receipts)
		if e != nil {
			return e
		}
		defer clear(oldRaw)
		newRaw, e := json.Marshal(receipts)
		if e != nil {
			return e
		}
		defer clear(newRaw)
		if subtle.ConstantTimeCompare(oldRaw, newRaw) != 1 {
			return invalid("stage evidence changed")
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		salt, nonce, ciphertext, err = sealStageEvidence(root, tag, raw)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO preprod_stage_evidence(evidence_tag,salt,nonce,cipher) VALUES(?,?,?,?)", tag, salt, nonce, ciphertext); err != nil {
			return err
		}
	} else {
		return err
	}
	return tx.Commit()
}

// loadStageEvidence verifies signatures at a locally claimed acceptance time.
// Without an external timestamp and rollback anchor this does not establish
// when acceptance actually occurred. It cannot authorize a publish or renew
// an expired authorization.
func loadStageEvidence(ctx context.Context, db *sql.DB, root []byte, expected map[string]stageReceiptRequest, pins map[string]ed25519.PublicKey) (stageEvidence, error) {
	var out stageEvidence
	if ctx == nil || db == nil {
		return out, invalid("stage evidence input")
	}
	tag, err := stageEvidenceTag(root, expected)
	if err != nil {
		return out, err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if err = requireStageEvidenceConstraints(ctx, tx); err != nil {
		return out, err
	}
	var salt, nonce, ciphertext []byte
	if err = tx.QueryRowContext(ctx, "SELECT salt,nonce,cipher FROM preprod_stage_evidence WHERE evidence_tag=?", tag).Scan(&salt, &nonce, &ciphertext); err != nil {
		return out, err
	}
	raw, err := openStageEvidence(root, tag, salt, nonce, ciphertext)
	if err != nil {
		return out, err
	}
	defer clear(raw)
	if json.Unmarshal(raw, &out) != nil || out.Version != 1 || out.AcceptedUnix <= 0 {
		return stageEvidence{}, invalid("stage evidence contents")
	}
	if err = verifyCompleteStageReceipts(expected, out.Receipts, pins, time.Unix(out.AcceptedUnix, 0)); err != nil {
		return stageEvidence{}, err
	}
	if err = tx.Commit(); err != nil {
		return stageEvidence{}, err
	}
	return out, nil
}
