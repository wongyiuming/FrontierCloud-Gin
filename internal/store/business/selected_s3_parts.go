package business

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type selectedS3Part struct {
	OperationID string `json:"op"`
	Number      int    `json:"number"`
	Bytes       int64  `json:"bytes"`
	SHA256      string `json:"sha256"`
	ETag        string `json:"etag,omitempty"`
	Confirmed   bool   `json:"confirmed"`
	GrantUntil  int64  `json:"grant_until"`
	Revision    int64  `json:"revision"`
}

func selectedS3PartIndex(key []byte, operation string, number int) string {
	return hex.EncodeToString(capacityMAC(key, "selected-s3-part-index", []byte(operation+":"+strconv.Itoa(number))))
}

func validSelectedS3Part(part selectedS3Part, intent selectedS3Intent) bool {
	if !validSelectedS3Intent(intent) || part.OperationID != intent.OperationID || part.Number < 1 || part.Number > 1280 || part.Revision < 1 || part.GrantUntil < 0 {
		return false
	}
	count := (intent.Bytes + store.S3PartBytes - 1) / store.S3PartBytes
	if int64(part.Number) > count {
		return false
	}
	size := store.S3PartBytes
	if int64(part.Number) == count {
		size = intent.Bytes - (count-1)*store.S3PartBytes
	}
	if part.Bytes != size {
		return false
	}
	digest, err := base64.StdEncoding.Strict().DecodeString(part.SHA256)
	if err != nil || len(digest) != 32 || base64.StdEncoding.EncodeToString(digest) != part.SHA256 {
		return false
	}
	if !part.Confirmed {
		return part.ETag == ""
	}
	if len(part.ETag) < 3 || len(part.ETag) > 512 || part.ETag[0] != '"' || part.ETag[len(part.ETag)-1] != '"' {
		return false
	}
	for _, ch := range part.ETag[1 : len(part.ETag)-1] {
		if ch < 33 || ch > 126 || ch == '"' {
			return false
		}
	}
	return true
}

// precommitSelectedS3PartsTx runs in the original reservation transaction.
// No part URL may exist until the complete ordered manifest is durable.
func (r *Repository) precommitSelectedS3PartsTx(ctx context.Context, q queryer, key []byte, intent selectedS3Intent, hashes []string) error {
	commitment, err := selectedS3Commitment(intent.Bytes, hashes)
	if err != nil || commitment != intent.PartCommitment || intent.Phase != "reserved" || intent.State != "pending" {
		return store.ErrNodeState
	}
	for i, checksum := range hashes {
		size := store.S3PartBytes
		if i == len(hashes)-1 {
			size = intent.Bytes - int64(i)*store.S3PartBytes
		}
		part := selectedS3Part{OperationID: intent.OperationID, Number: i + 1, Bytes: size, SHA256: checksum, Revision: 1}
		if !validSelectedS3Part(part, intent) {
			return store.ErrNodeState
		}
		index := selectedS3PartIndex(key, intent.OperationID, part.Number)
		raw, e := json.Marshal(part)
		if e != nil {
			return e
		}
		id, sealed, e := sealCapacityRecord(key, index, raw)
		clear(raw)
		if e != nil {
			return e
		}
		if _, e = q.ExecContext(ctx, `INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)`, id); e != nil {
			return store.ErrNodeState
		}
		if _, e = q.ExecContext(ctx, `INSERT INTO selected_s3_parts(operation_index,part_index,encryption_id,sealed) VALUES(?,?,?,?)`, opaqueCapacityIndex(key, intent.OperationID), index, id, sealed); e != nil {
			return store.ErrNodeState
		}
	}
	return ctx.Err()
}

func (r *Repository) readSelectedS3PartTx(ctx context.Context, q queryer, key []byte, intent selectedS3Intent, number int) (selectedS3Part, bool, error) {
	var value selectedS3Part
	if ctx == nil || q == nil || !validCapacityKey(key) || !validSelectedS3Intent(intent) || number < 1 || number > 1280 {
		return value, false, store.ErrNodeState
	}
	index := selectedS3PartIndex(key, intent.OperationID, number)
	var encryptionID string
	var sealed []byte
	err := q.QueryRowContext(ctx, `SELECT encryption_id,sealed FROM selected_s3_parts WHERE operation_index=? AND part_index=?`+r.lock(), opaqueCapacityIndex(key, intent.OperationID), index).Scan(&encryptionID, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return value, false, nil
	}
	if err != nil || !capacityIDExists(ctx, q, encryptionID, r.lock()) {
		return value, false, store.ErrNodeState
	}
	raw, err := openCapacityRecord(key, index, encryptionID, sealed)
	if err != nil {
		return value, false, store.ErrNodeState
	}
	defer clear(raw)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&value) != nil || dec.Decode(new(any)) != io.EOF || value.Number != number || !validSelectedS3Part(value, intent) {
		return selectedS3Part{}, false, store.ErrNodeState
	}
	return value, true, nil
}

// writeSelectedS3PartTx is a database-only operation. The caller's check must
// authenticate the selected reservation/member revision and, for confirmation,
// the provider observation; it must run under the same fences and transaction.
func (r *Repository) writeSelectedS3PartTx(ctx context.Context, q queryer, key []byte, intent selectedS3Intent, part selectedS3Part, check func(context.Context, queryer, selectedS3Part, bool) error) (bool, error) {
	if check == nil || intent.State != "pending" || intent.Phase != "uploading" || !validSelectedS3Part(part, intent) {
		return false, store.ErrNodeState
	}
	current, found, err := r.readSelectedS3IntentTx(ctx, q, key, intent.OperationID)
	if err != nil || !found || current != intent {
		return false, store.ErrNodeState
	}
	old, found, err := r.readSelectedS3PartTx(ctx, q, key, intent, part.Number)
	if err != nil {
		return false, err
	}
	if found {
		if old == part {
			if err = check(ctx, q, old, true); err != nil {
				return false, err
			}
			return true, nil
		}
		if old.Confirmed || part.Revision != old.Revision+1 || part.OperationID != old.OperationID || part.Number != old.Number || part.Bytes != old.Bytes || part.SHA256 != old.SHA256 || part.GrantUntil < old.GrantUntil {
			return false, store.ErrNodeState
		}
	} else {
		// Grants and confirmations may only update an originally committed part.
		return false, store.ErrNodeState
	}
	if err = check(ctx, q, old, found); err != nil {
		return false, err
	}
	index := selectedS3PartIndex(key, intent.OperationID, part.Number)
	raw, err := json.Marshal(part)
	if err != nil {
		return false, store.ErrNodeState
	}
	defer clear(raw)
	encryptionID, sealed, err := sealCapacityRecord(key, index, raw)
	if err != nil {
		return false, err
	}
	if _, err = q.ExecContext(ctx, `INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)`, encryptionID); err != nil {
		return false, store.ErrNodeState
	}
	var result sql.Result
	if found {
		var prior string
		if err = q.QueryRowContext(ctx, `SELECT encryption_id FROM selected_s3_parts WHERE operation_index=? AND part_index=?`+r.lock(), opaqueCapacityIndex(key, intent.OperationID), index).Scan(&prior); err != nil {
			return false, store.ErrNodeState
		}
		result, err = q.ExecContext(ctx, `UPDATE selected_s3_parts SET encryption_id=?,sealed=? WHERE operation_index=? AND part_index=? AND encryption_id=?`, encryptionID, sealed, opaqueCapacityIndex(key, intent.OperationID), index, prior)
	} else {
		result, err = q.ExecContext(ctx, `INSERT INTO selected_s3_parts(operation_index,part_index,encryption_id,sealed) VALUES(?,?,?,?)`, opaqueCapacityIndex(key, intent.OperationID), index, encryptionID, sealed)
	}
	if err != nil {
		return false, store.ErrNodeState
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return false, store.ErrNodeState
	}
	return false, nil
}

// completeSelectedS3PartsTx rejects missing, extra, unconfirmed or substituted
// rows. It does not contact the provider or publish an object.
func (r *Repository) completeSelectedS3PartsTx(ctx context.Context, q queryer, key []byte, intent selectedS3Intent) ([]store.S3Part, error) {
	if !validSelectedS3Intent(intent) || intent.State != "pending" || intent.Phase != "completing" {
		return nil, store.ErrNodeState
	}
	parts, err := r.listSelectedS3PartsTx(ctx, q, key, intent, true)
	if err != nil {
		return nil, err
	}
	hashes := make([]string, len(parts))
	for i, part := range parts {
		hashes[i] = part.SHA256
	}
	commitment, err := selectedS3Commitment(intent.Bytes, hashes)
	if err != nil || commitment != intent.PartCommitment {
		return nil, store.ErrNodeState
	}
	return parts, nil
}

func (r *Repository) listSelectedS3PartsTx(ctx context.Context, q queryer, key []byte, intent selectedS3Intent, complete bool) ([]store.S3Part, error) {
	if !validSelectedS3Intent(intent) || intent.State != "pending" {
		return nil, store.ErrNodeState
	}
	current, found, err := r.readSelectedS3IntentTx(ctx, q, key, intent.OperationID)
	if err != nil || !found || current != intent {
		return nil, store.ErrNodeState
	}
	count := int((intent.Bytes + store.S3PartBytes - 1) / store.S3PartBytes)
	rows, err := q.QueryContext(ctx, `SELECT p.part_index,p.encryption_id,p.sealed,CASE WHEN n.encryption_id IS NULL THEN 0 ELSE 1 END FROM selected_s3_parts p LEFT JOIN sealed_tree_capacity_ids n ON n.encryption_id=p.encryption_id WHERE p.operation_index=?`, opaqueCapacityIndex(key, intent.OperationID))
	if err != nil {
		return nil, store.ErrNodeState
	}
	defer rows.Close()
	parts := make([]store.S3Part, count)
	seen := 0
	for rows.Next() {
		var index, encryptionID string
		var sealed []byte
		var reserved int
		if rows.Scan(&index, &encryptionID, &sealed, &reserved) != nil || reserved != 1 || seen >= count {
			return nil, store.ErrNodeState
		}
		raw, err := openCapacityRecord(key, index, encryptionID, sealed)
		if err != nil {
			return nil, store.ErrNodeState
		}
		var part selectedS3Part
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		valid := dec.Decode(&part) == nil && dec.Decode(new(any)) == io.EOF && validSelectedS3Part(part, intent) && (!complete || part.Confirmed) && index == selectedS3PartIndex(key, intent.OperationID, part.Number)
		clear(raw)
		if !valid || parts[part.Number-1].Number != 0 {
			return nil, store.ErrNodeState
		}
		parts[part.Number-1] = store.S3Part{Number: part.Number, Bytes: part.Bytes, SHA256: part.SHA256, ETag: part.ETag, Confirmed: part.Confirmed, GrantUntil: part.GrantUntil}
		seen++
	}
	if err = rows.Err(); err != nil || complete && seen != count {
		return nil, store.ErrNodeState
	}
	if !complete {
		present := make([]store.S3Part, 0, seen)
		for _, part := range parts {
			if part.Number != 0 {
				present = append(present, part)
			}
		}
		return present, nil
	}
	return parts, nil
}
