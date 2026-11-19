package sealedtree

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const lyricAuditChunk = 32768

type LyricAuditChange struct {
	Track string `json:"track"`
	Lyric string `json:"lyric"`
}
type lyricAuditPayload struct {
	Origin    string             `json:"origin"`
	Targets   []string           `json:"targets"`
	Changes   []LyricAuditChange `json:"changes"`
	Relations int                `json:"relations"`
	At        string             `json:"at"`
	Audit     store.AdminAudit   `json:"audit"`
}

// Each row is one encrypted fragment of a single logical operation. Existing
// TEXT columns and the transaction are reused; no plaintext names reach SQL.
func (s *SQLStore) appendEncryptedLyricAudit(ctx context.Context, tx treeQuery, operation string, payload lyricAuditPayload) error {
	if handled, e := s.archiveLyricAudit(ctx, tx, operation, payload); handled {
		return e
	}
	raw, err := json.Marshal(payload)
	if err != nil || len(raw) == 0 {
		return ErrInvalid
	}
	defer clear(raw)
	digest := s.listingMAC("lyric-audit-content-v2", string(raw))
	total := (len(raw)-1)/(lyricAuditChunk-2) + 1
	for i := 0; i < total; i++ {
		if err = ctx.Err(); err != nil {
			return err
		}
		start := i * (lyricAuditChunk - 2)
		end := start + lyricAuditChunk - 2
		if end > len(raw) {
			end = len(raw)
		}
		plain := make([]byte, lyricAuditChunk)
		binary.BigEndian.PutUint16(plain[:2], uint16(end-start))
		copy(plain[2:], raw[start:end])
		random := make([]byte, recordSaltBytes+nonceBytes)
		if _, err = io.ReadFull(rand.Reader, random); err != nil {
			clear(plain)
			return ErrInvalid
		}
		if _, err = reserveID(ctx, tx, hex.EncodeToString(random[:recordSaltBytes])); err != nil {
			clear(plain)
			return err
		}
		aead, e := s.tree.recordCipher(random[:recordSaltBytes], "audit")
		if e != nil {
			clear(plain)
			return e
		}
		header := "sealed-tree-audit-v2:" + operation + ":" + strconv.Itoa(i) + ":" + strconv.Itoa(total) + ":" + digest
		sealed := append([]byte{1}, random...)
		sealed = aead.Seal(sealed, random[recordSaltBytes:], plain, []byte(header))
		clear(plain)
		detail := header + ":" + base64.RawStdEncoding.EncodeToString(sealed)
		count := 0
		if i == 0 {
			count = payload.Audit.TargetCount
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO admin_audit_log (session_id_hash,action,target_count,source_summary,result,detail,client_ip,user_agent,request_id,trace_id,created_at) VALUES (NULL,'lyric_relations',?,NULL,'success',?,NULL,NULL,NULL,NULL,?)`, count, detail, payload.At); err != nil {
			return err
		}
	}
	return nil
}

// LyricAudit is sensitive Master-only audit data. User authorization and the
// ordinary audit UI/backup integration remain separate product gates.
type LyricAudit struct {
	Origin    string
	Targets   []string
	Changes   []LyricAuditChange
	Relations int
	At        string
	Audit     store.AdminAudit
}

// ReadEncryptedLyricAudit reassembles the complete authenticated fragment
// set from a single DB snapshot; missing, duplicate, reordered, substituted
// or modified fragments fail closed. It is not an authorization check.
func (s *SQLStore) ReadEncryptedLyricAudit(ctx context.Context, operation string) (LyricAudit, error) {
	var empty LyricAudit
	if !s.valid() || ctx == nil || !hexID(operation) {
		return empty, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err = s.verifyRoot(ctx, tx); err != nil {
		return empty, err
	}
	prefix := "sealed-tree-audit-v2:" + operation + ":"
	rows, err := tx.QueryContext(ctx, `SELECT detail,target_count,action,result,CAST(created_at AS CHAR) FROM admin_audit_log WHERE action='lyric_relations' AND detail LIKE ?`, prefix+"%")
	if err != nil {
		return empty, err
	}
	type piece struct {
		data  []byte
		count int
		at    string
	}
	parts := map[int]piece{}
	defer func() {
		for _, part := range parts {
			clear(part.data)
		}
	}()
	ids := map[string]bool{}
	total := -1
	digest := ""
	for rows.Next() {
		var detail, action, result, at string
		var count int
		if rows.Scan(&detail, &count, &action, &result, &at) != nil || action != "lyric_relations" || result != "success" {
			rows.Close()
			return empty, ErrInvalid
		}
		fields := strings.Split(detail, ":")
		if len(fields) != 6 || fields[0] != "sealed-tree-audit-v2" || fields[1] != operation || !hexID(fields[4]) {
			rows.Close()
			return empty, ErrInvalid
		}
		index, e := strconv.Atoi(fields[2])
		n, e2 := strconv.Atoi(fields[3])
		if e != nil || e2 != nil || index < 0 || n < 1 || index >= n || strconv.Itoa(index) != fields[2] || strconv.Itoa(n) != fields[3] || total != -1 && total != n || digest != "" && digest != fields[4] {
			rows.Close()
			return empty, ErrInvalid
		}
		total, digest = n, fields[4]
		if _, exists := parts[index]; exists {
			rows.Close()
			return empty, ErrInvalid
		}
		sealed, e := base64.RawStdEncoding.Strict().DecodeString(fields[5])
		if e != nil || len(sealed) != 1+recordSaltBytes+nonceBytes+lyricAuditChunk+16 || sealed[0] != 1 {
			rows.Close()
			return empty, ErrInvalid
		}
		id := hex.EncodeToString(sealed[1 : 1+recordSaltBytes])
		if ids[id] {
			rows.Close()
			return empty, ErrInvalid
		}
		ids[id] = true
		aead, e := s.tree.recordCipher(sealed[1:1+recordSaltBytes], "audit")
		if e != nil {
			rows.Close()
			return empty, ErrInvalid
		}
		header := strings.Join(fields[:5], ":")
		plain, e := aead.Open(nil, sealed[1+recordSaltBytes:1+recordSaltBytes+nonceBytes], sealed[1+recordSaltBytes+nonceBytes:], []byte(header))
		if e != nil {
			rows.Close()
			return empty, ErrInvalid
		}
		length := int(binary.BigEndian.Uint16(plain[:2]))
		if length < 1 || length > lyricAuditChunk-2 {
			clear(plain)
			rows.Close()
			return empty, ErrInvalid
		}
		for _, b := range plain[2+length:] {
			if b != 0 {
				clear(plain)
				rows.Close()
				return empty, ErrInvalid
			}
		}
		parts[index] = piece{data: append([]byte(nil), plain[2:2+length]...), count: count, at: at}
		clear(plain)
	}
	rowsErr, closeErr := rows.Err(), rows.Close()
	if rowsErr != nil || closeErr != nil || total < 1 || len(parts) != total {
		return empty, ErrInvalid
	}
	for id := range ids {
		var reserved int
		if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_encryption_ids WHERE encryption_id=?`, id).Scan(&reserved) != nil || reserved != 1 {
			return empty, ErrInvalid
		}
	}
	var raw []byte
	for i := 0; i < total; i++ {
		part, ok := parts[i]
		if !ok || i > 0 && part.count != 0 {
			return empty, ErrInvalid
		}
		raw = append(raw, part.data...)
	}
	defer clear(raw)
	if !hmac.Equal([]byte(digest), []byte(s.listingMAC("lyric-audit-content-v2", string(raw)))) {
		return empty, ErrInvalid
	}
	var value lyricAuditPayload
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil {
		return empty, ErrInvalid
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || value.Audit.TargetCount != len(value.Targets)+1 || parts[0].count != value.Audit.TargetCount || value.Relations < 0 || value.At == "" {
		return empty, ErrInvalid
	}
	for _, part := range parts {
		if part.at != value.At {
			return empty, ErrInvalid
		}
	}
	if err = tx.Commit(); err != nil {
		return empty, err
	}
	return LyricAudit{Origin: value.Origin, Targets: value.Targets, Changes: value.Changes, Relations: value.Relations, At: value.At, Audit: value.Audit}, nil
}
