//go:build linux && ledger_fixture

package preprodimport

// Isolated synthetic SQLite experiment only. No product entry point uses this
// code. A test callback is NOT proof of maintenance, source connection inode,
// ownership, anti-rollback, schema compatibility or a 30-second production SLA.
import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"os"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

type fixtureRowSpec struct {
	name, table, key, condition string
	columns                     []string
}

var fixtureRowSpecs = []fixtureRowSpec{
	{"objects", "media_objects", "media_id", "", []string{"media_id", "object_kind", "media_path", "path_locator", "created_at", "updated_at"}},
	{"placements", "global_media_objects", "media_id", "", []string{"media_id", "storage_member_id", "object_id", "media_path", "object_kind", "size_bytes", "etag", "state", "created_at", "updated_at"}},
	{"visibility", "media_visibility", "relative_path", "", []string{"relative_path", "hidden", "updated_at"}},
	{"playback", "media_playback_stats", "media_id", "", []string{"media_id", "media_path", "preference", "play_score", "created_at", "updated_at"}},
	{"lyric_links", "media_lyric_links", "media_id", "", []string{"media_id", "media_path", "lyric_id", "lyric_path", "created_at", "updated_at"}},
	{"encryption", "media_encryption", "object_id", "object_kind='media'", []string{"object_kind", "object_id", "file_id", "descriptor_json", "created_at"}},
	{"members", "cluster_storage_members", "member_id", "", []string{"member_id", "relationship_id", "member_kind", "transport", "storage_enabled", "allocated_bytes", "used_bytes", "reserved_bytes", "physical_free_bytes", "health", "writable", "updated_at"}},
	{"relationships", "node_relationships", "relationship_id", "", []string{"relationship_id", "peer_id", "peer_endpoint", "peer_key", "direction", "mode", "state", "created_at"}},
	{"crypto_key_id", "media_crypto_keys", "singleton", "", []string{"singleton", "key_id", "created_at"}},
}

type fixtureSectionSummary struct {
	Name   string `json:"name"`
	Rows   int64  `json:"rows"`
	SHA256 string `json:"sha256"`
}
type fixtureStreamManifest struct {
	Version          int                     `json:"version"`
	Source           string                  `json:"source"`
	Target           string                  `json:"target"`
	Challenge        string                  `json:"challenge"`
	SchemaGeneration int                     `json:"schema_generation"`
	PageSize         int                     `json:"page_size"`
	SnapshotID       string                  `json:"snapshot_id"`
	NoncePrefix      string                  `json:"nonce_prefix"`
	PlainBytes       int64                   `json:"plain_bytes"`
	PlainSHA256      string                  `json:"plain_sha256"`
	CipherSHA256     string                  `json:"cipher_sha256"`
	Sections         []fixtureSectionSummary `json:"sections"`
}
type fixtureSignedStream struct {
	Manifest  fixtureStreamManifest
	Signature []byte
}
type fixtureStreamScope struct {
	Source, Target, Challenge  string
	SchemaGeneration, PageSize int
}
type fixtureStreamResult struct {
	sections []fixtureSectionSummary
	size     int64
	digest   [32]byte
}

// A connection executing BEGIN IMMEDIATE and an sql.Tx both retain one
// physical connection. The caller must establish and maintain that property.
type fixtureRowQuery interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type fixtureHashWriter struct {
	out   io.Writer
	total hash.Hash
	count int64
}

// A duplicate key crossing a LIMIT boundary would otherwise be silently
// skipped by a keyset query. Require an actual, non-partial unique constraint
// matching the fixed query's key (including its fixed encryption kind).
func fixtureRequireUniquePageKey(ctx context.Context, tx fixtureRowQuery, spec fixtureRowSpec) error {
	expected := spec.key
	if spec.name == "encryption" {
		expected = "object_kind,object_id"
	}
	rows, err := tx.QueryContext(ctx, `SELECT name,pk FROM pragma_table_info(?) WHERE pk>0 ORDER BY pk`, spec.table)
	if err != nil {
		return invalid("fixture page key schema")
	}
	var pk []string
	for rows.Next() {
		var name string
		var order int
		if rows.Scan(&name, &order) != nil {
			rows.Close()
			return invalid("fixture page key schema")
		}
		pk = append(pk, name)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return invalid("fixture page key schema")
	}
	if strings.Join(pk, ",") == expected {
		return nil
	}
	rows, err = tx.QueryContext(ctx, `SELECT name FROM pragma_index_list(?) WHERE "unique"=1 AND partial=0`, spec.table)
	if err != nil {
		return invalid("fixture page key schema")
	}
	var indexes []string
	for rows.Next() {
		var name string
		if rows.Scan(&name) != nil {
			rows.Close()
			return invalid("fixture page key schema")
		}
		indexes = append(indexes, name)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return invalid("fixture page key schema")
	}
	for _, index := range indexes {
		rows, err = tx.QueryContext(ctx, `SELECT name FROM pragma_index_info(?) ORDER BY seqno`, index)
		if err != nil {
			return invalid("fixture page key schema")
		}
		var cols []string
		for rows.Next() {
			var name sql.NullString
			if rows.Scan(&name) != nil || !name.Valid {
				rows.Close()
				return invalid("fixture page key schema")
			}
			cols = append(cols, name.String)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return invalid("fixture page key schema")
		}
		if strings.Join(cols, ",") == expected {
			return nil
		}
	}
	return invalid("fixture page key not unique")
}
func (w *fixtureHashWriter) write(frame any, section hash.Hash) error {
	raw, err := json.Marshal(frame)
	if err != nil || len(raw) > 1<<20 {
		return invalid("fixture row frame")
	}
	raw = append(raw, '\n')
	defer clear(raw)
	if _, err = w.total.Write(raw); err != nil {
		return err
	}
	if section != nil {
		if _, err = section.Write(raw); err != nil {
			return err
		}
	}
	if n, e := w.out.Write(raw); e != nil || n != len(raw) {
		return invalid("fixture row stream write")
	}
	w.count += int64(len(raw))
	return nil
}

// fixtureWalkSQLRows emits a deterministic framed stream using fixed schemas,
// binary keyset ordering and LIMIT. At most one row is materialized at a time;
// it fails closed on oversized values, duplicates and unexpected NULLs.
func fixtureWalkSQLRows(ctx context.Context, tx fixtureRowQuery, out io.Writer, pageSize int, check func() error) (fixtureStreamResult, error) {
	var result fixtureStreamResult
	if ctx == nil || tx == nil || out == nil || check == nil || pageSize < 1 || pageSize > 128 {
		return result, invalid("fixture row stream input")
	}
	w := fixtureHashWriter{out: out, total: sha256.New()}
	for _, spec := range fixtureRowSpecs {
		if err := fixtureRequireUniquePageKey(ctx, tx, spec); err != nil {
			return result, err
		}
		section := sha256.New()
		if err := w.write(struct {
			Name    string   `json:"section"`
			Columns []string `json:"columns"`
		}{spec.name, spec.columns}, section); err != nil {
			return result, err
		}
		keyColumn := -1
		bounded := make([]string, len(spec.columns))
		for i, col := range spec.columns {
			bounded[i] = "SUBSTR(" + col + ",1,65537)"
			if col == spec.key {
				keyColumn = i
			}
		}
		if keyColumn < 0 {
			return result, invalid("fixture row stream schema")
		}
		last := ""
		first := true
		var sectionRows int64
		for {
			if ctx.Err() != nil || check() != nil {
				return result, invalid("fixture freeze lost")
			}
			where := spec.condition
			args := []any{}
			if !first {
				if where != "" {
					where += " AND "
				}
				where += spec.key + " COLLATE BINARY > ?"
				args = append(args, last)
			}
			if where != "" {
				where = " WHERE " + where
			}
			query := "SELECT " + strings.Join(bounded, ",") + ",typeof(" + spec.key + ") FROM " + spec.table + where + " ORDER BY " + spec.key + " COLLATE BINARY LIMIT ?"
			args = append(args, pageSize)
			rows, err := tx.QueryContext(ctx, query, args...)
			if err != nil {
				return result, invalid("fixture row query")
			}
			pageRows := 0
			for rows.Next() {
				if ctx.Err() != nil || check() != nil {
					rows.Close()
					return result, invalid("fixture freeze lost")
				}
				values := make([]sql.NullString, len(spec.columns))
				dest := make([]any, len(values)+1)
				var keyType string
				for i := range values {
					dest[i] = &values[i]
				}
				dest[len(values)] = &keyType
				if rows.Scan(dest...) != nil {
					rows.Close()
					return result, invalid("fixture row scan")
				}
				cells := make([]*string, len(values))
				for i, value := range values {
					if !value.Valid {
						if !(spec.name == "encryption" && spec.columns[i] == "descriptor_json") && !(spec.name == "members" && spec.columns[i] == "relationship_id") {
							rows.Close()
							return result, invalid("fixture row null")
						}
						continue
					}
					if len(value.String) > 65536 || !utf8.ValidString(value.String) || strings.ContainsRune(value.String, 0) {
						rows.Close()
						return result, invalid("fixture row value")
					}
					v := value.String
					cells[i] = &v
				}
				if cells[keyColumn] == nil || *cells[keyColumn] == "" || (spec.name == "crypto_key_id" && (keyType != "integer" || *cells[keyColumn] != "1")) || (spec.name != "crypto_key_id" && keyType != "text") || (!first && *cells[keyColumn] <= last) {
					rows.Close()
					return result, invalid("fixture row order")
				}
				last = *cells[keyColumn]
				first = false
				pageRows++
				sectionRows++
				if err = w.write(struct {
					Row []*string `json:"row"`
				}{cells}, section); err != nil {
					rows.Close()
					return result, err
				}
			}
			e := rows.Err()
			rows.Close()
			if e != nil {
				return result, invalid("fixture row scan")
			}
			if pageRows < pageSize {
				break
			}
		}
		if err := w.write(struct {
			End  string `json:"end"`
			Rows int64  `json:"rows"`
		}{spec.name, sectionRows}, section); err != nil {
			return result, err
		}
		result.sections = append(result.sections, fixtureSectionSummary{Name: spec.name, Rows: sectionRows, SHA256: hex.EncodeToString(section.Sum(nil))})
	}
	result.size = w.count
	copy(result.digest[:], w.total.Sum(nil))
	return result, nil
}

func fixtureStreamManifestBytes(m fixtureStreamManifest) ([]byte, error) {
	raw, err := json.Marshal(m)
	if err != nil || len(raw) > 65536 {
		return nil, invalid("fixture stream manifest")
	}
	return raw, nil
}

// fixtureVerifyStreamFrames independently checks the signed stream's exact
// section sequence, schema, canonical row frames, key ordering, row counts and
// section digests. It holds only one bounded row and never writes plaintext.
func fixtureVerifyStreamFrames(ctx context.Context, input io.Reader, size int64, sections []fixtureSectionSummary) error {
	if ctx == nil || input == nil || size <= 0 || len(sections) != len(fixtureRowSpecs) {
		return invalid("fixture stream framing")
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64<<10), (1<<20)+1)
	index := -1
	var rows int64
	var bytesRead int64
	var digest hash.Hash
	var last string
	open := false
	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := scanner.Bytes()
		bytesRead += int64(len(line)) + 1
		var kind map[string]json.RawMessage
		if json.Unmarshal(line, &kind) != nil {
			return invalid("fixture stream frame")
		}
		if _, ok := kind["section"]; ok {
			if open || index+1 >= len(fixtureRowSpecs) {
				return invalid("fixture stream section order")
			}
			index++
			spec := fixtureRowSpecs[index]
			var header struct {
				Name    string   `json:"section"`
				Columns []string `json:"columns"`
			}
			if json.Unmarshal(line, &header) != nil || header.Name != spec.name || !reflect.DeepEqual(header.Columns, spec.columns) {
				return invalid("fixture stream section")
			}
			canonical, e := json.Marshal(header)
			if e != nil || !bytes.Equal(canonical, line) {
				return invalid("fixture stream canonical header")
			}
			digest = sha256.New()
			rows = 0
			last = ""
			open = true
		} else if _, ok := kind["row"]; ok {
			if !open {
				return invalid("fixture stream row order")
			}
			spec := fixtureRowSpecs[index]
			var row struct {
				Row []*string `json:"row"`
			}
			if json.Unmarshal(line, &row) != nil || len(row.Row) != len(spec.columns) {
				return invalid("fixture stream row")
			}
			canonical, e := json.Marshal(row)
			if e != nil || !bytes.Equal(canonical, line) {
				return invalid("fixture stream canonical row")
			}
			key := ""
			for i, value := range row.Row {
				if value == nil {
					if !(spec.name == "encryption" && spec.columns[i] == "descriptor_json") && !(spec.name == "members" && spec.columns[i] == "relationship_id") {
						return invalid("fixture stream row null")
					}
					continue
				}
				if len(*value) > 65536 || !utf8.ValidString(*value) || strings.ContainsRune(*value, 0) {
					return invalid("fixture stream row value")
				}
				if spec.columns[i] == spec.key {
					key = *value
				}
			}
			if key == "" || (rows > 0 && key <= last) || spec.name == "crypto_key_id" && key != "1" {
				return invalid("fixture stream row key")
			}
			last = key
			rows++
		} else if _, ok := kind["end"]; ok {
			if !open {
				return invalid("fixture stream end")
			}
			var end struct {
				End  string `json:"end"`
				Rows int64  `json:"rows"`
			}
			if json.Unmarshal(line, &end) != nil || end.End != fixtureRowSpecs[index].name || end.Rows != rows || rows != sections[index].Rows {
				return invalid("fixture stream count")
			}
			canonical, e := json.Marshal(end)
			if e != nil || !bytes.Equal(canonical, line) {
				return invalid("fixture stream canonical end")
			}
			_, _ = digest.Write(line)
			_, _ = digest.Write([]byte{'\n'})
			if hex.EncodeToString(digest.Sum(nil)) != sections[index].SHA256 {
				return invalid("fixture stream section digest")
			}
			open = false
			continue
		} else {
			return invalid("fixture stream frame kind")
		}
		_, _ = digest.Write(line)
		_, _ = digest.Write([]byte{'\n'})
	}
	if err := scanner.Err(); err != nil {
		return invalid("fixture stream framing")
	}
	if open || index != len(fixtureRowSpecs)-1 || bytesRead != size {
		return invalid("fixture stream incomplete")
	}
	return nil
}

// fixtureCaptureSQLRows never establishes or asserts a real maintenance
// lease. The caller holds the supplied transaction; the two passes use its
// same snapshot. Source identity, frozen writers and commit remain unproven.
func fixtureCaptureSQLRows(ctx context.Context, tx fixtureRowQuery, dst *os.File, signer ed25519.PrivateKey, scope fixtureStreamScope, check func() error, afterFirst func() error) (signed fixtureSignedStream, desc encryptedSnapshotFixtureDescriptor, err error) {
	if ctx == nil || tx == nil || dst == nil || check == nil || len(signer) != ed25519.PrivateKeySize || !id32.MatchString(scope.Source) || !id32.MatchString(scope.Target) || scope.Source == scope.Target || !id64.MatchString(scope.Challenge) || scope.SchemaGeneration < 1 || scope.PageSize < 1 || scope.PageSize > 128 {
		return signed, desc, invalid("fixture stream scope")
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 30*time.Second || check() != nil {
		return signed, desc, invalid("fixture stream deadline")
	}
	info, e := dst.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() != 0 {
		return signed, desc, invalid("fixture stream destination")
	}
	var generation int
	if tx.QueryRowContext(ctx, `SELECT generation FROM frontiercloud_schema WHERE singleton=1`).Scan(&generation) != nil || generation != scope.SchemaGeneration {
		return signed, desc, invalid("fixture stream schema generation")
	}
	first, e := fixtureWalkSQLRows(ctx, tx, io.Discard, scope.PageSize, check)
	if e != nil {
		return signed, desc, e
	}
	if afterFirst != nil && afterFirst() != nil {
		return signed, desc, invalid("fixture stream callback")
	}
	if check() != nil || ctx.Err() != nil {
		return signed, desc, invalid("fixture freeze lost")
	}
	pr, pw := io.Pipe()
	type rowResult struct {
		result fixtureStreamResult
		err    error
	}
	done := make(chan rowResult, 1)
	go func() {
		value, e := fixtureWalkSQLRows(ctx, tx, pw, scope.PageSize, check)
		_ = pw.CloseWithError(e)
		done <- rowResult{value, e}
	}()
	desc, err = captureEncryptedSnapshotFixture(ctx, dst, pr, first.size)
	if err != nil {
		_ = pr.CloseWithError(err)
	} else {
		_ = pr.Close()
	}
	second := <-done
	if err != nil || second.err != nil || second.result.size != first.size || second.result.digest != first.digest || desc.plainSHA != first.digest || !reflect.DeepEqual(second.result.sections, first.sections) || ctx.Err() != nil || check() != nil {
		clear(desc.key[:])
		return fixtureSignedStream{}, encryptedSnapshotFixtureDescriptor{}, invalid("fixture stream changed")
	}
	if tx.QueryRowContext(ctx, `SELECT generation FROM frontiercloud_schema WHERE singleton=1`).Scan(&generation) != nil || generation != scope.SchemaGeneration || dst.Sync() != nil {
		clear(desc.key[:])
		return fixtureSignedStream{}, encryptedSnapshotFixtureDescriptor{}, invalid("fixture stream final state")
	}
	info, e = dst.Stat()
	if e != nil || info.Size() <= 0 {
		clear(desc.key[:])
		return fixtureSignedStream{}, encryptedSnapshotFixtureDescriptor{}, invalid("fixture stream file")
	}
	h := sha256.New()
	encrypted := io.NewSectionReader(dst, 0, info.Size())
	hashBuffer := make([]byte, 64<<10)
	for {
		if ctx.Err() != nil || check() != nil {
			clear(hashBuffer)
			clear(desc.key[:])
			return fixtureSignedStream{}, encryptedSnapshotFixtureDescriptor{}, invalid("fixture freeze lost")
		}
		n, readErr := encrypted.Read(hashBuffer)
		if n > 0 {
			_, _ = h.Write(hashBuffer[:n])
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			clear(hashBuffer)
			clear(desc.key[:])
			return fixtureSignedStream{}, encryptedSnapshotFixtureDescriptor{}, readErr
		}
	}
	clear(hashBuffer)
	m := fixtureStreamManifest{Version: 1, Source: scope.Source, Target: scope.Target, Challenge: scope.Challenge, SchemaGeneration: scope.SchemaGeneration, PageSize: scope.PageSize, SnapshotID: hex.EncodeToString(desc.id[:]), NoncePrefix: hex.EncodeToString(desc.nonce[:]), PlainBytes: desc.size, PlainSHA256: hex.EncodeToString(desc.plainSHA[:]), CipherSHA256: hex.EncodeToString(h.Sum(nil)), Sections: first.sections}
	raw, e := fixtureStreamManifestBytes(m)
	if e != nil {
		clear(desc.key[:])
		return fixtureSignedStream{}, encryptedSnapshotFixtureDescriptor{}, e
	}
	sum := sha256.Sum256(append([]byte("frontiercloud:fixture-sql-row-stream:v1\x00"), raw...))
	clear(raw)
	signed = fixtureSignedStream{Manifest: m, Signature: ed25519.Sign(signer, sum[:])}
	if ctx.Err() != nil || check() != nil {
		clear(desc.key[:])
		return fixtureSignedStream{}, encryptedSnapshotFixtureDescriptor{}, invalid("fixture freeze lost")
	}
	return signed, desc, nil
}

func fixtureVerifySignedStream(ctx context.Context, s fixtureSignedStream, public ed25519.PublicKey, scope fixtureStreamScope, desc encryptedSnapshotFixtureDescriptor, file *os.File) error {
	m := s.Manifest
	if ctx == nil || ctx.Err() != nil || len(public) != ed25519.PublicKeySize || len(s.Signature) != ed25519.SignatureSize || file == nil || m.Version != 1 || m.Source != scope.Source || m.Target != scope.Target || m.Challenge != scope.Challenge || m.SchemaGeneration != scope.SchemaGeneration || m.PageSize != scope.PageSize || m.PlainBytes != desc.size || m.SnapshotID != hex.EncodeToString(desc.id[:]) || m.NoncePrefix != hex.EncodeToString(desc.nonce[:]) || m.PlainSHA256 != hex.EncodeToString(desc.plainSHA[:]) || len(m.Sections) != len(fixtureRowSpecs) {
		return invalid("fixture signed stream scope")
	}
	for i, spec := range fixtureRowSpecs {
		if m.Sections[i].Name != spec.name || m.Sections[i].Rows < 0 || !id64.MatchString(m.Sections[i].SHA256) {
			return invalid("fixture signed stream sections")
		}
	}
	raw, e := fixtureStreamManifestBytes(m)
	if e != nil {
		return e
	}
	sum := sha256.Sum256(append([]byte("frontiercloud:fixture-sql-row-stream:v1\x00"), raw...))
	clear(raw)
	if !ed25519.Verify(public, sum[:], s.Signature) {
		return invalid("fixture signed stream signature")
	}
	info, e := file.Stat()
	if e != nil || info.Size() <= 0 {
		return invalid("fixture signed stream file")
	}
	h := sha256.New()
	section := io.NewSectionReader(file, 0, info.Size())
	cipherBuffer := make([]byte, 64<<10)
	defer clear(cipherBuffer)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, readErr := section.Read(cipherBuffer)
		if n > 0 {
			_, _ = h.Write(cipherBuffer[:n])
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	want, e := hex.DecodeString(m.CipherSHA256)
	if e != nil || subtle.ConstantTimeCompare(h.Sum(nil), want) != 1 {
		return invalid("fixture signed stream ciphertext")
	}
	reader, e := openEncryptedSnapshotFixture(file, desc)
	if e != nil {
		return invalid("fixture signed stream key")
	}
	defer reader.Close()
	plainHash := sha256.New()
	if e = fixtureVerifyStreamFrames(ctx, io.TeeReader(io.NewSectionReader(reader, 0, desc.size), plainHash), desc.size, m.Sections); e != nil {
		return e
	}
	if subtle.ConstantTimeCompare(plainHash.Sum(nil), desc.plainSHA[:]) != 1 {
		return invalid("fixture signed stream plaintext digest")
	}
	return nil
}
