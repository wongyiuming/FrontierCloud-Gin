package preprodimport

// The v2 source row stream is an internal primitive, not a receiver, import
// authority or production route. The only permissible persisted destination is
// an authenticated encrypting writer; plaintext must never be written to disk.
import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
)

type sourceRowSpec struct {
	name, table, key, condition string
	columns                     []string
}

var sourceRowSpecs = []sourceRowSpec{
	{"objects", "media_objects", "media_id", "", []string{"media_id", "object_kind", "media_path", "path_locator", "created_at", "updated_at"}},
	{"placements", "global_media_objects", "media_id", "", []string{"media_id", "storage_member_id", "object_id", "media_path", "object_kind", "size_bytes", "etag", "state", "created_at", "updated_at"}},
	{"visibility", "media_visibility", "relative_path", "", []string{"relative_path", "hidden", "updated_at"}},
	{"playback", "media_playback_stats", "media_id", "", []string{"media_id", "media_path", "preference", "play_score", "created_at", "updated_at"}},
	{"lyric_links", "media_lyric_links", "media_id", "", []string{"media_id", "media_path", "lyric_id", "lyric_path", "created_at", "updated_at"}},
	{"encryption", "media_encryption", "object_id", "object_kind='media'", []string{"object_kind", "object_id", "file_id", "descriptor_json", "created_at"}},
	{"members", "cluster_storage_members", "member_id", "", []string{"member_id", "relationship_id", "member_kind", "transport", "storage_enabled", "allocated_bytes", "used_bytes", "reserved_bytes", "physical_free_bytes", "health", "writable", "updated_at"}},
	{"relationships", "node_relationships", "relationship_id", "", []string{"relationship_id", "peer_id", "peer_endpoint", "peer_key", "direction", "mode", "state", "created_at"}},
	{"crypto_key_id", "media_crypto_keys", "singleton", "", []string{"singleton", "key_id", "created_at"}},
	// Reserved IDs include both kinds and NULL-descriptor tombstones; this
	// section intentionally contains no recording object IDs or content.
	{"encryption_ids", "media_encryption", "file_id", "", []string{"file_id"}},
}

type sourceSectionDigest struct {
	Name   string `json:"name"`
	Rows   int64  `json:"rows"`
	SHA256 string `json:"sha256"`
}
type sourceRowsDigest struct {
	Sections []sourceSectionDigest
	Bytes    int64
	SHA256   [32]byte
}

// A non-unique key would silently omit records when crossing a page boundary.
func requireSourceUniqueKey(ctx context.Context, q maintenance.SQLiteSnapshotReader, spec sourceRowSpec) error {
	expected := spec.key
	if spec.name == "encryption" {
		expected = "object_kind,object_id"
	}
	rows, err := q.QueryContext(ctx, `SELECT name,pk FROM pragma_table_info(?) WHERE pk>0 ORDER BY pk`, spec.table)
	if err != nil {
		return invalid("source row key schema")
	}
	var cols []string
	for rows.Next() {
		var name string
		var order int
		if rows.Scan(&name, &order) != nil {
			rows.Close()
			return invalid("source row key schema")
		}
		cols = append(cols, name)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return invalid("source row key schema")
	}
	if strings.Join(cols, ",") == expected {
		return nil
	}
	rows, err = q.QueryContext(ctx, `SELECT name FROM pragma_index_list(?) WHERE "unique"=1 AND partial=0`, spec.table)
	if err != nil {
		return invalid("source row indexes")
	}
	var indexes []string
	for rows.Next() {
		var name string
		if rows.Scan(&name) != nil {
			rows.Close()
			return invalid("source row indexes")
		}
		indexes = append(indexes, name)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return invalid("source row indexes")
	}
	for _, index := range indexes {
		rows, err = q.QueryContext(ctx, `SELECT name FROM pragma_index_info(?) ORDER BY seqno`, index)
		if err != nil {
			return invalid("source row indexes")
		}
		cols = nil
		for rows.Next() {
			var name sql.NullString
			if rows.Scan(&name) != nil || !name.Valid {
				rows.Close()
				return invalid("source row indexes")
			}
			cols = append(cols, name.String)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return invalid("source row indexes")
		}
		if strings.Join(cols, ",") == expected {
			return nil
		}
	}
	return invalid("source row key not unique")
}

func writeSourceFrame(out io.Writer, total, section hash.Hash, result *sourceRowsDigest, frame any) error {
	raw, err := json.Marshal(frame)
	if err != nil || len(raw) > 1<<20 {
		return invalid("source row frame")
	}
	raw = append(raw, '\n')
	defer clear(raw)
	_, _ = total.Write(raw)
	_, _ = section.Write(raw)
	n, err := out.Write(raw)
	if err != nil || n != len(raw) {
		return invalid("source row output")
	}
	result.Bytes += int64(n)
	if result.Bytes < 0 {
		return invalid("source row size overflow")
	}
	return nil
}

// scanSourceRowsV2 uses fixed SQL and binary keyset paging; each cell is
// bounded before the driver allocates it. check must retain the same SQLite
// transaction and maintenance lease through every row and final signature.
func scanSourceRowsV2(ctx context.Context, q maintenance.SQLiteSnapshotReader, out io.Writer, pageSize int, check func() error) (result sourceRowsDigest, err error) {
	if ctx == nil || q == nil || out == nil || check == nil || pageSize < 1 || pageSize > 128 {
		return result, invalid("source row input")
	}
	total := sha256.New()
	for _, spec := range sourceRowSpecs {
		if ctx.Err() != nil || check() != nil {
			return sourceRowsDigest{}, invalid("source row fence")
		}
		if err = requireSourceUniqueKey(ctx, q, spec); err != nil {
			return sourceRowsDigest{}, err
		}
		section := sha256.New()
		if err = writeSourceFrame(out, total, section, &result, struct {
			Name    string   `json:"section"`
			Columns []string `json:"columns"`
		}{spec.name, spec.columns}); err != nil {
			return sourceRowsDigest{}, err
		}
		keyIndex := -1
		bounded := make([]string, len(spec.columns))
		for i, column := range spec.columns {
			bounded[i] = "SUBSTR(" + column + ",1,65537)"
			if column == spec.key {
				keyIndex = i
			}
		}
		if keyIndex < 0 {
			return sourceRowsDigest{}, invalid("source row key")
		}
		last := ""
		first := true
		var count int64
		for {
			if ctx.Err() != nil || check() != nil {
				return sourceRowsDigest{}, invalid("source row fence")
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
			rows, e := q.QueryContext(ctx, query, args...)
			if e != nil {
				return sourceRowsDigest{}, invalid("source row query")
			}
			page := 0
			for rows.Next() {
				if ctx.Err() != nil || check() != nil {
					rows.Close()
					return sourceRowsDigest{}, invalid("source row fence")
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
					return sourceRowsDigest{}, invalid("source row scan")
				}
				cells := make([]*string, len(values))
				for i, value := range values {
					if !value.Valid {
						if !(spec.name == "encryption" && spec.columns[i] == "descriptor_json") && !(spec.name == "members" && spec.columns[i] == "relationship_id") {
							rows.Close()
							return sourceRowsDigest{}, invalid("source row null")
						}
						continue
					}
					if len(value.String) > 65536 || !utf8.ValidString(value.String) || strings.ContainsRune(value.String, 0) {
						rows.Close()
						return sourceRowsDigest{}, invalid("source row value")
					}
					v := value.String
					cells[i] = &v
				}
				if cells[keyIndex] == nil || *cells[keyIndex] == "" || (spec.name == "crypto_key_id" && (keyType != "integer" || *cells[keyIndex] != "1")) || (spec.name == "encryption_ids" && !id32.MatchString(*cells[keyIndex])) || (spec.name != "crypto_key_id" && keyType != "text") || (!first && *cells[keyIndex] <= last) {
					rows.Close()
					return sourceRowsDigest{}, invalid("source row order")
				}
				last = *cells[keyIndex]
				first = false
				page++
				count++
				if count < 0 {
					rows.Close()
					return sourceRowsDigest{}, invalid("source row count overflow")
				}
				if err = writeSourceFrame(out, total, section, &result, struct {
					Row []*string `json:"row"`
				}{cells}); err != nil {
					rows.Close()
					return sourceRowsDigest{}, err
				}
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return sourceRowsDigest{}, invalid("source row scan")
			}
			if page < pageSize {
				break
			}
		}
		if err = writeSourceFrame(out, total, section, &result, struct {
			End  string `json:"end"`
			Rows int64  `json:"rows"`
		}{spec.name, count}); err != nil {
			return sourceRowsDigest{}, err
		}
		result.Sections = append(result.Sections, sourceSectionDigest{Name: spec.name, Rows: count, SHA256: hex.EncodeToString(section.Sum(nil))})
	}
	copy(result.SHA256[:], total.Sum(nil))
	return result, nil
}
