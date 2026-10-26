package schema

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

var s3ColumnPattern = regexp.MustCompile(`^([a-z][a-z0-9_]*)\s+([A-Z]+(?:\([0-9]+\))?)\s+NOT NULL`)
var s3CheckPattern = regexp.MustCompile(`(?i)\bCHECK\s*\(`)

type s3Index struct {
	name, table string
	columns     []string
	unique      bool
}

var s3Indexes = []s3Index{
	{"idx_s3_member_namespace", "s3_members", []string{"namespace_key"}, false},
	{"uq_s3_upload_object", "s3_uploads", []string{"object_id"}, true},
	{"idx_s3_upload_member", "s3_uploads", []string{"member_id", "state"}, false},
	{"idx_s3_upload_state", "s3_uploads", []string{"state", "updated_at"}, false},
	{"uq_s3_object_identity", "s3_objects", []string{"object_id"}, true},
	{"idx_s3_object_member", "s3_objects", []string{"member_id", "state"}, false},
	{"idx_s3_object_state", "s3_objects", []string{"state", "updated_at"}, false},
	{"idx_s3_probe_member", "s3_probe_journal", []string{"member_id", "state"}, false},
	{"idx_s3_probe_state", "s3_probe_journal", []string{"state", "updated_at"}, false},
}

func checkS3Journal(ctx context.Context, conn *sql.Conn, required bool) error {
	var name, checksum string
	err := conn.QueryRowContext(ctx, "SELECT migration_name,checksum FROM frontiercloud_schema_migrations WHERE generation=8").Scan(&name, &checksum)
	if errors.Is(err, sql.ErrNoRows) && !required {
		return nil
	}
	if err != nil {
		return fmt.Errorf("S3 schema journal is missing or unreadable: %w", err)
	}
	if name != migrations.S3Name || checksum != migrations.S3Checksum {
		return errors.New("S3 schema journal identity mismatch")
	}
	return nil
}

func writeS3Journal(ctx context.Context, conn *sql.Conn) error {
	if err := checkS3Journal(ctx, conn, false); err != nil {
		return err
	}
	var count int
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM frontiercloud_schema_migrations WHERE generation=8").Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		_, err := conn.ExecContext(ctx, "INSERT INTO frontiercloud_schema_migrations(generation,migration_name,checksum,applied_at) VALUES (8,?,?,?)", migrations.S3Name, migrations.S3Checksum, time.Now().Unix())
		return err
	}
	return nil
}

// A generation-7 MySQL interruption can leave complete additive tables behind.
// Only absent secondary indexes are repaired. Existing rows, columns, primary
// keys and constraint meanings are never replaced to make admission succeed.
func prepareS3Schema(ctx context.Context, conn *sql.Conn, backend string, statements []string, create bool) error {
	definitions := map[string]string{}
	for _, statement := range statements {
		match := tablePattern.FindStringSubmatch(statement)
		if len(match) == 2 && strings.HasPrefix(match[1], "s3_") {
			definitions[match[1]] = statement
			if create {
				if _, err := conn.ExecContext(ctx, statement); err != nil {
					return err
				}
			}
		}
	}
	if len(definitions) != 5 {
		return errors.New("incomplete canonical S3 table definitions")
	}
	for table, statement := range definitions {
		if err := checkS3Columns(ctx, conn, backend, table, statement); err != nil {
			return err
		}
		if err := checkS3Constraints(ctx, conn, backend, table, statement); err != nil {
			return err
		}
	}
	for _, index := range s3Indexes {
		if err := ensureS3Index(ctx, conn, backend, index); err != nil {
			return err
		}
	}
	return nil
}

func checkS3Columns(ctx context.Context, conn *sql.Conn, backend, table, statement string) error {
	type column struct{ name, kind string }
	var expected []column
	for _, line := range strings.Split(statement, "\n") {
		if match := s3ColumnPattern.FindStringSubmatch(strings.TrimSpace(line)); len(match) == 3 {
			expected = append(expected, column{match[1], strings.ReplaceAll(match[2], "INTEGER", "INT")})
		}
	}
	query := "SELECT COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=? ORDER BY ORDINAL_POSITION"
	var rows *sql.Rows
	var err error
	if backend == "sqlite" {
		rows, err = conn.QueryContext(ctx, "PRAGMA table_info("+table+")")
	} else {
		rows, err = conn.QueryContext(ctx, query, table)
	}
	if err != nil {
		return err
	}
	defer rows.Close()
	index := 0
	var primary []string
	for rows.Next() {
		var name, kind string
		notNull := true
		if backend == "sqlite" {
			var number, required, pk int
			var fallback any
			err = rows.Scan(&number, &name, &kind, &required, &fallback, &pk)
			notNull = required != 0
			if pk != 0 {
				primary = append(primary, name)
			}
		} else {
			var nullable string
			err = rows.Scan(&name, &kind, &nullable)
			notNull = nullable == "NO"
		}
		kind = strings.ReplaceAll(strings.ToUpper(kind), "INTEGER", "INT")
		if err != nil || index >= len(expected) || expected[index] != (column{name, kind}) || !notNull {
			return fmt.Errorf("incompatible S3 table columns: %s", table)
		}
		index++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if index != len(expected) || index == 0 {
		return fmt.Errorf("incomplete S3 table columns: %s", table)
	}
	expectedPrimary := map[string][]string{"s3_members": {"member_id"}, "s3_uploads": {"upload_id"},
		"s3_upload_parts": {"upload_id", "part_number"}, "s3_objects": {"media_id"}, "s3_probe_journal": {"probe_id"}}[table]
	if backend == "mysql" {
		var err error
		primary, _, err = s3IndexColumns(ctx, conn, backend, table, "PRIMARY")
		if err != nil {
			return err
		}
	}
	if strings.Join(primary, ",") != strings.Join(expectedPrimary, ",") {
		return fmt.Errorf("incompatible S3 table primary key: %s", table)
	}
	return nil
}

func normalizedS3Check(value string) string {
	return strings.Map(func(c rune) rune {
		if c == '(' || c == ')' || c == '`' || c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			return -1
		}
		return c
	}, strings.ToUpper(value))
}

func s3Checks(statement string) []string {
	var result []string
	for _, bounds := range s3CheckPattern.FindAllStringIndex(statement, -1) {
		start, depth := bounds[1], 1
		for end := start; end < len(statement); end++ {
			switch statement[end] {
			case '(':
				depth++
			case ')':
				depth--
			}
			if depth == 0 {
				result = append(result, normalizedS3Check(statement[start:end]))
				break
			}
		}
	}
	sort.Strings(result)
	return result
}

func checkS3Constraints(ctx context.Context, conn *sql.Conn, backend, table, statement string) error {
	expected := s3Checks(statement)
	var actual []string
	if backend == "sqlite" {
		var ddl string
		if err := conn.QueryRowContext(ctx, "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?", table).Scan(&ddl); err != nil {
			return err
		}
		actual = s3Checks(ddl)
	} else {
		rows, err := conn.QueryContext(ctx, "SELECT c.CHECK_CLAUSE FROM information_schema.check_constraints c JOIN information_schema.table_constraints t ON c.CONSTRAINT_SCHEMA=t.CONSTRAINT_SCHEMA AND c.CONSTRAINT_NAME=t.CONSTRAINT_NAME WHERE t.TABLE_SCHEMA=DATABASE() AND t.TABLE_NAME=? AND t.CONSTRAINT_TYPE='CHECK'", table)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var clause string
			if err := rows.Scan(&clause); err != nil {
				return err
			}
			actual = append(actual, normalizedS3Check(clause))
		}
		if err := rows.Err(); err != nil {
			return err
		}
		sort.Strings(actual)
	}
	if strings.Join(actual, "\n") != strings.Join(expected, "\n") {
		return fmt.Errorf("incompatible S3 table constraints: %s", table)
	}
	return nil
}

func s3IndexColumns(ctx context.Context, conn *sql.Conn, backend, table, name string) ([]string, bool, error) {
	if backend == "mysql" {
		rows, err := conn.QueryContext(ctx, "SELECT COLUMN_NAME,NON_UNIQUE FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name=? AND index_name=? ORDER BY SEQ_IN_INDEX", table, name)
		if err != nil {
			return nil, false, err
		}
		defer rows.Close()
		var columns []string
		unique := true
		for rows.Next() {
			var column string
			var nonUnique int
			if err := rows.Scan(&column, &nonUnique); err != nil {
				return nil, false, err
			}
			columns = append(columns, column)
			unique = unique && nonUnique == 0
		}
		return columns, unique, rows.Err()
	}
	var owner string
	err := conn.QueryRowContext(ctx, "SELECT tbl_name FROM sqlite_schema WHERE type='index' AND name=?", name).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil || owner != table {
		return nil, false, fmt.Errorf("incompatible S3 index owner: %s", name)
	}
	rows, err := conn.QueryContext(ctx, "PRAGMA index_list("+table+")")
	if err != nil {
		return nil, false, err
	}
	unique := false
	for rows.Next() {
		var number, isUnique, partial int
		var index, origin string
		if err := rows.Scan(&number, &index, &isUnique, &origin, &partial); err != nil {
			rows.Close()
			return nil, false, err
		}
		if index == name {
			if partial != 0 {
				rows.Close()
				return nil, false, fmt.Errorf("partial S3 index is unsupported: %s", name)
			}
			unique = isUnique != 0
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, false, err
	}
	if err := rows.Close(); err != nil {
		return nil, false, err
	}
	rows, err = conn.QueryContext(ctx, "PRAGMA index_info("+name+")")
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var sequence, number int
		var column string
		if err := rows.Scan(&sequence, &number, &column); err != nil {
			return nil, false, err
		}
		columns = append(columns, column)
	}
	return columns, unique, rows.Err()
}

func ensureS3Index(ctx context.Context, conn *sql.Conn, backend string, index s3Index) error {
	columns, unique, err := s3IndexColumns(ctx, conn, backend, index.table, index.name)
	if err != nil {
		return err
	}
	if len(columns) != 0 {
		if strings.Join(columns, ",") != strings.Join(index.columns, ",") || unique != index.unique {
			return fmt.Errorf("incompatible S3 secondary index: %s", index.name)
		}
		return nil
	}
	kind := ""
	if index.unique {
		kind = "UNIQUE "
	}
	query := "CREATE " + kind + "INDEX " + index.name + " ON " + index.table + " (" + strings.Join(index.columns, ",") + ")"
	if backend == "mysql" {
		query = "ALTER TABLE " + index.table + " ADD " + kind + "INDEX " + index.name + " (" + strings.Join(index.columns, ",") + ")"
	}
	_, err = conn.ExecContext(ctx, query)
	return err
}
