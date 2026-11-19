package schema

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

// ValidateSelectedS3Schema rejects incompatible columns, constraints,
// collations and indexes. Migration ownership and incomplete-operation
// recovery must be checked separately by the integrating runtime.
func ValidateSelectedS3Schema(ctx context.Context, conn *sql.Conn, backend string) error {
	statements, err := migrations.SelectedS3Statements(backend)
	if err != nil || ctx == nil || conn == nil {
		return errors.New("invalid selected S3 schema input")
	}
	definitions := map[string]string{}
	for _, statement := range statements {
		if match := tablePattern.FindStringSubmatch(statement); len(match) == 2 {
			definitions[match[1]] = statement
		}
	}
	if len(definitions) != 2 {
		return errors.New("incomplete selected S3 schema")
	}
	for table, definition := range definitions {
		if err := checkSelectedS3Columns(ctx, conn, backend, table, definition); err != nil {
			return err
		}
		if err := checkS3Constraints(ctx, conn, backend, table, definition); err != nil {
			return err
		}
		if err := checkSealedTreeCollations(ctx, conn, backend, table); err != nil {
			return err
		}
	}
	indexes := []s3Index{
		{name: "uq_selected_s3_upload_encryption", table: "selected_s3_uploads", columns: []string{"encryption_id"}, unique: true},
		{name: "idx_selected_s3_upload_state", table: "selected_s3_uploads", columns: []string{"state", "operation_index"}},
		{name: "uq_selected_s3_part_encryption", table: "selected_s3_parts", columns: []string{"encryption_id"}, unique: true},
	}
	for _, index := range indexes {
		columns, unique, err := s3IndexColumns(ctx, conn, backend, index.table, index.name)
		if err != nil || unique != index.unique || strings.Join(columns, ",") != strings.Join(index.columns, ",") {
			return errors.New("invalid selected S3 index")
		}
		if err = checkSealedIndexOrdering(ctx, conn, backend, index); err != nil {
			return err
		}
	}
	for _, primary := range []s3Index{
		{table: "selected_s3_uploads", columns: []string{"operation_index"}, unique: true},
		{table: "selected_s3_parts", columns: []string{"operation_index", "part_index"}, unique: true},
	} {
		primary.name = "PRIMARY"
		if backend == "sqlite" {
			primary.name = "sqlite_autoindex_" + primary.table + "_1"
		}
		columns, unique, err := s3IndexColumns(ctx, conn, backend, primary.table, primary.name)
		if err != nil || !unique || strings.Join(columns, ",") != strings.Join(primary.columns, ",") {
			return errors.New("invalid selected S3 primary key")
		}
		if err = checkSealedIndexOrdering(ctx, conn, backend, primary); err != nil {
			return err
		}
	}
	return nil
}

func checkSelectedS3Columns(ctx context.Context, conn *sql.Conn, backend, table, definition string) error {
	type column struct{ name, kind string }
	var expected []column
	for _, line := range strings.Split(definition, "\n") {
		if match := s3ColumnPattern.FindStringSubmatch(strings.TrimSpace(line)); len(match) == 4 && match[3] == "NOT NULL" {
			expected = append(expected, column{match[1], strings.ReplaceAll(match[2], "INTEGER", "INT")})
		}
	}
	var rows *sql.Rows
	var err error
	if backend == "sqlite" {
		rows, err = conn.QueryContext(ctx, "PRAGMA table_info("+table+")")
	} else {
		rows, err = conn.QueryContext(ctx, `SELECT COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=? ORDER BY ORDINAL_POSITION`, table)
	}
	if err != nil {
		return err
	}
	defer rows.Close()
	i := 0
	for rows.Next() {
		var name, kind string
		var required bool
		if backend == "sqlite" {
			var number, notNull, primary int
			var fallback any
			err = rows.Scan(&number, &name, &kind, &notNull, &fallback, &primary)
			required = notNull != 0
		} else {
			var nullable string
			err = rows.Scan(&name, &kind, &nullable)
			required = nullable == "NO"
		}
		kind = strings.ReplaceAll(strings.ToUpper(kind), "INTEGER", "INT")
		if err != nil || !required || i >= len(expected) || expected[i] != (column{name, kind}) {
			return errors.New("invalid selected S3 columns")
		}
		i++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if i == 0 || i != len(expected) {
		return errors.New("incomplete selected S3 columns")
	}
	return nil
}
