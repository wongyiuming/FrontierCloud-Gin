package schema

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

func checkSelectedUploadIntentJournal(ctx context.Context, conn *sql.Conn, required bool) error {
	var name, checksum string
	err := conn.QueryRowContext(ctx, `SELECT migration_name,checksum FROM frontiercloud_schema_migrations WHERE generation=12`).Scan(&name, &checksum)
	if errors.Is(err, sql.ErrNoRows) && !required {
		return nil
	}
	if err != nil || name != migrations.SelectedUploadIntentName || checksum != migrations.SelectedUploadIntentChecksum {
		return errors.New("selected upload intent migration journal mismatch")
	}
	return nil
}

func writeSelectedUploadIntentJournal(ctx context.Context, conn *sql.Conn) error {
	if err := checkSelectedUploadIntentJournal(ctx, conn, false); err != nil {
		return err
	}
	var n int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM frontiercloud_schema_migrations WHERE generation=12`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		_, err := conn.ExecContext(ctx, `INSERT INTO frontiercloud_schema_migrations(generation,migration_name,checksum,applied_at) VALUES(12,?,?,?)`, migrations.SelectedUploadIntentName, migrations.SelectedUploadIntentChecksum, time.Now().Unix())
		return err
	}
	return nil
}

// MySQL DDL can survive interruption. Only an exact canonical empty partial
// structure may be completed before the migration journal is committed. The
// new upload runtime/recovery path is not installed, so startup also refuses
// nonempty selected-upload intents instead of dropping them or guessing state.
func prepareSelectedUploadIntent(ctx context.Context, conn *sql.Conn, backend string, create, requireEmpty bool) error {
	sqlite, err := migrations.SelectedUploadIntentStatements("sqlite")
	if err != nil {
		return err
	}
	mysql, err := migrations.SelectedUploadIntentStatements("mysql")
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte("sqlite\n" + strings.Join(sqlite, "\n") + "\nmysql\n" + strings.Join(mysql, "\n")))
	if hex.EncodeToString(sum[:]) != migrations.SelectedUploadIntentChecksum {
		return errors.New("selected upload intent checksum mismatch")
	}
	statements := sqlite
	if backend == "mysql" {
		statements = mysql
	} else if backend != "sqlite" {
		return errors.New("unsupported database")
	}
	if len(statements) == 0 {
		return errors.New("missing selected upload intent schema")
	}
	if create {
		if _, err = conn.ExecContext(ctx, statements[0]); err != nil {
			return err
		}
	}
	const table = "selected_upload_intents"
	if err = checkS3Columns(ctx, conn, backend, table, statements[0]); err != nil {
		return err
	}
	if err = checkS3Constraints(ctx, conn, backend, table, statements[0]); err != nil {
		return err
	}
	if err = checkSealedTreeCollations(ctx, conn, backend, table); err != nil {
		return err
	}
	primary := s3Index{name: "PRIMARY", table: table, columns: []string{"operation_index"}, unique: true}
	if backend == "sqlite" {
		primary.name = "sqlite_autoindex_" + table + "_1"
	}
	cols, unique, err := s3IndexColumns(ctx, conn, backend, table, primary.name)
	if err != nil || !unique || strings.Join(cols, ",") != "operation_index" {
		return errors.New("invalid selected upload intent primary key")
	}
	if err = checkSealedIndexOrdering(ctx, conn, backend, primary); err != nil {
		return err
	}
	for _, index := range []s3Index{
		{name: "uq_selected_upload_upload", table: table, columns: []string{"upload_index"}, unique: true},
		{name: "uq_selected_upload_blob", table: table, columns: []string{"blob_index"}, unique: true},
		{name: "uq_selected_upload_encryption", table: table, columns: []string{"encryption_id"}, unique: true},
		{name: "idx_selected_upload_member", table: table, columns: []string{"member_index"}},
		{name: "idx_selected_upload_parent", table: table, columns: []string{"parent_index", "state"}},
	} {
		if create {
			if err = ensureS3Index(ctx, conn, backend, index); err != nil {
				return err
			}
		}
		cols, unique, err = s3IndexColumns(ctx, conn, backend, table, index.name)
		if err != nil || unique != index.unique || strings.Join(cols, ",") != strings.Join(index.columns, ",") {
			return errors.New("invalid selected upload intent index")
		}
		if err = checkSealedIndexOrdering(ctx, conn, backend, index); err != nil {
			return err
		}
	}
	const scopeTable = "selected_upload_parent_scopes"
	var scopeDDL string
	for _, stmt := range statements {
		if strings.HasPrefix(stmt, "CREATE TABLE IF NOT EXISTS "+scopeTable+" ") {
			if scopeDDL != "" {
				return errors.New("duplicate selected upload scope schema")
			}
			scopeDDL = stmt
		}
	}
	if scopeDDL == "" {
		return errors.New("missing selected upload scope schema")
	}
	if create {
		if _, err = conn.ExecContext(ctx, scopeDDL); err != nil {
			return err
		}
	}
	if err = checkS3Columns(ctx, conn, backend, scopeTable, scopeDDL); err != nil {
		return err
	}
	if err = checkS3Constraints(ctx, conn, backend, scopeTable, scopeDDL); err != nil {
		return err
	}
	if err = checkSealedTreeCollations(ctx, conn, backend, scopeTable); err != nil {
		return err
	}
	scopePrimary := s3Index{name: "PRIMARY", table: scopeTable, columns: []string{"parent_index"}, unique: true}
	if backend == "sqlite" {
		scopePrimary.name = "sqlite_autoindex_" + scopeTable + "_1"
	}
	cols, unique, err = s3IndexColumns(ctx, conn, backend, scopeTable, scopePrimary.name)
	if err != nil || !unique || strings.Join(cols, ",") != "parent_index" {
		return errors.New("invalid selected upload scope primary key")
	}
	if err = checkSealedIndexOrdering(ctx, conn, backend, scopePrimary); err != nil {
		return err
	}
	scopeIndex := s3Index{name: "uq_selected_upload_scope_encryption", table: scopeTable, columns: []string{"encryption_id"}, unique: true}
	if create {
		if err = ensureS3Index(ctx, conn, backend, scopeIndex); err != nil {
			return err
		}
	}
	cols, unique, err = s3IndexColumns(ctx, conn, backend, scopeTable, scopeIndex.name)
	if err != nil || !unique || strings.Join(cols, ",") != "encryption_id" {
		return errors.New("invalid selected upload scope encryption index")
	}
	if err = checkSealedIndexOrdering(ctx, conn, backend, scopeIndex); err != nil {
		return err
	}
	const cancellationTable = "selected_upload_cancellations"
	var cancellationDDL string
	for _, stmt := range statements {
		if strings.HasPrefix(stmt, "CREATE TABLE IF NOT EXISTS "+cancellationTable+" ") {
			if cancellationDDL != "" {
				return errors.New("duplicate selected upload cancellation schema")
			}
			cancellationDDL = stmt
		}
	}
	if cancellationDDL == "" {
		return errors.New("missing selected upload cancellation schema")
	}
	if create {
		if _, err = conn.ExecContext(ctx, cancellationDDL); err != nil {
			return err
		}
	}
	if err = checkS3Columns(ctx, conn, backend, cancellationTable, cancellationDDL); err != nil {
		return err
	}
	if err = checkS3Constraints(ctx, conn, backend, cancellationTable, cancellationDDL); err != nil {
		return err
	}
	if err = checkSealedTreeCollations(ctx, conn, backend, cancellationTable); err != nil {
		return err
	}
	cancelPrimary := s3Index{name: "PRIMARY", table: cancellationTable, columns: []string{"operation_id"}, unique: true}
	if backend == "sqlite" {
		cancelPrimary.name = "sqlite_autoindex_" + cancellationTable + "_1"
	}
	cols, unique, err = s3IndexColumns(ctx, conn, backend, cancellationTable, cancelPrimary.name)
	if err != nil || !unique || strings.Join(cols, ",") != "operation_id" {
		return errors.New("invalid selected upload cancellation primary key")
	}
	if err = checkSealedIndexOrdering(ctx, conn, backend, cancelPrimary); err != nil {
		return err
	}
	if create {
		for _, statement := range statements {
			if migrations.IsSelectedS3Statement(statement) {
				if _, err = conn.ExecContext(ctx, statement); err != nil {
					return err
				}
			}
		}
	}
	if err = ValidateSelectedS3Schema(ctx, conn, backend); err != nil {
		return err
	}
	if requireEmpty {
		var n int64
		if err = conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil || n != 0 {
			return fmt.Errorf("selected upload intents require offline recovery")
		}
		if err = conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+scopeTable).Scan(&n); err != nil || n != 0 {
			return fmt.Errorf("selected upload parent scopes require offline recovery")
		}
		if err = conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+cancellationTable).Scan(&n); err != nil || n != 0 {
			return fmt.Errorf("selected upload cancellations require offline recovery")
		}
		for _, name := range []string{"selected_s3_uploads", "selected_s3_parts"} {
			if err = conn.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM "+name+")").Scan(&n); err != nil || n != 0 {
				return errors.New("selected S3 multipart journals require offline recovery")
			}
		}
	}
	return nil
}
