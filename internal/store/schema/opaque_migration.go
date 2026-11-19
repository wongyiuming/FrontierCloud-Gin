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

type opaqueMigrationTable struct {
	name, foreignKey, referencedTable string
	primary, foreignColumns           []string
	zeroDefaults                      []string
}

var opaqueMigrationTables = []opaqueMigrationTable{
	{name: "opaque_migration_tasks", foreignKey: "fk_opaque_migration_task", referencedTable: "migration_tasks",
		primary: []string{"task_id"}, foreignColumns: []string{"task_id"}},
	{name: "opaque_migration_units", foreignKey: "fk_opaque_migration_unit", referencedTable: "opaque_migration_tasks",
		primary: []string{"task_id", "unit_id"}, foreignColumns: []string{"task_id"}, zeroDefaults: []string{"committed_at", "cleanup_after"}},
	{name: "opaque_migration_objects", foreignKey: "fk_opaque_migration_object", referencedTable: "opaque_migration_units",
		primary: []string{"task_id", "object_index"}, foreignColumns: []string{"task_id", "unit_id"}, zeroDefaults: []string{"verified_bytes"}},
}

var opaqueMigrationIndexes = []s3Index{
	{"uq_opaque_migration_task_intent", "opaque_migration_tasks", []string{"intent_encryption_id"}, true},
	{"uq_opaque_migration_task_terminal", "opaque_migration_tasks", []string{"terminal_encryption_id"}, true},
	{"uq_opaque_migration_active_parent", "opaque_migration_units", []string{"active_parent_index"}, true},
	{"uq_opaque_migration_unit_encryption", "opaque_migration_units", []string{"encryption_id"}, true},
	{"idx_opaque_migration_unit_state", "opaque_migration_units", []string{"task_id", "state", "cleanup_after"}, false},
	{"uq_opaque_migration_retired_alias", "opaque_migration_objects", []string{"retired_alias_index"}, true},
	{"uq_opaque_migration_object_encryption", "opaque_migration_objects", []string{"encryption_id"}, true},
	{"uq_opaque_migration_object_receipt", "opaque_migration_objects", []string{"receipt_encryption_id"}, true},
	{"idx_opaque_migration_unit_objects", "opaque_migration_objects", []string{"task_id", "unit_id", "object_index"}, false},
}

func checkOpaqueMigrationJournal(ctx context.Context, conn *sql.Conn, required bool) error {
	var name, checksum string
	err := conn.QueryRowContext(ctx, `SELECT migration_name,checksum FROM frontiercloud_schema_migrations WHERE generation=13`).Scan(&name, &checksum)
	if errors.Is(err, sql.ErrNoRows) && !required {
		return nil
	}
	if err != nil || name != migrations.OpaqueMigrationName || checksum != migrations.OpaqueMigrationChecksum {
		return errors.New("opaque migration ledger journal mismatch")
	}
	return nil
}

func writeOpaqueMigrationJournal(ctx context.Context, conn *sql.Conn) error {
	if err := checkOpaqueMigrationJournal(ctx, conn, false); err != nil {
		return err
	}
	var present bool
	if err := conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM frontiercloud_schema_migrations WHERE generation=13)`).Scan(&present); err != nil {
		return err
	}
	if present {
		return nil
	}
	_, err := conn.ExecContext(ctx, `INSERT INTO frontiercloud_schema_migrations(generation,migration_name,checksum,applied_at) VALUES(13,?,?,?)`,
		migrations.OpaqueMigrationName, migrations.OpaqueMigrationChecksum, time.Now().Unix())
	return err
}

// MySQL DDL commits independently. Only canonical empty partial structures
// can be completed before the new migration journal is recorded. Verification
// of an already prepared runtime does not create, repair or empty its ledger.
func prepareOpaqueMigrationSchema(ctx context.Context, conn *sql.Conn, backend string, create, requireEmpty bool) error {
	sqlite, err := migrations.OpaqueMigrationStatements("sqlite")
	if err != nil {
		return err
	}
	mysql, err := migrations.OpaqueMigrationStatements("mysql")
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte("sqlite\n" + strings.Join(sqlite, "\n") + "\nmysql\n" + strings.Join(mysql, "\n")))
	if hex.EncodeToString(digest[:]) != migrations.OpaqueMigrationChecksum {
		return errors.New("opaque migration ledger checksum mismatch")
	}
	statements := sqlite
	if backend == "mysql" {
		statements = mysql
	} else if backend != "sqlite" {
		return errors.New("unsupported database")
	}
	definitions := make(map[string]string, len(opaqueMigrationTables))
	for _, statement := range statements {
		match := tablePattern.FindStringSubmatch(statement)
		if len(match) == 2 {
			definitions[match[1]] = statement
		}
	}
	if len(definitions) != len(opaqueMigrationTables) {
		return errors.New("incomplete canonical opaque migration ledger definitions")
	}
	for _, table := range opaqueMigrationTables {
		statement := definitions[table.name]
		if statement == "" {
			return errors.New("missing opaque migration ledger definition")
		}
		if create {
			if _, err := conn.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
		if err := checkOpaqueMigrationTable(ctx, conn, backend, table, statement); err != nil {
			return err
		}
		if requireEmpty {
			var populated bool
			if err := conn.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM "+table.name+")").Scan(&populated); err != nil || populated {
				return errors.New("opaque migration ledger requires prepared runtime recovery")
			}
		}
	}
	for _, index := range opaqueMigrationIndexes {
		if create {
			if err := ensureS3Index(ctx, conn, backend, index); err != nil {
				return err
			}
		}
		columns, unique, err := s3IndexColumns(ctx, conn, backend, index.table, index.name)
		if err != nil || unique != index.unique || strings.Join(columns, ",") != strings.Join(index.columns, ",") {
			return fmt.Errorf("incompatible opaque migration ledger index: %s", index.name)
		}
		if err := checkSealedIndexOrdering(ctx, conn, backend, index); err != nil {
			return err
		}
	}
	return nil
}

func checkOpaqueMigrationTable(ctx context.Context, conn *sql.Conn, backend string, table opaqueMigrationTable, statement string) error {
	primary := s3Index{name: "PRIMARY", table: table.name, columns: table.primary, unique: true}
	if backend == "sqlite" {
		// SQLite preserves the table definition except for IF NOT EXISTS.
		// Compare the whole definition, including defaults and foreign keys.
		expected := strings.Replace(statement, "CREATE TABLE IF NOT EXISTS ", "CREATE TABLE ", 1)
		var actual string
		if err := conn.QueryRowContext(ctx, `SELECT sql FROM sqlite_schema WHERE type='table' AND name=?`, table.name).Scan(&actual); err != nil || actual != expected {
			return fmt.Errorf("incompatible opaque migration ledger table: %s", table.name)
		}
		primary.name = "sqlite_autoindex_" + table.name + "_1"
	} else {
		if err := checkS3Columns(ctx, conn, backend, table.name, statement); err != nil {
			return err
		}
		if err := checkS3Constraints(ctx, conn, backend, table.name, statement); err != nil {
			return err
		}
		if err := checkOpaqueMigrationMySQLTable(ctx, conn, table); err != nil {
			return err
		}
	}
	return checkSealedIndexOrdering(ctx, conn, backend, primary)
}

func checkOpaqueMigrationMySQLTable(ctx context.Context, conn *sql.Conn, table opaqueMigrationTable) error {
	var collation, engine string
	if err := conn.QueryRowContext(ctx, `SELECT TABLE_COLLATION,ENGINE FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?`, table.name).Scan(&collation, &engine); err != nil || collation != "utf8mb4_bin" || engine != "InnoDB" {
		return fmt.Errorf("incompatible opaque migration ledger storage: %s", table.name)
	}
	var mismatched int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.columns WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND DATA_TYPE IN ('char','varchar') AND COLLATION_NAME<>'utf8mb4_bin'`, table.name).Scan(&mismatched); err != nil || mismatched != 0 {
		return fmt.Errorf("incompatible opaque migration ledger collation: %s", table.name)
	}
	defaults, err := conn.QueryContext(ctx, `SELECT COLUMN_NAME,COLUMN_DEFAULT FROM information_schema.columns WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND COLUMN_DEFAULT IS NOT NULL ORDER BY ORDINAL_POSITION`, table.name)
	if err != nil {
		return err
	}
	var foundDefaults []string
	for defaults.Next() {
		var column, value string
		if err := defaults.Scan(&column, &value); err != nil || value != "0" {
			defaults.Close()
			return fmt.Errorf("incompatible opaque migration ledger defaults: %s", table.name)
		}
		foundDefaults = append(foundDefaults, column)
	}
	if err := errors.Join(defaults.Err(), defaults.Close()); err != nil {
		return err
	}
	if strings.Join(foundDefaults, ",") != strings.Join(table.zeroDefaults, ",") {
		return fmt.Errorf("incomplete opaque migration ledger defaults: %s", table.name)
	}
	rows, err := conn.QueryContext(ctx, `SELECT k.CONSTRAINT_NAME,k.ORDINAL_POSITION,k.REFERENCED_TABLE_SCHEMA=DATABASE(),k.REFERENCED_TABLE_NAME,k.COLUMN_NAME,k.REFERENCED_COLUMN_NAME,r.UPDATE_RULE,r.DELETE_RULE
		FROM information_schema.key_column_usage k JOIN information_schema.referential_constraints r
		ON r.CONSTRAINT_SCHEMA=k.CONSTRAINT_SCHEMA AND r.CONSTRAINT_NAME=k.CONSTRAINT_NAME AND r.TABLE_NAME=k.TABLE_NAME
		WHERE k.TABLE_SCHEMA=DATABASE() AND k.TABLE_NAME=? AND k.REFERENCED_TABLE_NAME IS NOT NULL ORDER BY k.CONSTRAINT_NAME,k.ORDINAL_POSITION`, table.name)
	if err != nil {
		return err
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var key, targetTable, column, targetColumn, update, remove string
		var position int
		var localSchema bool
		if err := rows.Scan(&key, &position, &localSchema, &targetTable, &column, &targetColumn, &update, &remove); err != nil ||
			seen >= len(table.foreignColumns) || key != table.foreignKey || position != seen+1 || !localSchema || targetTable != table.referencedTable ||
			column != table.foreignColumns[seen] || targetColumn != column || update != "RESTRICT" || remove != "RESTRICT" {
			return fmt.Errorf("incompatible opaque migration ledger foreign key: %s", table.name)
		}
		seen++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if seen != len(table.foreignColumns) {
		return fmt.Errorf("incomplete opaque migration ledger foreign key: %s", table.name)
	}
	return nil
}
