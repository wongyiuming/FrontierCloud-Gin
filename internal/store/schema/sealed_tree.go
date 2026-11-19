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

var sealedTreeIndexes = []s3Index{
	{"uq_st_records_enc", "sealed_tree_records", []string{"encryption_id"}, true},
	{"uq_st_records_parent_lookup", "sealed_tree_records", []string{"parent_index", "lookup_tag"}, true},
	{"uq_st_placement_blob", "sealed_tree_placements", []string{"blob_index"}, true},
	{"uq_st_placement_enc", "sealed_tree_placements", []string{"encryption_id"}, true},
	{"uq_st_alias_object", "sealed_tree_aliases", []string{"object_index"}, true},
	{"uq_st_revoke_object", "sealed_tree_revocations", []string{"object_index"}, true},
	{"uq_st_capacity_enc", "sealed_tree_capacity_intents", []string{"encryption_id"}, true},
	{"uq_st_capacity_blob", "sealed_tree_capacity_intents", []string{"blob_index"}, true},
	{"uq_st_capacity_member_operation", "sealed_tree_capacity_intents", []string{"member_index", "operation_index"}, true},
	{"uq_st_capacity_account_enc", "sealed_tree_capacity_accounts", []string{"encryption_id"}, true},
	{"uq_st_capacity_scope_enc", "sealed_tree_capacity_scopes", []string{"encryption_id"}, true},
	{"uq_st_listing_group_lookup", "sealed_tree_listing", []string{"group_tag", "lookup_tag"}, true},
	{"uq_st_listing_object", "sealed_tree_listing", []string{"object_index"}, true},
	{"uq_st_facts_enc", "sealed_tree_facts", []string{"encryption_id"}, true},
	{"uq_st_pending_object", "sealed_tree_pending_files", []string{"object_index"}, true},
	{"uq_st_pending_name_enc", "sealed_tree_pending_files", []string{"name_encryption_id"}, true},
	{"uq_st_pending_blob", "sealed_tree_pending_files", []string{"blob_index"}, true},
	{"uq_st_pending_place_enc", "sealed_tree_pending_files", []string{"placement_encryption_id"}, true},
	{"uq_st_pending_parent_lookup", "sealed_tree_pending_files", []string{"parent_index", "lookup_tag"}, true},
	{"uq_st_pending_facts_object", "sealed_tree_pending_facts", []string{"object_index"}, true},
	{"uq_st_pending_facts_enc", "sealed_tree_pending_facts", []string{"encryption_id"}, true},
}

var sealedTreePrimary = map[string]string{
	"sealed_tree_meta": "singleton", "sealed_tree_records": "object_index", "sealed_tree_encryption_ids": "encryption_id", "sealed_tree_blob_ids": "blob_index", "sealed_tree_placements": "object_index", "sealed_tree_aliases": "alias_index", "sealed_tree_revocations": "operation_index", "sealed_tree_facts": "object_index", "sealed_tree_operation_ids": "operation_id", "sealed_tree_pending_files": "operation_id", "sealed_tree_pending_facts": "operation_id", "sealed_tree_fence": "singleton", "sealed_tree_owner_fence": "singleton", "sealed_tree_capacity_intents": "operation_index", "sealed_tree_capacity_meta": "singleton", "sealed_tree_capacity_accounts": "member_index", "sealed_tree_capacity_ids": "encryption_id", "sealed_tree_source_pin": "singleton", "sealed_tree_capacity_scopes": "operation_index", "sealed_tree_listing_meta": "singleton", "sealed_tree_listing": "index_key",
}

func checkSealedTreeDigest() error {
	sqlite, err := migrations.SealedTreeStatements("sqlite")
	if err != nil {
		return err
	}
	mysql, err := migrations.SealedTreeStatements("mysql")
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte("sqlite\n" + strings.Join(sqlite, "\n") + "\nmysql\n" + strings.Join(mysql, "\n")))
	if hex.EncodeToString(sum[:]) != migrations.SealedTreeChecksum {
		return errors.New("sealed tree canonical schema checksum mismatch")
	}
	return nil
}

func checkSealedTreeJournal(ctx context.Context, conn *sql.Conn, required bool) error {
	var name, checksum string
	err := conn.QueryRowContext(ctx, `SELECT migration_name,checksum FROM frontiercloud_schema_migrations WHERE generation=10`).Scan(&name, &checksum)
	if errors.Is(err, sql.ErrNoRows) && !required {
		return nil
	}
	if err != nil {
		return fmt.Errorf("sealed tree schema journal missing or unreadable: %w", err)
	}
	if name != migrations.SealedTreeName || checksum != migrations.SealedTreeChecksum {
		return errors.New("sealed tree schema journal identity mismatch")
	}
	return nil
}

// ValidateSQLiteTree verifies the exact current migration and tree schema on
// the caller's existing SQLite connection. When requireEmpty is true all tree
// tables must also be empty. It performs no repair, creation or deletion.
// The caller must hold its maintenance fence and write transaction throughout.
func ValidateSQLiteTree(ctx context.Context, conn *sql.Conn, requireEmpty bool) error {
	return validateSQLiteTree(ctx, conn, requireEmpty, false)
}

// ValidateEmptySQLiteTreeWithOwner permits the one already authenticated
// Owner binding and requires all tree and selected upload state to be empty.
func ValidateEmptySQLiteTreeWithOwner(ctx context.Context, conn *sql.Conn) error {
	return validateSQLiteTree(ctx, conn, true, true)
}

func validateSQLiteTree(ctx context.Context, conn *sql.Conn, requireEmpty, preparedOwner bool) error {
	if ctx == nil || conn == nil {
		return errors.New("missing SQLite schema verification context")
	}
	var version string
	if err := conn.QueryRowContext(ctx, `SELECT sqlite_version()`).Scan(&version); err != nil || version == "" {
		return errors.New("SQLite schema required")
	}
	var generation int
	if err := conn.QueryRowContext(ctx, `SELECT generation FROM frontiercloud_schema WHERE singleton=1`).Scan(&generation); err != nil || generation != migrations.Generation {
		return errors.New("unexpected SQLite schema generation")
	}
	if err := checkSealedTreeJournal(ctx, conn, true); err != nil {
		return err
	}
	if err := checkLegacyReadIntentJournal(ctx, conn, true); err != nil {
		return err
	}
	if err := prepareLegacyReadIntent(ctx, conn, "sqlite", false, true); err != nil {
		return err
	}
	// A tree initializer cannot safely disregard unresolved selected uploads or
	// partial migration DDL. Keep these records for explicit recovery.
	if err := checkSelectedUploadIntentJournal(ctx, conn, true); err != nil {
		return err
	}
	if err := prepareSelectedUploadIntent(ctx, conn, "sqlite", false, true); err != nil {
		return err
	}
	if err := prepareRecordingAudioSchema(ctx, conn, "sqlite", false, requireEmpty); err != nil {
		return err
	}
	if err := checkOpaqueMigrationJournal(ctx, conn, true); err != nil {
		return err
	}
	if err := prepareOpaqueMigrationSchema(ctx, conn, "sqlite", false, requireEmpty); err != nil {
		return err
	}
	return checkSealedTreeSchema(ctx, conn, "sqlite", false, requireEmpty, preparedOwner)
}

func writeSealedTreeJournal(ctx context.Context, conn *sql.Conn) error {
	if err := checkSealedTreeJournal(ctx, conn, false); err != nil {
		return err
	}
	var n int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM frontiercloud_schema_migrations WHERE generation=10`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		_, err := conn.ExecContext(ctx, `INSERT INTO frontiercloud_schema_migrations(generation,migration_name,checksum,applied_at) VALUES(10,?,?,?)`, migrations.SealedTreeName, migrations.SealedTreeChecksum, time.Now().Unix())
		return err
	}
	return nil
}

func checkSealedIndexOrdering(ctx context.Context, conn *sql.Conn, backend string, index s3Index) error {
	if backend == "mysql" {
		rows, err := conn.QueryContext(ctx, `SELECT SUB_PART,COLLATION FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name=? AND index_name=? ORDER BY SEQ_IN_INDEX`, index.table, index.name)
		if err != nil {
			return err
		}
		defer rows.Close()
		n := 0
		for rows.Next() {
			var prefix sql.NullInt64
			var direction sql.NullString
			if err = rows.Scan(&prefix, &direction); err != nil || prefix.Valid || !direction.Valid || direction.String != "A" {
				return fmt.Errorf("incompatible sealed tree index ordering: %s", index.name)
			}
			n++
		}
		if err = rows.Err(); err != nil {
			return err
		}
		if n != len(index.columns) {
			return fmt.Errorf("incomplete sealed tree index: %s", index.name)
		}
		return nil
	}
	// Index names are fixed constants in sealedTreeIndexes, never user input.
	rows, err := conn.QueryContext(ctx, "PRAGMA index_xinfo("+index.name+")")
	if err != nil {
		return err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var sequence, cid, descending, key int
		var name, collation sql.NullString
		if err = rows.Scan(&sequence, &cid, &name, &descending, &collation, &key); err != nil {
			return err
		}
		if key == 0 {
			continue
		}
		if cid < 0 || !name.Valid || !collation.Valid || !strings.EqualFold(collation.String, "BINARY") || descending != 0 {
			return fmt.Errorf("incompatible sealed tree index collation: %s", index.name)
		}
		n++
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if n != len(index.columns) {
		return fmt.Errorf("incomplete sealed tree index: %s", index.name)
	}
	return nil
}

func checkSealedTreeCollations(ctx context.Context, conn *sql.Conn, backend, table string) error {
	if backend != "mysql" {
		return nil
	}
	var collation string
	if err := conn.QueryRowContext(ctx, `SELECT TABLE_COLLATION FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=?`, table).Scan(&collation); err != nil || collation != "ascii_bin" {
		return fmt.Errorf("incompatible sealed tree table collation: %s", table)
	}
	var count int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=? AND DATA_TYPE='char' AND (CHARACTER_SET_NAME IS NULL OR CHARACTER_SET_NAME<>'ascii' OR COLLATION_NAME IS NULL OR COLLATION_NAME<>'ascii_bin')`, table).Scan(&count); err != nil || count != 0 {
		return fmt.Errorf("incompatible sealed tree column collation: %s", table)
	}
	return nil
}

// prepareSealedTreeSchema is strictly additive. It does not initialize a tree
// key or root, touch historical rows/files, or claim activation readiness.
// MySQL DDL may have committed before interruption; only canonical tables and
// exact indexes can be accepted on retry. Verification never repairs schema.
func prepareSealedTreeSchema(ctx context.Context, conn *sql.Conn, backend string, create bool) error {
	return checkSealedTreeSchema(ctx, conn, backend, create, true, false)
}

func checkSealedTreeSchema(ctx context.Context, conn *sql.Conn, backend string, create, requireEmpty, preparedOwner bool) error {
	if err := checkSealedTreeDigest(); err != nil {
		return err
	}
	statements, err := migrations.SealedTreeStatements(backend)
	if err != nil {
		return err
	}
	definitions := map[string]string{}
	for _, statement := range statements {
		match := tablePattern.FindStringSubmatch(statement)
		if len(match) != 2 || !strings.HasPrefix(match[1], "sealed_tree_") {
			continue
		}
		definitions[match[1]] = statement
		if create {
			if _, err = conn.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
	}
	if len(definitions) != 21 {
		return errors.New("incomplete canonical sealed tree definitions")
	}
	for table, statement := range definitions {
		if err = checkS3Columns(ctx, conn, backend, table, statement); err != nil {
			return err
		}
		if err = checkS3Constraints(ctx, conn, backend, table, statement); err != nil {
			return err
		}
		if err = checkSealedTreeCollations(ctx, conn, backend, table); err != nil {
			return err
		}
		if backend == "mysql" || (table != "sealed_tree_meta" && table != "sealed_tree_fence" && table != "sealed_tree_owner_fence" && table != "sealed_tree_capacity_meta" && table != "sealed_tree_source_pin" && table != "sealed_tree_listing_meta") {
			name := "PRIMARY"
			if backend == "sqlite" {
				name = "sqlite_autoindex_" + table + "_1"
			}
			primary := s3Index{name: name, table: table, columns: []string{sealedTreePrimary[table]}, unique: true}
			if primary.columns[0] == "" {
				return errors.New("unknown sealed tree primary key")
			}
			cols, unique, indexErr := s3IndexColumns(ctx, conn, backend, table, name)
			if indexErr != nil || !unique || strings.Join(cols, ",") != strings.Join(primary.columns, ",") {
				return fmt.Errorf("incompatible sealed tree primary key: %s", table)
			}
			if err = checkSealedIndexOrdering(ctx, conn, backend, primary); err != nil {
				return err
			}
		}
	}
	for _, index := range sealedTreeIndexes {
		if create {
			if err = ensureS3Index(ctx, conn, backend, index); err != nil {
				return err
			}
		} else {
			columns, unique, err := s3IndexColumns(ctx, conn, backend, index.table, index.name)
			if err != nil || !unique || strings.Join(columns, ",") != strings.Join(index.columns, ",") {
				return fmt.Errorf("incompatible sealed tree index: %s", index.name)
			}
		}
		if err = checkSealedIndexOrdering(ctx, conn, backend, index); err != nil {
			return err
		}
	}
	// No running product path, backup or restore format understands these
	// records yet. A nonempty dormant table must stop startup rather than let
	// old catalog writers or recovery silently omit protected state.
	if requireEmpty {
		for table := range definitions {
			var count int64
			var expected int64
			if preparedOwner && table == "sealed_tree_owner_fence" {
				expected = 1
			}
			if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil || count != expected {
				return fmt.Errorf("sealed tree runtime is not integrated; nonempty table %s refused", table)
			}
		}
	}
	return nil
}
