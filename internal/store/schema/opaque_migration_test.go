package schema_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/schema"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

func opaqueMigrationGenerationTwelve(t *testing.T) *sql.DB {
	t.Helper()
	db := selectedUploadGenerationEleven(t)
	statements, err := migrations.SelectedUploadIntentStatements("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range statements {
		opaqueLedgerExec(t, db, statement)
	}
	opaqueLedgerExec(t, db, "INSERT INTO frontiercloud_schema_migrations VALUES(12,?,?,123)", migrations.SelectedUploadIntentName, migrations.SelectedUploadIntentChecksum)
	opaqueLedgerExec(t, db, "UPDATE frontiercloud_schema SET generation=12 WHERE singleton=1")
	return db
}

func opaqueLedgerExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func opaqueCommonTask(t *testing.T, db *sql.DB, id string) {
	t.Helper()
	opaqueLedgerExec(t, db, "INSERT INTO migration_tasks(task_id,master_id,source_id,target_id,source_relationship,target_relationship,plan_sha256,plan,state,object_count,total_bytes,created_at,updated_at) VALUES(?,'master','source','target','source-rel','target-rel',?,'{}','queued',1,0,1,1)", id, strings.Repeat("b", 64))
}

func TestOpaqueMigrationGenerationTwelveSQLiteRecovery(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"clean", "partial", "index", "journal", "journal-fault", "partial-data", "protected"} {
		t.Run(mode, func(t *testing.T) {
			db := opaqueMigrationGenerationTwelve(t)
			task := strings.Repeat("a", 32)
			opaqueCommonTask(t, db, task)
			if err := schema.VerifyPreparedSQLiteRuntime(ctx, db); err == nil {
				t.Fatal("Gen12 accepted by Gen13 runtime")
			}
			switch mode {
			case "partial", "index", "partial-data":
				statements, err := migrations.OpaqueMigrationStatements("sqlite")
				if err != nil {
					t.Fatal(err)
				}
				for _, statement := range statements {
					if strings.HasPrefix(statement, "CREATE TABLE") && !strings.Contains(statement, "CREATE TABLE IF NOT EXISTS opaque_migration_objects") {
						opaqueLedgerExec(t, db, statement)
					}
				}
				if mode == "index" {
					opaqueLedgerExec(t, db, "CREATE INDEX uq_opaque_migration_active_parent ON opaque_migration_units(active_parent_index)")
				}
				if mode == "partial-data" {
					opaqueLedgerExec(t, db, "INSERT INTO opaque_migration_tasks(task_id,intent_encryption_id,intent_sealed) VALUES(?,?,?)", task, strings.Repeat("a", 64), []byte("preserve"))
				}
			case "journal":
				opaqueLedgerExec(t, db, "INSERT INTO frontiercloud_schema_migrations VALUES(13,'foreign','foreign',123)")
			case "journal-fault":
				opaqueLedgerExec(t, db, "CREATE TRIGGER fail_opaque_journal BEFORE INSERT ON frontiercloud_schema_migrations WHEN NEW.generation=13 BEGIN SELECT RAISE(ABORT,'opaque-journal-fault'); END")
			case "protected":
				opaqueLedgerExec(t, db, "INSERT INTO legacy_read_control_intents VALUES(?,?,?,1,?)", strings.Repeat("c", 64), strings.Repeat("d", 64), []byte("012345678901"), []byte("preserve"))
			}

			err := schema.Initialize(ctx, db, "sqlite")
			if mode == "journal-fault" {
				if err == nil || !strings.Contains(err.Error(), "opaque-journal-fault") {
					t.Fatal("journal fault was not observed", err)
				}
				s3Marker(t, db, 12)
				var count int
				if err = db.QueryRow("SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name LIKE 'opaque_migration_%'").Scan(&count); err != nil || count != 0 {
					t.Fatal("SQLite ledger DDL was not rolled back", count, err)
				}
				opaqueLedgerExec(t, db, "DROP TRIGGER fail_opaque_journal")
				err = schema.Initialize(ctx, db, "sqlite")
			}
			if mode == "index" || mode == "journal" || mode == "partial-data" || mode == "protected" {
				if err == nil {
					t.Fatal("unresolved or incompatible Gen12 state accepted")
				}
				s3Marker(t, db, 12)
				switch mode {
				case "partial-data":
					var sealed []byte
					if err = db.QueryRow("SELECT intent_sealed FROM opaque_migration_tasks").Scan(&sealed); err != nil || string(sealed) != "preserve" {
						t.Fatal("incomplete ledger data changed", err)
					}
				case "protected":
					var sealed []byte
					if err = db.QueryRow("SELECT sealed FROM legacy_read_control_intents").Scan(&sealed); err != nil || string(sealed) != "preserve" {
						t.Fatal("protected data changed", err)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			s3Marker(t, db, 13)
			if err = schema.VerifyPreparedSQLiteRuntime(ctx, db); err != nil {
				t.Fatal("prepared Gen13 verification", err)
			}
			var name, checksum, state string
			if err = db.QueryRow("SELECT migration_name,checksum FROM frontiercloud_schema_migrations WHERE generation=13").Scan(&name, &checksum); err != nil || name != migrations.OpaqueMigrationName || checksum != migrations.OpaqueMigrationChecksum {
				t.Fatal("Gen13 migration journal", err)
			}
			if err = db.QueryRow("SELECT state FROM migration_tasks WHERE task_id=?", task).Scan(&state); err != nil || state != "queued" {
				t.Fatal("existing migration task changed", err)
			}
		})
	}
}

func TestOpaqueMigrationSQLiteLedgerConstraintsAndReopen(t *testing.T) {
	ctx := context.Background()
	db := opaqueMigrationGenerationTwelve(t)
	if err := schema.Initialize(ctx, db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	task, other := strings.Repeat("a", 32), strings.Repeat("b", 32)
	unit, secondUnit := strings.Repeat("1", 64), strings.Repeat("2", 64)
	parent, alias := strings.Repeat("3", 64), strings.Repeat("4", 64)
	sealed := []byte("opaque fixture")
	insertTask := "INSERT INTO opaque_migration_tasks(task_id,intent_encryption_id,intent_sealed) VALUES(?,?,?)"
	insertUnit := "INSERT INTO opaque_migration_units(task_id,unit_id,parent_index,active_parent_index,state,object_count,total_bytes,encryption_id,sealed) VALUES(?,?,?,?,'pending',1,0,?,?)"
	insertObject := "INSERT INTO opaque_migration_objects(task_id,unit_id,object_index,retired_alias_index,state,expected_bytes,updated_at,encryption_id,sealed) VALUES(?,?,?,?,?,0,1,?,?)"
	reject := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(query, args...); err == nil {
			t.Fatal("invalid ledger state accepted", query)
		}
	}

	reject(insertTask, task, strings.Repeat("a", 64), sealed)
	opaqueCommonTask(t, db, task)
	opaqueCommonTask(t, db, other)
	opaqueLedgerExec(t, db, insertTask, task, strings.Repeat("a", 64), sealed)
	opaqueLedgerExec(t, db, insertTask, other, strings.Repeat("b", 64), sealed)
	opaqueLedgerExec(t, db, insertUnit, task, unit, parent, parent, strings.Repeat("c", 64), sealed)
	reject(insertUnit, other, secondUnit, parent, parent, strings.Repeat("d", 64), sealed)
	opaqueLedgerExec(t, db, insertUnit, other, secondUnit, parent, nil, strings.Repeat("d", 64), sealed)
	reject(insertObject, other, unit, strings.Repeat("5", 64), nil, "pending", strings.Repeat("e", 64), sealed)
	reject(insertObject, task, unit, strings.Repeat("5", 64), alias, "pending", strings.Repeat("e", 64), sealed)
	opaqueLedgerExec(t, db, insertObject, task, unit, strings.Repeat("5", 64), alias, "cleanup_pending", strings.Repeat("e", 64), sealed)
	reject(insertObject, other, secondUnit, strings.Repeat("6", 64), alias, "cleanup_pending", strings.Repeat("f", 64), sealed)
	opaqueLedgerExec(t, db, insertObject, other, secondUnit, strings.Repeat("6", 64), nil, "pending", strings.Repeat("f", 64), sealed)
	reject("UPDATE opaque_migration_objects SET receipt_sealed=? WHERE task_id=?", sealed, other)
	reject("DELETE FROM migration_tasks WHERE task_id=?", task)
	if err := schema.Initialize(ctx, db, "sqlite"); err == nil {
		t.Fatal("generic initializer accepted a live opaque ledger")
	}
	if err := schema.VerifyPreparedSQLiteRuntime(ctx, db); err != nil {
		t.Fatal("prepared reopen rejected intact opaque ledger", err)
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM opaque_migration_objects").Scan(&count); err != nil || count != 2 {
		t.Fatal("opaque ledger data changed", count, err)
	}
	opaqueLedgerExec(t, db, "DROP INDEX uq_opaque_migration_retired_alias")
	if err := schema.VerifyPreparedSQLiteRuntime(ctx, db); err == nil {
		t.Fatal("prepared reopen accepted an incompatible ledger")
	}
}
