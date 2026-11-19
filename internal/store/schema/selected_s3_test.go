package schema_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/schema"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
	_ "modernc.org/sqlite"
)

func TestSelectedS3SchemaSQLiteRejectsIncompatibleAndPreservesOpaqueRows(t *testing.T) {
	for _, mode := range []string{"valid", "missing_index", "wrong_primary", "descending_index"} {
		t.Run(mode, func(t *testing.T) {
			db, err := sql.Open("sqlite", "file::memory:?cache=private")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			conn, err := db.Conn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			statements, err := migrations.SelectedS3Statements("sqlite")
			if err != nil {
				t.Fatal(err)
			}
			for _, stmt := range statements {
				if mode == "wrong_primary" && strings.HasPrefix(stmt, "CREATE TABLE IF NOT EXISTS selected_s3_parts") {
					stmt = strings.Replace(stmt, "PRIMARY KEY (operation_index,part_index)", "PRIMARY KEY (part_index,operation_index)", 1)
				}
				if mode == "missing_index" && strings.Contains(stmt, "uq_selected_s3_part_encryption") {
					continue
				}
				if mode == "descending_index" && strings.Contains(stmt, "idx_selected_s3_upload_state") {
					stmt = strings.Replace(stmt, "state,operation_index", "state DESC,operation_index", 1)
				}
				if _, err = conn.ExecContext(context.Background(), stmt); err != nil {
					t.Fatal(err)
				}
			}
			err = schema.ValidateSelectedS3Schema(context.Background(), conn, "sqlite")
			if mode != "valid" {
				if err == nil {
					t.Fatal("incompatible schema accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			op, part, encryption := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
			if _, err = conn.ExecContext(context.Background(), `INSERT INTO selected_s3_uploads(operation_index,encryption_id,sealed,state) VALUES(?,?,?,'pending')`, op, encryption, []byte("opaque")); err != nil {
				t.Fatal(err)
			}
			if _, err = conn.ExecContext(context.Background(), `INSERT INTO selected_s3_parts(operation_index,part_index,encryption_id,sealed) VALUES(?,?,?,?)`, op, part, strings.Repeat("d", 64), []byte("sealed")); err != nil {
				t.Fatal(err)
			}
			if _, err = conn.ExecContext(context.Background(), `INSERT INTO selected_s3_parts(operation_index,part_index,encryption_id,sealed) VALUES(?,?,?,?)`, op, part, strings.Repeat("e", 64), []byte("other")); err == nil {
				t.Fatal("duplicate part accepted")
			}
			if _, err = conn.ExecContext(context.Background(), `UPDATE selected_s3_uploads SET state='unknown' WHERE operation_index=?`, op); err == nil {
				t.Fatal("unknown terminal state accepted")
			}
			if err = schema.ValidateSelectedS3Schema(context.Background(), conn, "sqlite"); err != nil {
				t.Fatal("validation changed existing journal", err)
			}
		})
	}
	if _, err := migrations.SelectedS3Statements("unsupported"); err == nil {
		t.Fatal("unknown backend accepted")
	}
}

func TestSelectedS3SQLiteMigrationAndPreparedAdmission(t *testing.T) {
	ctx := context.Background()
	statements, err := migrations.SelectedS3Statements("sqlite")
	if err != nil || len(statements) != 5 {
		t.Fatal("selected S3 migration statements", err)
	}
	t.Run("resume empty partial journal", func(t *testing.T) {
		db := selectedUploadGenerationEleven(t)
		if _, err := db.Exec(statements[0]); err != nil {
			t.Fatal(err)
		}
		if err := schema.Initialize(ctx, db, "sqlite"); err != nil {
			t.Fatal(err)
		}
		if err := schema.VerifyPreparedSQLiteRuntime(ctx, db); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`DROP INDEX uq_selected_s3_part_encryption`); err != nil {
			t.Fatal(err)
		}
		if err := schema.VerifyPreparedSQLiteRuntime(ctx, db); err == nil {
			t.Fatal("prepared SQLite admitted an incomplete S3 journal")
		}
		var indexCount int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_schema WHERE name='uq_selected_s3_part_encryption'`).Scan(&indexCount); err != nil || indexCount != 0 {
			t.Fatal("prepared schema admission changed the damaged database", indexCount, err)
		}
	})
	t.Run("retain unresolved S3 parts", func(t *testing.T) {
		db := selectedUploadGenerationEleven(t)
		for _, statement := range statements {
			if _, err := db.Exec(statement); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := db.Exec(`INSERT INTO selected_s3_parts(operation_index,part_index,encryption_id,sealed) VALUES(?,?,?,?)`, strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), []byte("unresolved")); err != nil {
			t.Fatal(err)
		}
		if err := schema.Initialize(ctx, db, "sqlite"); err == nil || !strings.Contains(err.Error(), "selected S3 multipart journals require offline recovery") {
			t.Fatal("migration accepted unresolved S3 state", err)
		}
		s3Marker(t, db, 11)
		var sealed []byte
		if err := db.QueryRow(`SELECT sealed FROM selected_s3_parts`).Scan(&sealed); err != nil || string(sealed) != "unresolved" {
			t.Fatal("migration changed the unresolved record", err)
		}
	})
}
