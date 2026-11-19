package schema_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	mysqlstore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/mysql"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/schema"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

// Each named fixture must be newly allocated by the development harness.
// This test never drops, clears, or adopts an existing database.
func TestSealedTreeMySQLGenerationNineRecovery(t *testing.T) {
	if os.Getenv("FRONTIERCLOUD_SCHEMA_TEST_MYSQL_HOST") == "" {
		t.Skip("isolated MySQL fixture not configured")
	}
	for _, mode := range []string{"preserve", "partial", "journal", "index", "prefix", "collation", "check", "nonempty"} {
		t.Run(mode, func(t *testing.T) {
			prefix := os.Getenv("FRONTIERCLOUD_SCHEMA_TEST_MYSQL_DATABASE_PREFIX")
			if !strings.HasPrefix(prefix, "fc_schema_") {
				t.Fatal("isolated schema database prefix required")
			}
			s, err := mysqlstore.Open(mysqlstore.Config{Host: os.Getenv("FRONTIERCLOUD_SCHEMA_TEST_MYSQL_HOST"), Port: 3306, Database: prefix + "tree_" + mode, User: os.Getenv("FRONTIERCLOUD_SCHEMA_TEST_MYSQL_USER"), PasswordFile: os.Getenv("FRONTIERCLOUD_SCHEMA_TEST_MYSQL_PASSWORD_FILE")})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			db := s.Database()
			var count int
			if err = db.QueryRow(`SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()`).Scan(&count); err != nil || count != 0 {
				t.Fatal("fixture database is not empty", count, err)
			}
			raw, err := os.ReadFile("../../../migrations/mysql/0009-schema.json")
			if err != nil {
				t.Fatal(err)
			}
			var old struct {
				Statements []string `json:"statements"`
			}
			if err = json.Unmarshal(raw, &old); err != nil {
				t.Fatal(err)
			}
			for _, statement := range old.Statements {
				if _, err = db.Exec(statement); err != nil {
					t.Fatal(err)
				}
			}
			for _, q := range []struct {
				sql  string
				args []any
			}{
				{`INSERT INTO frontiercloud_schema VALUES(1,9,123)`, nil},
				{`INSERT INTO frontiercloud_schema_migrations VALUES(8,?,?,123)`, []any{migrations.S3Name, migrations.S3Checksum}},
				{`INSERT INTO frontiercloud_schema_migrations VALUES(9,?,?,123)`, []any{migrations.PublicRoutingName, migrations.PublicRoutingChecksum}},
				{`INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES('historical','audio','music/old.mp3','historical-locator','2026-01-01','2026-01-01')`, nil},
			} {
				if _, err = db.Exec(q.sql, q.args...); err != nil {
					t.Fatal(err)
				}
			}
			statements, err := migrations.SealedTreeStatements("mysql")
			if err != nil || len(statements) != 21 {
				t.Fatal("canonical tree tables", err)
			}
			switch mode {
			case "partial":
				_, err = db.Exec(statements[0])
			case "journal":
				_, err = db.Exec(`CREATE TRIGGER block_tree_journal BEFORE INSERT ON frontiercloud_schema_migrations FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='fixture journal unavailable'`)
			case "index":
				if _, err = db.Exec(statements[1]); err == nil {
					_, err = db.Exec(`ALTER TABLE sealed_tree_records DROP INDEX uq_st_records_enc, ADD INDEX uq_st_records_enc(encryption_id)`)
				}
			case "prefix":
				if _, err = db.Exec(statements[1]); err == nil {
					_, err = db.Exec(`ALTER TABLE sealed_tree_records DROP INDEX uq_st_records_enc, ADD UNIQUE INDEX uq_st_records_enc(encryption_id(8))`)
				}
			case "collation":
				wrong := strings.Replace(statements[0], "COLLATE=ascii_bin", "COLLATE=ascii_general_ci", 1)
				if wrong == statements[0] {
					t.Fatal("fixture did not modify collation")
				}
				_, err = db.Exec(wrong)
			case "check":
				wrong := strings.Replace(statements[0], "CHECK(version=1)", "CHECK(version>=1)", 1)
				if wrong == statements[0] {
					t.Fatal("fixture did not modify constraint")
				}
				_, err = db.Exec(wrong)
			}
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if mode == "journal" {
				if err = schema.Initialize(ctx, db, "mysql"); err == nil {
					t.Fatal("journal failure accepted")
				}
				s3Marker(t, db, 9)
				if _, err = db.Exec(`DROP TRIGGER block_tree_journal`); err != nil {
					t.Fatal(err)
				}
			}
			err = schema.Initialize(ctx, db, "mysql")
			if mode == "index" || mode == "prefix" || mode == "collation" || mode == "check" {
				if err == nil {
					t.Fatal("foreign shape accepted")
				}
				s3Marker(t, db, 9)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			s3Marker(t, db, migrations.Generation)
			if mode == "nonempty" {
				if _, err = db.Exec(`INSERT INTO sealed_tree_encryption_ids(encryption_id) VALUES(?)`, strings.Repeat("f", 64)); err != nil {
					t.Fatal(err)
				}
				if err = schema.Initialize(ctx, db, "mysql"); err == nil {
					t.Fatal("nonempty dormant tree admitted")
				}
				return
			}
			if err = schema.Initialize(ctx, db, "mysql"); err != nil {
				t.Fatal("repeat admission", err)
			}
			var path string
			if err = db.QueryRow(`SELECT media_path FROM media_objects WHERE media_id='historical'`).Scan(&path); err != nil || path != "music/old.mp3" {
				t.Fatal("legacy data changed", err)
			}
			if mode == "preserve" {
				// The existing BLOB column must hold both old 4 KiB and new
				// fixed 32 KiB encrypted envelopes without truncation. This is a
				// schema contract, not a MySQL sealed-tree runtime test.
				old := bytes.Repeat([]byte{1}, 1+32+12+4096+16)
				wide := bytes.Repeat([]byte{2}, 1+32+12+32768+16)
				id, enc := strings.Repeat("1", 64), strings.Repeat("2", 64)
				if _, err = db.Exec(`INSERT INTO sealed_tree_facts(object_index,revision,encryption_id,sealed) VALUES(?,1,?,?)`, id, enc, old); err != nil {
					t.Fatal(err)
				}
				if _, err = db.Exec(`UPDATE sealed_tree_facts SET revision=2,sealed=? WHERE object_index=?`, wide, id); err != nil {
					t.Fatal(err)
				}
				var got []byte
				if err = db.QueryRow(`SELECT sealed FROM sealed_tree_facts WHERE object_index=?`, id).Scan(&got); err != nil || !bytes.Equal(got, wide) {
					t.Fatal("wide encrypted facts truncated", err)
				}
			}
		})
	}
}
