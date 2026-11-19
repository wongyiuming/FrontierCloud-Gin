package schema_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	mysqlstore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/mysql"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/schema"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

// Each mode requires a newly allocated, isolated MySQL schema.
func TestSelectedUploadMySQLGenerationElevenRecovery(t *testing.T) {
	host := os.Getenv("FRONTIERCLOUD_SCHEMA_TEST_MYSQL_HOST")
	if host == "" {
		t.Skip("isolated MySQL schema fixture not configured")
	}
	prefix := os.Getenv("FRONTIERCLOUD_SCHEMA_TEST_MYSQL_DATABASE_PREFIX")
	if !strings.HasPrefix(prefix, "fc_schema_") {
		t.Fatal("isolated schema database prefix required")
	}
	for _, mode := range []string{"clean", "partial", "partialcancel", "journal", "index", "foreignjournal", "priorintent", "newintent", "newcancel", "partials3", "newparts3"} {
		t.Run(mode, func(t *testing.T) {
			s, err := mysqlstore.Open(mysqlstore.Config{Host: host, Port: 3306, Database: prefix + "selected_" + mode, User: os.Getenv("FRONTIERCLOUD_SCHEMA_TEST_MYSQL_USER"), PasswordFile: os.Getenv("FRONTIERCLOUD_SCHEMA_TEST_MYSQL_PASSWORD_FILE")})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			db := s.Database()
			var count int
			if err = db.QueryRow(`SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()`).Scan(&count); err != nil || count != 0 {
				t.Fatal("fixture database not empty", count, err)
			}
			raw, err := os.ReadFile("../../../migrations/mysql/0011-schema.json")
			if err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Generation int      `json:"generation"`
				Statements []string `json:"statements"`
			}
			if err = json.Unmarshal(raw, &doc); err != nil || doc.Generation != 11 {
				t.Fatal("historic schema", err)
			}
			for _, q := range doc.Statements {
				if _, err = db.Exec(q); err != nil {
					t.Fatal(err)
				}
			}
			for _, q := range []struct {
				query string
				args  []any
			}{
				{`INSERT INTO frontiercloud_schema VALUES(1,11,123)`, nil},
				{`INSERT INTO frontiercloud_schema_migrations VALUES(8,?,?,123)`, []any{migrations.S3Name, migrations.S3Checksum}},
				{`INSERT INTO frontiercloud_schema_migrations VALUES(9,?,?,123)`, []any{migrations.PublicRoutingName, migrations.PublicRoutingChecksum}},
				{`INSERT INTO frontiercloud_schema_migrations VALUES(10,?,?,123)`, []any{migrations.SealedTreeName, migrations.SealedTreeChecksum}},
				{`INSERT INTO frontiercloud_schema_migrations VALUES(11,?,?,123)`, []any{migrations.LegacyReadIntentName, migrations.LegacyReadIntentChecksum}},
				{`INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES('historical','audio','music/legacy/song.mp3','historic-locator','2026-01-01','2026-01-01')`, nil},
			} {
				if _, err = db.Exec(q.query, q.args...); err != nil {
					t.Fatal(err)
				}
			}
			statements, err := migrations.SelectedUploadIntentStatements("mysql")
			if err != nil || len(statements) < 3 || !strings.HasPrefix(statements[2], "CREATE TABLE IF NOT EXISTS selected_upload_cancellations ") {
				t.Fatal("canonical DDL", err)
			}
			switch mode {
			case "partial", "index", "newintent":
				_, err = db.Exec(statements[0])
				if err == nil && mode == "index" {
					_, err = db.Exec(`ALTER TABLE selected_upload_intents DROP INDEX uq_selected_upload_blob, ADD INDEX uq_selected_upload_blob(blob_index)`)
				}
				if err == nil && mode == "newintent" {
					_, err = db.Exec(`INSERT INTO selected_upload_intents(operation_index,upload_index,member_index,parent_index,blob_index,encryption_id,sealed) VALUES(?,?,?,?,?,?,?)`, strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("f", 64), strings.Repeat("d", 64), strings.Repeat("e", 64), []byte("sealed"))
				}
			case "partialcancel", "newcancel":
				_, err = db.Exec(statements[2])
				if err == nil && mode == "newcancel" {
					_, err = db.Exec(`INSERT INTO selected_upload_cancellations(operation_id,object_index,blob_index,cancellation_mac) VALUES(?,?,?,?)`, strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64))
				}
			case "partials3", "newparts3":
				s3, e := migrations.SelectedS3Statements("mysql")
				if e != nil || len(s3) != 2 {
					t.Fatal("canonical S3 DDL", e)
				}
				_, err = db.Exec(s3[0])
				if err == nil && mode == "newparts3" {
					if _, err = db.Exec(s3[1]); err == nil {
						_, err = db.Exec(`INSERT INTO selected_s3_parts(operation_index,part_index,encryption_id,sealed) VALUES(?,?,?,?)`, strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), []byte("sealed"))
					}
				}
			case "priorintent":
				_, err = db.Exec(`INSERT INTO legacy_read_control_intents VALUES(?,?,?,1,?)`, strings.Repeat("a", 64), strings.Repeat("b", 64), []byte("012345678901"), []byte("preserve"))
			case "journal":
				_, err = db.Exec(`CREATE TRIGGER fail_selected_journal BEFORE INSERT ON frontiercloud_schema_migrations FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='selected-journal-fault'`)
			case "foreignjournal":
				_, err = db.Exec(`INSERT INTO frontiercloud_schema_migrations VALUES(12,'foreign','foreign',123)`)
			}
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			err = schema.Initialize(ctx, db, "mysql")
			if mode == "journal" {
				if err == nil || !strings.Contains(err.Error(), "selected-journal-fault") {
					t.Fatal("journal fault not observed", err)
				}
				s3Marker(t, db, 11)
				if _, err = db.Exec(`DROP TRIGGER fail_selected_journal`); err != nil {
					t.Fatal(err)
				}
				err = schema.Initialize(ctx, db, "mysql")
			}
			if mode == "index" || mode == "foreignjournal" || mode == "priorintent" || mode == "newintent" || mode == "newcancel" || mode == "newparts3" {
				if err == nil {
					t.Fatal("incompatible or unresolved intent accepted")
				}
				s3Marker(t, db, 11)
				if mode == "priorintent" || mode == "newintent" || mode == "newcancel" || mode == "newparts3" {
					table := "legacy_read_control_intents"
					if mode == "newintent" {
						table = "selected_upload_intents"
					}
					if mode == "newcancel" {
						table = "selected_upload_cancellations"
					}
					if mode == "newparts3" {
						table = "selected_s3_parts"
					}
					if e := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); e != nil || count != 1 {
						t.Fatal("intent lost", count, e)
					}
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				s3Marker(t, db, migrations.Generation)
				if err = schema.Initialize(ctx, db, "mysql"); err != nil {
					t.Fatal("repeat admission", err)
				}
				var checksum string
				if err = db.QueryRow(`SELECT checksum FROM frontiercloud_schema_migrations WHERE generation=12`).Scan(&checksum); err != nil || checksum != migrations.SelectedUploadIntentChecksum {
					t.Fatal("journal mismatch", err)
				}
			}
			var path string
			if err = db.QueryRow(`SELECT media_path FROM media_objects WHERE media_id='historical'`).Scan(&path); err != nil || path != "music/legacy/song.mp3" {
				t.Fatal("media changed", err)
			}
		})
	}
}
