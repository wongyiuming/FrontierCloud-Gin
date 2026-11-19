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

// Each mode requires a newly allocated isolated schema from the test harness.
func TestLegacyReadIntentMySQLGenerationTenRecovery(t *testing.T) {
	host := os.Getenv("FRONTIERCLOUD_SCHEMA_TEST_MYSQL_HOST")
	if host == "" {
		t.Skip("isolated MySQL schema fixture not configured")
	}
	prefix := os.Getenv("FRONTIERCLOUD_SCHEMA_TEST_MYSQL_DATABASE_PREFIX")
	if !strings.HasPrefix(prefix, "fc_schema_") {
		t.Fatal("isolated schema database prefix required")
	}
	for _, mode := range []string{"clean", "partial", "journal", "index", "foreignjournal", "nonempty"} {
		t.Run(mode, func(t *testing.T) {
			s, err := mysqlstore.Open(mysqlstore.Config{Host: host, Port: 3306, Database: prefix + "intent_" + mode, User: os.Getenv("FRONTIERCLOUD_SCHEMA_TEST_MYSQL_USER"), PasswordFile: os.Getenv("FRONTIERCLOUD_SCHEMA_TEST_MYSQL_PASSWORD_FILE")})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			db := s.Database()
			var count int
			if err = db.QueryRow(`SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()`).Scan(&count); err != nil || count != 0 {
				t.Fatal("fixture database is not empty", count, err)
			}
			raw, err := os.ReadFile("../../../migrations/mysql/0010-schema.json")
			if err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Generation int      `json:"generation"`
				Statements []string `json:"statements"`
			}
			if err = json.Unmarshal(raw, &doc); err != nil || doc.Generation != 10 {
				t.Fatal("historical generation", err)
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
				{`INSERT INTO frontiercloud_schema VALUES(1,10,123)`, nil},
				{`INSERT INTO frontiercloud_schema_migrations VALUES(8,?,?,123)`, []any{migrations.S3Name, migrations.S3Checksum}},
				{`INSERT INTO frontiercloud_schema_migrations VALUES(9,?,?,123)`, []any{migrations.PublicRoutingName, migrations.PublicRoutingChecksum}},
				{`INSERT INTO frontiercloud_schema_migrations VALUES(10,?,?,123)`, []any{migrations.SealedTreeName, migrations.SealedTreeChecksum}},
				{`INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES('historical','audio','music/legacy/song.mp3','historic-locator','2026-01-01','2026-01-01')`, nil},
				{`INSERT INTO karaoke_users(user_id,username,username_key,password_hash,status,quota_bytes,used_bytes,created_at,updated_at) VALUES('historic-user','fixture_user','fixture_user','fixture-hash','active',42,0,123,123)`, nil},
			} {
				if _, err = db.Exec(q.query, q.args...); err != nil {
					t.Fatal(err)
				}
			}
			statements, err := migrations.LegacyReadIntentStatements("mysql")
			if err != nil || len(statements) != 1 {
				t.Fatal("canonical intent DDL", err)
			}
			switch mode {
			case "partial", "index", "nonempty":
				_, err = db.Exec(statements[0])
				if err == nil && mode == "index" {
					_, err = db.Exec(`ALTER TABLE legacy_read_control_intents DROP INDEX uq_legacy_read_control_nonce, ADD INDEX uq_legacy_read_control_nonce(nonce)`)
				}
				if err == nil && mode == "nonempty" {
					_, err = db.Exec(`INSERT INTO legacy_read_control_intents(operation_index,challenge_tag,nonce,revision,sealed) VALUES(?,?,?,1,?)`, strings.Repeat("a", 64), strings.Repeat("b", 64), []byte("012345678901"), []byte("synthetic"))
				}
			case "journal":
				_, err = db.Exec(`CREATE TRIGGER fail_intent_journal BEFORE INSERT ON frontiercloud_schema_migrations FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='intent-journal-fault'`)
			case "foreignjournal":
				_, err = db.Exec(`INSERT INTO frontiercloud_schema_migrations VALUES(11,'foreign','foreign',123)`)
			}
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			err = schema.Initialize(ctx, db, "mysql")
			if mode == "journal" {
				if err == nil || !strings.Contains(err.Error(), "intent-journal-fault") {
					t.Fatal("journal fault not observed", err)
				}
				s3Marker(t, db, 10)
				if _, err = db.Exec(`DROP TRIGGER fail_intent_journal`); err != nil {
					t.Fatal(err)
				}
				err = schema.Initialize(ctx, db, "mysql")
			}
			if mode == "index" || mode == "foreignjournal" || mode == "nonempty" {
				if err == nil {
					t.Fatal("foreign or nonempty intent accepted")
				}
				s3Marker(t, db, 10)
			} else {
				if err != nil {
					t.Fatal(err)
				}
				s3Marker(t, db, migrations.Generation)
				if err = schema.Initialize(ctx, db, "mysql"); err != nil {
					t.Fatal("repeat admission", err)
				}
				var checksum string
				if err = db.QueryRow(`SELECT checksum FROM frontiercloud_schema_migrations WHERE generation=11`).Scan(&checksum); err != nil || checksum != migrations.LegacyReadIntentChecksum {
					t.Fatal("journal mismatch", err)
				}
			}
			var path, user, hash string
			if err = db.QueryRow(`SELECT media_path FROM media_objects WHERE media_id='historical'`).Scan(&path); err != nil || path != "music/legacy/song.mp3" {
				t.Fatal("media changed", err)
			}
			if err = db.QueryRow(`SELECT username,password_hash FROM karaoke_users WHERE user_id='historic-user'`).Scan(&user, &hash); err != nil || user != "fixture_user" || hash != "fixture-hash" {
				t.Fatal("account changed", err)
			}
		})
	}
}
