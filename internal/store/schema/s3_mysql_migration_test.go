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

// The harness must allocate these named databases before opting in. Never
// adopt or clear an existing database to make a migration fixture pass.
func TestS3MigrationMySQLPartialDDLAndRecovery(t *testing.T) {
	if os.Getenv("FRONTIERCLOUD_SCHEMA_TEST_MYSQL_HOST") == "" {
		t.Skip("isolated MySQL fixture not configured")
	}
	for _, mode := range []string{"preserve", "journal", "partial", "index", "check"} {
		t.Run(mode, func(t *testing.T) {
			prefix := os.Getenv("FRONTIERCLOUD_SCHEMA_TEST_MYSQL_DATABASE_PREFIX")
			if !strings.HasPrefix(prefix, "fc_schema_") {
				t.Fatal("isolated schema database prefix required")
			}
			s, err := mysqlstore.Open(mysqlstore.Config{Host: os.Getenv("FRONTIERCLOUD_SCHEMA_TEST_MYSQL_HOST"), Port: 3306, Database: prefix + "s3_" + mode, User: os.Getenv("FRONTIERCLOUD_SCHEMA_TEST_MYSQL_USER"), PasswordFile: os.Getenv("FRONTIERCLOUD_SCHEMA_TEST_MYSQL_PASSWORD_FILE")})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close() })
			db := s.Database()
			var count int
			if err = db.QueryRow("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()").Scan(&count); err != nil || count != 0 {
				t.Fatal("fixture is not a fresh database", count, err)
			}
			raw, err := os.ReadFile("../../../migrations/mysql/0007-schema.json")
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
			if _, err = db.Exec("INSERT INTO frontiercloud_schema VALUES(1,7,123)"); err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec("INSERT INTO ip_security_projection(singleton) VALUES(1)"); err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec("INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES('historical','audio','music/old.mp3','historical-locator','2026-01-01','2026-01-01')"); err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec("INSERT INTO media_playback_stats VALUES('historical','music/old.mp3',17,500000,'2026-01-01','2026-01-02')"); err != nil {
				t.Fatal(err)
			}
			all, err := migrations.Statements("mysql")
			if err != nil {
				t.Fatal(err)
			}
			var tables []string
			for _, statement := range all {
				if strings.HasPrefix(statement, "CREATE TABLE IF NOT EXISTS s3_") {
					tables = append(tables, statement)
				}
			}
			if len(tables) != 5 {
				t.Fatal("missing canonical S3 tables")
			}
			switch mode {
			case "journal":
				if _, err = db.Exec("CREATE TRIGGER block_s3_journal BEFORE INSERT ON frontiercloud_schema_migrations FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='fixture journal unavailable'"); err != nil {
					t.Fatal(err)
				}
				if err = schema.Initialize(context.Background(), db, "mysql"); err == nil {
					t.Fatal("journal fault accepted")
				}
				s3Marker(t, db, 7)
				if err = db.QueryRow("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name LIKE 's3_%'").Scan(&count); err != nil || count != 5 {
					t.Fatal("partial DDL evidence lost", count, err)
				}
				if _, err = db.Exec("DROP TRIGGER block_s3_journal"); err != nil {
					t.Fatal(err)
				}
			case "partial":
				for _, statement := range tables[:2] {
					if _, err = db.Exec(statement); err != nil {
						t.Fatal(err)
					}
				}
				if _, err = db.Exec("ALTER TABLE s3_members DROP INDEX idx_s3_member_namespace"); err != nil {
					t.Fatal(err)
				}
			case "index":
				if _, err = db.Exec(tables[0]); err != nil {
					t.Fatal(err)
				}
				if _, err = db.Exec("ALTER TABLE s3_members DROP INDEX idx_s3_member_namespace, ADD INDEX idx_s3_member_namespace(name)"); err != nil {
					t.Fatal(err)
				}
			case "check":
				wrong := strings.Replace(tables[0], "cleanup_only IN (0,1)", "cleanup_only IN (0,1,2)", 1)
				if wrong == tables[0] {
					t.Fatal("fixture constraint was not changed")
				}
				if _, err = db.Exec(wrong); err != nil {
					t.Fatal(err)
				}
			}
			err = schema.Initialize(context.Background(), db, "mysql")
			if mode == "index" || mode == "check" {
				if err == nil {
					t.Fatal("foreign partial schema adopted")
				}
				s3Marker(t, db, 7)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			s3Marker(t, db, 8)
			if err = schema.Initialize(context.Background(), db, "mysql"); err != nil {
				t.Fatal("idempotent admission failed", err)
			}
			var name, checksum string
			if err = db.QueryRow("SELECT migration_name,checksum FROM frontiercloud_schema_migrations WHERE generation=8").Scan(&name, &checksum); err != nil || name != migrations.S3Name || checksum != migrations.S3Checksum {
				t.Fatal(name, checksum, err)
			}
			var path string
			var score, preference int
			if err = db.QueryRow("SELECT m.media_path,s.play_score,s.preference FROM media_objects m JOIN media_playback_stats s ON s.media_id=m.media_id WHERE m.media_id='historical'").Scan(&path, &score, &preference); err != nil || path != "music/old.mp3" || score != 17 || preference != 500000 {
				t.Fatal("historical facts changed", path, score, preference, err)
			}
			if _, err = db.Exec("UPDATE frontiercloud_schema SET generation=9"); err != nil {
				t.Fatal(err)
			}
			if err = schema.Initialize(context.Background(), db, "mysql"); err == nil {
				t.Fatal("downgrade accepted")
			}
		})
	}
}
