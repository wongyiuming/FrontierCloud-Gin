package schema_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	mysqlstore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/mysql"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/schema"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

// MySQL uses newly allocated, explicitly named test databases only. These
// tests never delete/adopt existing tables to make a fixture pass.
func TestResourceMigrationGenerationFourUpgrade(t *testing.T) {
	backends := []string{"sqlite"}
	if os.Getenv("FRONTIERCLOUD_SCHEMA_TEST_MYSQL_HOST") != "" {
		backends = append(backends, "mysql")
	}
	for _, startGeneration := range []int{4, 5} {
		for _, backend := range backends {
			for _, interrupted := range []bool{false, true} {
				name := "preserve"
				if interrupted {
					name = "interrupted"
				}
				if startGeneration == 5 {
					name = "bindings" + name
				}
				t.Run(backend+"/"+name, func(t *testing.T) {
					ctx := context.Background()
					var db *sql.DB
					if backend == "sqlite" {
						s, e := sqlitestore.Open(filepath.Join(t.TempDir(), "old.db"))
						if e != nil {
							t.Fatal(e)
						}
						t.Cleanup(func() { s.Close() })
						db = s.Database()
					} else {
						prefix := os.Getenv("FRONTIERCLOUD_SCHEMA_TEST_MYSQL_DATABASE_PREFIX")
						if !strings.HasPrefix(prefix, "fc_schema_") {
							t.Fatal("isolated schema database prefix required")
						}
						s, e := mysqlstore.Open(mysqlstore.Config{Host: os.Getenv("FRONTIERCLOUD_SCHEMA_TEST_MYSQL_HOST"), Port: 3306, Database: prefix + name, User: os.Getenv("FRONTIERCLOUD_SCHEMA_TEST_MYSQL_USER"), PasswordFile: os.Getenv("FRONTIERCLOUD_SCHEMA_TEST_MYSQL_PASSWORD_FILE")})
						if e != nil {
							t.Fatal(e)
						}
						t.Cleanup(func() { s.Close() })
						db = s.Database()
						var count int
						if e = db.QueryRow("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()").Scan(&count); e != nil || count != 0 {
							t.Fatal("schema fixture must be empty", count, e)
						}
					}
					raw, e := os.ReadFile(fmt.Sprintf("../../../migrations/%s/%04d-schema.json", backend, startGeneration))
					if e != nil {
						t.Fatal(e)
					}
					var old struct {
						Statements []string `json:"statements"`
					}
					if e = json.Unmarshal(raw, &old); e != nil {
						t.Fatal(e)
					}
					for _, statement := range old.Statements {
						if _, e = db.Exec(statement); e != nil {
							t.Fatal(e)
						}
					}
					for _, statement := range []string{
						fmt.Sprintf("INSERT INTO frontiercloud_schema VALUES(1,%d,123)", startGeneration),
						"INSERT INTO ip_security_projection(singleton) VALUES(1)",
						"INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES ('historical-id','audio','music/old/a.mp3','historical-locator','2026-01-01','2026-01-01')",
						"INSERT INTO media_playback_stats VALUES('historical-id','music/old/a.mp3',7,500000,'2026-01-01','2026-01-02')",
					} {
						if _, e = db.Exec(statement); e != nil {
							t.Fatal(e)
						}
					}
					if startGeneration == 5 {
						if _, e = db.Exec("INSERT INTO frontiercloud_schema_migrations VALUES (5,?,?,123)", migrations.ResourceMigrationName, migrations.ResourceMigrationChecksum); e != nil {
							t.Fatal(e)
						}
					}
					if interrupted {
						trigger := fmt.Sprintf("CREATE TRIGGER block_resource_journal BEFORE INSERT ON frontiercloud_schema_migrations WHEN NEW.generation=%d BEGIN SELECT RAISE(ABORT,'journal unavailable'); END", startGeneration+1)
						if backend == "mysql" {
							trigger = "CREATE TRIGGER block_resource_journal BEFORE INSERT ON frontiercloud_schema_migrations FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='journal unavailable'"
						}
						if _, e = db.Exec(trigger); e != nil {
							t.Fatal(e)
						}
						if e = schema.Initialize(ctx, db, backend); e == nil {
							t.Fatal("journal fault admitted")
						}
						var generation int
						if e = db.QueryRow("SELECT generation FROM frontiercloud_schema").Scan(&generation); e != nil || generation != startGeneration {
							t.Fatal("marker advanced before journal", generation, e)
						}
						table := "migration_tasks"
						if startGeneration == 5 {
							table = "migration_peer_bindings"
						}
						if backend == "sqlite" {
							var count int
							if e = db.QueryRow("SELECT COUNT(*) FROM sqlite_schema WHERE name=?", table).Scan(&count); e != nil || count != 0 {
								t.Fatal("SQLite DDL did not roll back", count, e)
							}
						} else {
							var count int
							if e = db.QueryRow("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=?", table).Scan(&count); e != nil || count != 1 {
								t.Fatal("MySQL resumable DDL fixture missing", count, e)
							}
						}
						if _, e = db.Exec("DROP TRIGGER block_resource_journal"); e != nil {
							t.Fatal(e)
						}
					}
					if e = schema.Initialize(ctx, db, backend); e != nil {
						t.Fatal(e)
					}
					if e = schema.Initialize(ctx, db, backend); e != nil {
						t.Fatal("idempotency", e)
					}
					var generation int
					var checksum string
					if e = db.QueryRow("SELECT generation FROM frontiercloud_schema").Scan(&generation); e != nil || generation != migrations.Generation {
						t.Fatal(generation, e)
					}
					if e = db.QueryRow("SELECT checksum FROM frontiercloud_schema_migrations WHERE generation=5").Scan(&checksum); e != nil || checksum != migrations.ResourceMigrationChecksum {
						t.Fatal(checksum, e)
					}
					var migrationName string
					if e = db.QueryRow("SELECT migration_name,checksum FROM frontiercloud_schema_migrations WHERE generation=6").Scan(&migrationName, &checksum); e != nil || migrationName != migrations.PeerBindingsName || checksum != migrations.PeerBindingsChecksum {
						t.Fatal("generation-6 journal identity", migrationName, checksum, e)
					}
					var id, path string
					var score, preference int
					if e = db.QueryRow("SELECT m.media_id,m.media_path,s.play_score,s.preference FROM media_objects m JOIN media_playback_stats s ON s.media_id=m.media_id WHERE m.path_locator='historical-locator'").Scan(&id, &path, &score, &preference); e != nil || id != "historical-id" || path != "music/old/a.mp3" || score != 7 || preference != 500000 {
						t.Fatal("historical facts changed", id, path, score, preference, e)
					}
					if _, e = db.Exec("INSERT INTO migration_runners(task_id,runner_id,epoch,expires_at) VALUES ('task','runner',1,1)"); e != nil {
						t.Fatal(e)
					}
					if _, e = db.Exec("INSERT INTO migration_runners(task_id,runner_id,epoch,expires_at) VALUES ('task','other',2,2)"); e == nil {
						t.Fatal("duplicate task runner admitted")
					}
					if _, e = db.Exec("INSERT INTO migration_capacity(task_id,member_id,reserved_bytes,updated_at) VALUES ('task','target',-1,1)"); e == nil {
						t.Fatal("negative reservation admitted")
					}
					if _, e = db.Exec("UPDATE frontiercloud_schema SET generation=7"); e != nil {
						t.Fatal(e)
					}
					if e = schema.Initialize(ctx, db, backend); e == nil {
						t.Fatal("future schema accepted")
					}
				})
			}
		}
	}
}
