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

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/schema"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

func s3GenerationSeven(t *testing.T) *sql.DB {
	t.Helper()
	s, err := sqlitestore.Open(filepath.Join(t.TempDir(), "seven.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	db := s.Database()
	raw, err := os.ReadFile("../../../migrations/sqlite/0007-schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var snapshot struct {
		Statements []string `json:"statements"`
	}
	if err = json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	for _, statement := range snapshot.Statements {
		if _, err = db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	for _, statement := range []string{
		"INSERT INTO frontiercloud_schema VALUES(1,7,123)",
		"INSERT INTO ip_security_projection(singleton) VALUES(1)",
		"INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES('historical','audio','music/old.mp3','locator','2026-01-01','2026-01-01')",
		"INSERT INTO media_playback_stats VALUES('historical','music/old.mp3',17,500000,'2026-01-01','2026-01-02')",
	} {
		if _, err = db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func s3Statements(t *testing.T) []string {
	t.Helper()
	all, err := migrations.Statements("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	var result []string
	for _, statement := range all {
		if strings.Contains(statement, " s3_") {
			result = append(result, statement)
		}
	}
	return result
}

func s3Marker(t *testing.T, db *sql.DB, expected int) {
	t.Helper()
	var generation int
	if err := db.QueryRow("SELECT generation FROM frontiercloud_schema").Scan(&generation); err != nil || generation != expected {
		t.Fatal("generation", generation, err)
	}
}

func TestS3MigrationSevenPreservesFactsAndJournal(t *testing.T) {
	db := s3GenerationSeven(t)
	for run := 0; run < 2; run++ {
		if err := schema.Initialize(context.Background(), db, "sqlite"); err != nil {
			t.Fatal(err)
		}
	}
	s3Marker(t, db, 8)
	var name, checksum, path string
	var score, preference, applied int
	if err := db.QueryRow("SELECT migration_name,checksum,applied_at FROM frontiercloud_schema_migrations WHERE generation=8").Scan(&name, &checksum, &applied); err != nil || name != migrations.S3Name || checksum != migrations.S3Checksum || applied < 1 {
		t.Fatal(name, checksum, applied, err)
	}
	if err := db.QueryRow("SELECT m.media_path,s.play_score,s.preference FROM media_objects m JOIN media_playback_stats s ON s.media_id=m.media_id WHERE m.media_id='historical'").Scan(&path, &score, &preference); err != nil || path != "music/old.mp3" || score != 17 || preference != 500000 {
		t.Fatal("historical facts changed", path, score, preference, err)
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name LIKE 's3_%'").Scan(&count); err != nil || count != 5 {
		t.Fatal(count, err)
	}
}

func TestS3MigrationInterruptedAndPartialDDLRepair(t *testing.T) {
	for _, mode := range []string{"journal-rollback", "two-tables", "missing-indexes"} {
		t.Run(mode, func(t *testing.T) {
			db := s3GenerationSeven(t)
			if mode == "journal-rollback" {
				if _, err := db.Exec("CREATE TRIGGER block_s3_journal BEFORE INSERT ON frontiercloud_schema_migrations WHEN NEW.generation=8 BEGIN SELECT RAISE(ABORT,'journal unavailable'); END"); err != nil {
					t.Fatal(err)
				}
				if err := schema.Initialize(context.Background(), db, "sqlite"); err == nil {
					t.Fatal("fault accepted")
				}
				s3Marker(t, db, 7)
				var count int
				if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name LIKE 's3_%'").Scan(&count); err != nil || count != 0 {
					t.Fatal("DDL was not rolled back", count, err)
				}
				if _, err := db.Exec("DROP TRIGGER block_s3_journal"); err != nil {
					t.Fatal(err)
				}
			} else {
				created := 0
				for _, statement := range s3Statements(t) {
					if strings.HasPrefix(statement, "CREATE TABLE") {
						if _, err := db.Exec(statement); err != nil {
							t.Fatal(err)
						}
						created++
						if mode == "two-tables" && created == 2 {
							break
						}
					}
				}
			}
			if err := schema.Initialize(context.Background(), db, "sqlite"); err != nil {
				t.Fatal(err)
			}
			s3Marker(t, db, 8)
			var count int
			if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_schema WHERE type='index' AND (name LIKE 'idx_s3_%' OR name LIKE 'uq_s3_%')").Scan(&count); err != nil || count != 9 {
				t.Fatal("secondary indexes not repaired", count, err)
			}
		})
	}
}

func TestS3MigrationRejectsForeignShapeAndJournal(t *testing.T) {
	for _, mode := range []string{"columns", "check", "index", "journal", "missing-current-table", "missing-current-journal", "future"} {
		t.Run(mode, func(t *testing.T) {
			db := s3GenerationSeven(t)
			switch mode {
			case "columns":
				if _, err := db.Exec("CREATE TABLE s3_members(member_id TEXT NOT NULL PRIMARY KEY)"); err != nil {
					t.Fatal(err)
				}
			case "check":
				for _, statement := range s3Statements(t) {
					if strings.HasPrefix(statement, "CREATE TABLE IF NOT EXISTS s3_members") {
						statement = strings.Replace(statement, "cleanup_only IN (0,1)", "cleanup_only IN (0,1,2)", 1)
						if _, err := db.Exec(statement); err != nil {
							t.Fatal(err)
						}
						break
					}
				}
			case "index":
				for _, statement := range s3Statements(t) {
					if strings.HasPrefix(statement, "CREATE TABLE") {
						if _, err := db.Exec(statement); err != nil {
							t.Fatal(err)
						}
					}
				}
				if _, err := db.Exec("CREATE INDEX idx_s3_member_namespace ON s3_members(name)"); err != nil {
					t.Fatal(err)
				}
			case "journal":
				if _, err := db.Exec("INSERT INTO frontiercloud_schema_migrations VALUES(8,'foreign','wrong',123)"); err != nil {
					t.Fatal(err)
				}
			default:
				if err := schema.Initialize(context.Background(), db, "sqlite"); err != nil {
					t.Fatal(err)
				}
				statement := "DROP TABLE s3_objects"
				if mode == "missing-current-journal" {
					statement = "DELETE FROM frontiercloud_schema_migrations WHERE generation=8"
				}
				if mode == "future" {
					statement = fmt.Sprintf("UPDATE frontiercloud_schema SET generation=%d", migrations.Generation+1)
				}
				if _, err := db.Exec(statement); err != nil {
					t.Fatal(err)
				}
			}
			if err := schema.Initialize(context.Background(), db, "sqlite"); err == nil {
				t.Fatal("unsafe schema adopted", mode)
			}
			if mode == "columns" || mode == "check" || mode == "index" || mode == "journal" {
				s3Marker(t, db, 7)
			}
		})
	}
}
