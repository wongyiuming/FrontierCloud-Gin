package schema_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/schema"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

func routingGenerationEight(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sqlitestore.Open(filepath.Join(t.TempDir(), "eight.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	raw := db.Database()
	data, err := os.ReadFile("../../../migrations/sqlite/0008-schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var snapshot struct {
		Statements []string `json:"statements"`
	}
	if err = json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	for _, statement := range snapshot.Statements {
		if _, err = raw.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	master, object := strings.Repeat("a", 32), strings.Repeat("b", 64)
	for _, entry := range []struct {
		query string
		args  []any
	}{
		{"INSERT INTO frontiercloud_schema VALUES(1,8,123)", nil},
		{"INSERT INTO frontiercloud_schema_migrations VALUES(8,?,?,123)", []any{migrations.S3Name, migrations.S3Checksum}},
		{"INSERT INTO node_identity VALUES(1,?,'Master','https://master.test','sealed',123)", []any{master}},
		{"INSERT INTO cluster_storage_members VALUES(?,NULL,'MasterLocal','Local',1,1073741824,9,0,100,'online',1,123)", []any{master}},
		{"INSERT INTO global_media_objects VALUES(?,?,?,?,?,'audio',9,'etag','active',123,124)", []any{object, master, object, "music/old/song.mp3", strings.Repeat("c", 64)}},
	} {
		if _, err = raw.Exec(entry.query, entry.args...); err != nil {
			t.Fatal(err)
		}
	}
	return raw
}

func routingSchemaStatements(t *testing.T) []string {
	t.Helper()
	statements, err := migrations.Statements("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	var result []string
	for _, statement := range statements {
		if strings.HasPrefix(statement, "CREATE TABLE IF NOT EXISTS public_ingress_config") || strings.HasPrefix(statement, "CREATE TABLE IF NOT EXISTS native_transport_policy") {
			result = append(result, statement)
		}
	}
	if len(result) != 2 {
		t.Fatal("missing routing schema statements", len(result))
	}
	return result
}

func TestPublicRoutingGenerationEightPreservesOwnershipAndDoesNotGuessPolicy(t *testing.T) {
	db := routingGenerationEight(t)
	ctx := context.Background()
	for range 2 {
		if err := schema.Initialize(ctx, db, "sqlite"); err != nil {
			t.Fatal(err)
		}
	}
	s3Marker(t, db, migrations.Generation)
	var name, checksum, owner, object, path, kind, transport string
	var count int
	if err := db.QueryRow("SELECT migration_name,checksum FROM frontiercloud_schema_migrations WHERE generation=9").Scan(&name, &checksum); err != nil || name != migrations.PublicRoutingName || checksum != migrations.PublicRoutingChecksum {
		t.Fatal("routing journal", name, checksum, err)
	}
	if err := db.QueryRow("SELECT g.storage_member_id,g.object_id,g.media_path,s.member_kind,s.transport FROM global_media_objects g JOIN cluster_storage_members s ON s.member_id=g.storage_member_id").Scan(&owner, &object, &path, &kind, &transport); err != nil || owner != strings.Repeat("a", 32) || object != strings.Repeat("b", 64) || path != "music/old/song.mp3" || kind != "MasterLocal" || transport != "Local" {
		t.Fatal("historical object changed", owner, object, path, kind, transport, err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM native_transport_policy").Scan(&count); err != nil || count != 0 {
		t.Fatal("migration guessed policy", count, err)
	}
}

func TestPublicRoutingMigrationInterruptedAndForeignSchema(t *testing.T) {
	for _, mode := range []string{"journal-failure", "partial-ddl", "foreign-columns", "foreign-check", "foreign-journal", "missing-current-table", "missing-current-journal", "future"} {
		t.Run(mode, func(t *testing.T) {
			db := routingGenerationEight(t)
			ctx := context.Background()
			switch mode {
			case "journal-failure":
				if _, err := db.Exec("CREATE TRIGGER block_public_journal BEFORE INSERT ON frontiercloud_schema_migrations WHEN NEW.generation=9 BEGIN SELECT RAISE(ABORT,'journal unavailable'); END"); err != nil {
					t.Fatal(err)
				}
				if err := schema.Initialize(ctx, db, "sqlite"); err == nil {
					t.Fatal("journal failure admitted")
				}
				s3Marker(t, db, 8)
				var count int
				if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name IN ('public_ingress_config','native_transport_policy')").Scan(&count); err != nil || count != 0 {
					t.Fatal("SQLite DDL did not roll back", count, err)
				}
				if _, err := db.Exec("DROP TRIGGER block_public_journal"); err != nil {
					t.Fatal(err)
				}
			case "partial-ddl":
				if _, err := db.Exec(routingSchemaStatements(t)[0]); err != nil {
					t.Fatal(err)
				}
			case "foreign-columns":
				if _, err := db.Exec("CREATE TABLE public_ingress_config(singleton INTEGER NOT NULL PRIMARY KEY)"); err != nil {
					t.Fatal(err)
				}
			case "foreign-check":
				statement := strings.Replace(routingSchemaStatements(t)[0], "generation>0", "generation>=0", 1)
				if _, err := db.Exec(statement); err != nil {
					t.Fatal(err)
				}
			case "foreign-journal":
				if _, err := db.Exec("INSERT INTO frontiercloud_schema_migrations VALUES(9,'foreign','wrong',123)"); err != nil {
					t.Fatal(err)
				}
			default:
				if err := schema.Initialize(ctx, db, "sqlite"); err != nil {
					t.Fatal(err)
				}
				statement := "DROP TABLE native_transport_policy"
				if mode == "missing-current-journal" {
					statement = "DELETE FROM frontiercloud_schema_migrations WHERE generation=9"
				} else if mode == "future" {
					statement = "UPDATE frontiercloud_schema SET generation=999"
				}
				if _, err := db.Exec(statement); err != nil {
					t.Fatal(err)
				}
			}
			err := schema.Initialize(ctx, db, "sqlite")
			if mode == "journal-failure" || mode == "partial-ddl" {
				if err != nil {
					t.Fatal("valid retry failed", err)
				}
				s3Marker(t, db, migrations.Generation)
			} else if err == nil {
				t.Fatal("foreign or incomplete schema admitted", mode)
			} else if strings.HasPrefix(mode, "foreign-") {
				s3Marker(t, db, 8)
			}
		})
	}
}
