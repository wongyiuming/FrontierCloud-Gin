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
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

func legacyIntentGenerationTen(t *testing.T) *sql.DB {
	t.Helper()
	s, err := sqlite.Open(filepath.Join(t.TempDir(), "generation10.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	data, err := os.ReadFile("../../../migrations/sqlite/0010-schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Generation int      `json:"generation"`
		Statements []string `json:"statements"`
	}
	if err = json.Unmarshal(data, &doc); err != nil || doc.Generation != 10 {
		t.Fatal("historic schema", err)
	}
	db := s.Database()
	for _, statement := range doc.Statements {
		if _, err = db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct {
		generation     int
		name, checksum string
	}{{8, migrations.S3Name, migrations.S3Checksum}, {9, migrations.PublicRoutingName, migrations.PublicRoutingChecksum}, {10, migrations.SealedTreeName, migrations.SealedTreeChecksum}} {
		if _, err = db.Exec(`INSERT INTO frontiercloud_schema_migrations(generation,migration_name,checksum,applied_at) VALUES(?,?,?,123)`, item.generation, item.name, item.checksum); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.Exec(`INSERT INTO frontiercloud_schema(singleton,generation,created_at) VALUES(1,10,123)`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES(?,'audio','music/legacy/song.mp3',?,'old','old')`, strings.Repeat("a", 64), strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestLegacyReadIntentGenerationTenMigrationRecovery(t *testing.T) {
	for _, mode := range []string{"clean", "partial", "journal-failure", "foreign-schema", "foreign-journal", "nonempty"} {
		t.Run(mode, func(t *testing.T) {
			db := legacyIntentGenerationTen(t)
			ctx := context.Background()
			statements, err := migrations.LegacyReadIntentStatements("sqlite")
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "partial":
				_, err = db.Exec(statements[0])
			case "journal-failure":
				_, err = db.Exec(`CREATE TRIGGER fail_intent_journal BEFORE INSERT ON frontiercloud_schema_migrations WHEN NEW.generation=11 BEGIN SELECT RAISE(ABORT,'intent-journal-fault'); END`)
			case "foreign-schema":
				_, err = db.Exec(`CREATE TABLE legacy_read_control_intents(operation_id TEXT PRIMARY KEY)`)
			case "foreign-journal":
				_, err = db.Exec(`INSERT INTO frontiercloud_schema_migrations VALUES(11,'foreign','foreign',123)`)
			case "nonempty":
				for _, q := range statements {
					if _, err = db.Exec(q); err != nil {
						t.Fatal(err)
					}
				}
				_, err = db.Exec(`INSERT INTO legacy_read_control_intents VALUES(?,?,?,1,?)`, strings.Repeat("c", 64), strings.Repeat("d", 64), []byte("012345678901"), []byte("synthetic"))
			}
			if err != nil {
				t.Fatal(err)
			}
			err = schema.Initialize(ctx, db, "sqlite")
			if mode == "journal-failure" {
				if err == nil || !strings.Contains(err.Error(), "intent-journal-fault") {
					t.Fatal("journal fault not observed", err)
				}
				s3Marker(t, db, 10)
				var count int
				if e := db.QueryRow(`SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='legacy_read_control_intents'`).Scan(&count); e != nil || count != 0 {
					t.Fatal("SQLite DDL not rolled back", count, e)
				}
				if _, e := db.Exec(`DROP TRIGGER fail_intent_journal`); e != nil {
					t.Fatal(e)
				}
				err = schema.Initialize(ctx, db, "sqlite")
			}
			if mode == "foreign-schema" || mode == "foreign-journal" || mode == "nonempty" {
				if err == nil {
					t.Fatal("invalid state accepted")
				}
				s3Marker(t, db, 10)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			s3Marker(t, db, migrations.Generation)
			if err = schema.Initialize(ctx, db, "sqlite"); err != nil {
				t.Fatal("idempotent reopen", err)
			}
			var path, checksum string
			if err = db.QueryRow(`SELECT media_path FROM media_objects WHERE media_id=?`, strings.Repeat("a", 64)).Scan(&path); err != nil || path != "music/legacy/song.mp3" {
				t.Fatal("legacy row changed", err)
			}
			if err = db.QueryRow(`SELECT checksum FROM frontiercloud_schema_migrations WHERE generation=11`).Scan(&checksum); err != nil || checksum != migrations.LegacyReadIntentChecksum {
				t.Fatal("journal", err)
			}
		})
	}
}
