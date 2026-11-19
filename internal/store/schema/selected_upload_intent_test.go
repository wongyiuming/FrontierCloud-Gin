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

func selectedUploadGenerationEleven(t *testing.T) *sql.DB {
	t.Helper()
	s, err := sqlite.Open(filepath.Join(t.TempDir(), "generation11.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	data, err := os.ReadFile("../../../migrations/sqlite/0011-schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Generation int      `json:"generation"`
		Statements []string `json:"statements"`
	}
	if err = json.Unmarshal(data, &doc); err != nil || doc.Generation != 11 {
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
	}{{8, migrations.S3Name, migrations.S3Checksum}, {9, migrations.PublicRoutingName, migrations.PublicRoutingChecksum}, {10, migrations.SealedTreeName, migrations.SealedTreeChecksum}, {11, migrations.LegacyReadIntentName, migrations.LegacyReadIntentChecksum}} {
		if _, err = db.Exec(`INSERT INTO frontiercloud_schema_migrations(generation,migration_name,checksum,applied_at) VALUES(?,?,?,123)`, item.generation, item.name, item.checksum); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.Exec(`INSERT INTO frontiercloud_schema(singleton,generation,created_at) VALUES(1,11,123)`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES(?,'audio','music/legacy/song.mp3',?,'old','old')`, strings.Repeat("a", 64), strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestSelectedUploadGenerationElevenSQLiteRecovery(t *testing.T) {
	for _, mode := range []string{"clean", "partial", "journal-failure", "foreign-schema", "foreign-index", "foreign-journal", "prior-intent", "new-intent", "foreign-recording"} {
		t.Run(mode, func(t *testing.T) {
			db := selectedUploadGenerationEleven(t)
			ctx := context.Background()
			statements, err := migrations.SelectedUploadIntentStatements("sqlite")
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "partial", "foreign-index", "new-intent":
				_, err = db.Exec(statements[0])
				if err == nil && mode == "foreign-index" {
					_, err = db.Exec(`CREATE INDEX uq_selected_upload_blob ON selected_upload_intents(blob_index)`)
				}
				if err == nil && mode == "new-intent" {
					_, err = db.Exec(`INSERT INTO selected_upload_intents(operation_index,upload_index,member_index,parent_index,blob_index,encryption_id,sealed) VALUES(?,?,?,?,?,?,?)`, strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64), strings.Repeat("2", 64), strings.Repeat("f", 64), strings.Repeat("1", 64), []byte("sealed"))
				}
			case "journal-failure":
				_, err = db.Exec(`CREATE TRIGGER fail_selected_journal BEFORE INSERT ON frontiercloud_schema_migrations WHEN NEW.generation=12 BEGIN SELECT RAISE(ABORT,'selected-journal-fault'); END`)
			case "foreign-schema":
				_, err = db.Exec(`CREATE TABLE selected_upload_intents(operation_id TEXT PRIMARY KEY)`)
			case "foreign-recording":
				_, err = db.Exec(`CREATE TABLE sealed_recording_audio(recording_index TEXT PRIMARY KEY)`)
			case "foreign-journal":
				_, err = db.Exec(`INSERT INTO frontiercloud_schema_migrations VALUES(12,'foreign','foreign',123)`)
			case "prior-intent":
				_, err = db.Exec(`INSERT INTO legacy_read_control_intents VALUES(?,?,?,1,?)`, strings.Repeat("c", 64), strings.Repeat("d", 64), []byte("012345678901"), []byte("preserve"))
			}
			if err != nil {
				t.Fatal(err)
			}
			err = schema.Initialize(ctx, db, "sqlite")
			if mode == "journal-failure" {
				if err == nil || !strings.Contains(err.Error(), "selected-journal-fault") {
					t.Fatal("journal fault not observed", err)
				}
				s3Marker(t, db, 11)
				var count int
				if e := db.QueryRow(`SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='selected_upload_intents'`).Scan(&count); e != nil || count != 0 {
					t.Fatal("SQLite partial DDL was not rolled back", count, e)
				}
				if _, e := db.Exec(`DROP TRIGGER fail_selected_journal`); e != nil {
					t.Fatal(e)
				}
				err = schema.Initialize(ctx, db, "sqlite")
			}
			if mode == "foreign-schema" || mode == "foreign-index" || mode == "foreign-journal" || mode == "prior-intent" || mode == "new-intent" || mode == "foreign-recording" {
				if err == nil {
					t.Fatal("incompatible or unresolved state accepted")
				}
				s3Marker(t, db, 11)
				if mode == "prior-intent" || mode == "new-intent" {
					table := "legacy_read_control_intents"
					if mode == "new-intent" {
						table = "selected_upload_intents"
					}
					var count int
					if e := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); e != nil || count != 1 {
						t.Fatal("unfinished intent was lost", count, e)
					}
				}
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
			if err = db.QueryRow(`SELECT checksum FROM frontiercloud_schema_migrations WHERE generation=12`).Scan(&checksum); err != nil || checksum != migrations.SelectedUploadIntentChecksum {
				t.Fatal("journal", err)
			}
			if _, err = db.Exec(`DROP INDEX uq_sealed_recording_audio_title_enc`); err != nil {
				t.Fatal("canonical recording index was not initialized", err)
			}
			if err = schema.VerifyPreparedSQLiteRuntime(ctx, db); err == nil {
				t.Fatal("prepared runtime accepted a missing recording index")
			}
		})
	}
}
