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

func sealedGenerationNine(t *testing.T) *sql.DB {
	t.Helper()
	store, err := sqlitestore.Open(filepath.Join(t.TempDir(), "nine.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	db := store.Database()
	data, err := os.ReadFile("../../../migrations/sqlite/0009-schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Statements []string `json:"statements"`
	}
	if err = json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for _, statement := range doc.Statements {
		if _, err = db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	queries := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO frontiercloud_schema VALUES(1,9,123)`, nil},
		{`INSERT INTO frontiercloud_schema_migrations VALUES(8,?,?,123)`, []any{migrations.S3Name, migrations.S3Checksum}},
		{`INSERT INTO frontiercloud_schema_migrations VALUES(9,?,?,123)`, []any{migrations.PublicRoutingName, migrations.PublicRoutingChecksum}},
		{`INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES(?,'audio','music/legacy/song.mp3',?,'old','old')`, []any{strings.Repeat("a", 64), strings.Repeat("b", 64)}},
	}
	for _, q := range queries {
		if _, err = db.Exec(q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestSealedTreeGenerationNinePreservesLegacyAndStaysDormant(t *testing.T) {
	db := sealedGenerationNine(t)
	ctx := context.Background()
	for range 2 {
		if err := schema.Initialize(ctx, db, "sqlite"); err != nil {
			t.Fatal(err)
		}
	}
	s3Marker(t, db, migrations.Generation)
	var name, checksum, path string
	if err := db.QueryRow(`SELECT migration_name,checksum FROM frontiercloud_schema_migrations WHERE generation=10`).Scan(&name, &checksum); err != nil || name != migrations.SealedTreeName || checksum != migrations.SealedTreeChecksum {
		t.Fatal("journal mismatch", err)
	}
	if err := db.QueryRow(`SELECT media_path FROM media_objects WHERE media_id=?`, strings.Repeat("a", 64)).Scan(&path); err != nil || path != "music/legacy/song.mp3" {
		t.Fatal("legacy path was changed", err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_meta`).Scan(&count); err != nil || count != 0 {
		t.Fatal("tree initialized automatically", err)
	}
}

func TestSealedTreeMigrationRecoveryAndFailClosed(t *testing.T) {
	for _, mode := range []string{"partial-ddl", "foreign-columns", "journal-failure", "foreign-journal", "missing-index", "wrong-index-collation", "wrong-alias-index", "missing-journal", "nonempty"} {
		t.Run(mode, func(t *testing.T) {
			db := sealedGenerationNine(t)
			ctx := context.Background()
			statements, err := migrations.SealedTreeStatements("sqlite")
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "partial-ddl":
				_, err = db.Exec(statements[0])
			case "foreign-columns":
				_, err = db.Exec(`CREATE TABLE sealed_tree_meta(singleton INTEGER NOT NULL PRIMARY KEY)`)
			case "journal-failure":
				_, err = db.Exec(`CREATE TRIGGER block_tree BEFORE INSERT ON frontiercloud_schema_migrations WHEN NEW.generation=10 BEGIN SELECT RAISE(ABORT,'blocked'); END`)
			case "foreign-journal":
				_, err = db.Exec(`INSERT INTO frontiercloud_schema_migrations VALUES(10,'foreign','wrong',1)`)
			default:
				if err = schema.Initialize(ctx, db, "sqlite"); err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "missing-index":
					_, err = db.Exec(`DROP INDEX uq_st_records_enc`)
				case "wrong-index-collation":
					if _, err = db.Exec(`DROP INDEX uq_st_records_enc`); err == nil {
						_, err = db.Exec(`CREATE UNIQUE INDEX uq_st_records_enc ON sealed_tree_records(encryption_id COLLATE NOCASE)`)
					}
				case "wrong-alias-index":
					if _, err = db.Exec(`DROP INDEX uq_st_alias_object`); err == nil {
						_, err = db.Exec(`CREATE INDEX uq_st_alias_object ON sealed_tree_aliases(object_index)`)
					}
				case "missing-journal":
					_, err = db.Exec(`DELETE FROM frontiercloud_schema_migrations WHERE generation=10`)
				case "nonempty":
					_, err = db.Exec(`INSERT INTO sealed_tree_encryption_ids(encryption_id) VALUES(?)`, strings.Repeat("f", 64))
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			err = schema.Initialize(ctx, db, "sqlite")
			switch mode {
			case "partial-ddl":
				if err != nil {
					t.Fatal(err)
				}
				s3Marker(t, db, migrations.Generation)
			case "journal-failure":
				if err == nil {
					t.Fatal("journal failure accepted")
				}
				s3Marker(t, db, 9)
				var count int
				if err = db.QueryRow(`SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name LIKE 'sealed_tree_%'`).Scan(&count); err != nil || count != 0 {
					t.Fatal("DDL did not roll back", err)
				}
				if _, err = db.Exec(`DROP TRIGGER block_tree`); err != nil {
					t.Fatal(err)
				}
				if err = schema.Initialize(ctx, db, "sqlite"); err != nil {
					t.Fatal(err)
				}
			default:
				if err == nil {
					t.Fatal("invalid tree schema or nonempty state admitted")
				}
			}
		})
	}
}
