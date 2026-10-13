package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

func TestPriorityGenerationThreeUpgradePreservesFactsAndRollsBack(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "preserve", true: "rollback"}[fail], func(t *testing.T) {
			db, err := Open(filepath.Join(t.TempDir(), "old.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			raw, err := os.ReadFile("../../../migrations/sqlite/0003-schema.json")
			if err != nil {
				t.Fatal(err)
			}
			var document struct {
				Statements []string `json:"statements"`
			}
			if err = json.Unmarshal(raw, &document); err != nil {
				t.Fatal(err)
			}
			for _, statement := range document.Statements {
				if _, err = db.database.Exec(statement); err != nil {
					t.Fatal(err)
				}
			}
			for _, statement := range []string{
				"INSERT INTO frontiercloud_schema VALUES(1,3,123)",
				"INSERT INTO media_playback_stats VALUES('directory','music/old',7,500,'2026-01-01','2026-01-02')",
				"INSERT INTO media_playback_stats VALUES('media','music/old/a.mp3',8,100,'2026-02-01','2026-02-02')",
				"CREATE INDEX keep_priority_index ON media_playback_stats(play_score)",
				"CREATE TRIGGER keep_priority_trigger AFTER UPDATE ON media_playback_stats BEGIN SELECT 1; END",
			} {
				if _, err = db.database.Exec(statement); err != nil {
					t.Fatal(err)
				}
			}
			if fail {
				if _, err = db.database.Exec("CREATE TRIGGER block_priority_migration BEFORE INSERT ON frontiercloud_schema_migrations WHEN NEW.generation=4 BEGIN SELECT RAISE(ABORT,'journal unavailable'); END"); err != nil {
					t.Fatal(err)
				}
			}
			err = db.Initialize(context.Background())
			if (err != nil) != fail {
				t.Fatal(err)
			}
			var generation int
			if err = db.database.QueryRow("SELECT generation FROM frontiercloud_schema").Scan(&generation); err != nil {
				t.Fatal(err)
			}
			want := migrations.Generation
			if fail {
				want = 3
			}
			if generation != want {
				t.Fatal(generation)
			}
			for _, id := range []string{"directory", "media"} {
				var p, created, updated string
				var score, value int
				if err = db.database.QueryRow("SELECT media_path,play_score,preference,CAST(created_at AS TEXT),CAST(updated_at AS TEXT) FROM media_playback_stats WHERE media_id=?", id).Scan(&p, &score, &value, &created, &updated); err != nil {
					t.Fatal(err)
				}
				if id == "directory" && (p != "music/old" || score != 7 || value != 500 || created != "2026-01-01" || updated != "2026-01-02") || id == "media" && (p != "music/old/a.mp3" || score != 8 || value != 100 || created != "2026-02-01" || updated != "2026-02-02") {
					t.Fatal("historical facts changed", id, p, score, value, created, updated)
				}
			}
			var count int
			if err = db.database.QueryRow("SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('keep_priority_index','keep_priority_trigger')").Scan(&count); err != nil || count != 2 {
				t.Fatal("lost index/trigger", count, err)
			}
			_, err = db.database.Exec("UPDATE media_playback_stats SET preference=500000 WHERE media_id='media'")
			if (err != nil) != fail {
				t.Fatal("range migration/rollback", err)
			}
			if fail {
				db.database.Exec("DROP TRIGGER block_priority_migration")
			}
			if err = db.Initialize(context.Background()); err != nil {
				t.Fatal("recovery/idempotency", err)
			}
			if _, err = db.database.Exec("UPDATE media_playback_stats SET preference=500001 WHERE media_id='media'"); err == nil {
				t.Fatal("invalid maximum accepted")
			}
		})
	}
}

func TestSharedSchemaBootstrapAndUpgrade(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "schema.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.database.QueryRow("SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 49 {
		t.Fatalf("got %d tables, want 49", count)
	}
	if _, err := store.database.Exec("DROP TABLE frontiercloud_schema_migrations"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.database.Exec("UPDATE frontiercloud_schema SET generation=1 WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	if err := store.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	var generation int
	if err := store.database.QueryRow("SELECT generation FROM frontiercloud_schema WHERE singleton=1").Scan(&generation); err != nil {
		t.Fatal(err)
	}
	if generation != migrations.Generation {
		t.Fatalf("generation=%d, want %d", generation, migrations.Generation)
	}
	var checksum string
	if err := store.database.QueryRow("SELECT checksum FROM frontiercloud_schema_migrations WHERE generation=2").Scan(&checksum); err != nil {
		t.Fatal(err)
	}
	if checksum != "aee46be69d8c5b005cbee58ebfd37feb41d3431eb1fb23bb8339c9076147c03e" {
		t.Fatal("migration journal differs from Python")
	}
}

func TestGenerationTwoUpgradeAddsEncryptionWithoutChangingObjects(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "upgrade.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err = store.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = store.database.Exec("INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES ('old-identity','audio','music/old/track.mp3','old-locator','2026-01-01','2026-01-01')"); err != nil {
		t.Fatal(err)
	}
	if _, err = store.database.Exec("DROP TABLE media_encryption"); err != nil {
		t.Fatal(err)
	}
	if _, err = store.database.Exec("DROP TABLE media_crypto_keys"); err != nil {
		t.Fatal(err)
	}
	if _, err = store.database.Exec("UPDATE frontiercloud_schema SET generation=2"); err != nil {
		t.Fatal(err)
	}
	if err = store.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	var id string
	if err = store.database.QueryRow("SELECT media_id FROM media_objects WHERE path_locator='old-locator'").Scan(&id); err != nil || id != "old-identity" {
		t.Fatal("upgrade changed historical identity", err)
	}
	var generation int
	if err = store.database.QueryRow("SELECT generation FROM frontiercloud_schema").Scan(&generation); err != nil || generation != migrations.Generation {
		t.Fatal(generation, err)
	}
	var count int
	if err = store.database.QueryRow("SELECT COUNT(*) FROM media_encryption").Scan(&count); err != nil || count != 0 {
		t.Fatal("historical plaintext rewritten", err)
	}
	if err = store.Initialize(ctx); err != nil {
		t.Fatal("upgrade not idempotent", err)
	}
}

func TestRejectsIncompleteAndFutureSchemas(t *testing.T) {
	for _, change := range []string{"DROP TABLE karaoke_users", fmt.Sprintf("UPDATE frontiercloud_schema SET generation=%d", migrations.Generation+1)} {
		t.Run(change, func(t *testing.T) {
			store, err := Open(filepath.Join(t.TempDir(), "schema.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if err := store.Initialize(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := store.database.Exec(change); err != nil {
				t.Fatal(err)
			}
			if err := store.Initialize(context.Background()); err == nil {
				t.Fatal("invalid schema was accepted")
			}
		})
	}
}

func TestConcurrentSchemaBootstrap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "schema.db")
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	var workers sync.WaitGroup
	errors := make(chan error, 2)
	for _, store := range []*Store{first, second} {
		workers.Add(1)
		go func() { defer workers.Done(); errors <- store.Initialize(context.Background()) }()
	}
	workers.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestUnmarkedDatabaseIsNotAdopted(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "schema.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.database.Exec("CREATE TABLE foreign_data(id INTEGER)"); err != nil {
		t.Fatal(err)
	}
	if err := store.Initialize(context.Background()); err == nil || !strings.Contains(err.Error(), "no schema marker") {
		t.Fatalf("unexpected result: %v", err)
	}
}
