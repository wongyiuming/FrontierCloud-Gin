package sqlite

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

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
	if count != 36 {
		t.Fatalf("got %d tables, want 36", count)
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
	if generation != 3 {
		t.Fatalf("generation=%d, want 3", generation)
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
	if err = store.database.QueryRow("SELECT generation FROM frontiercloud_schema").Scan(&generation); err != nil || generation != 3 {
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
	for _, change := range []string{"DROP TABLE karaoke_users", "UPDATE frontiercloud_schema SET generation=4"} {
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
