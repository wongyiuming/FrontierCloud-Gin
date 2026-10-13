package business_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	mysqlstore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/mysql"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

var mysqlFixtureSequence atomic.Uint64

func database(t *testing.T) store.Store {
	t.Helper()
	var db store.Store
	var err error
	isolatedDatabase := ""
	var isolatedConfig mysqlstore.Config
	if host := os.Getenv("FRONTIERCLOUD_TEST_MYSQL_HOST"); host != "" {
		port := 3306
		if text := os.Getenv("FRONTIERCLOUD_TEST_MYSQL_PORT"); text != "" {
			port, err = strconv.Atoi(text)
			if err != nil {
				t.Fatal(err)
			}
		}
		name := os.Getenv("FRONTIERCLOUD_TEST_MYSQL_DATABASE")
		if prefix := os.Getenv("FRONTIERCLOUD_TEST_MYSQL_DATABASE_PREFIX"); prefix != "" {
			if len(prefix) > 32 || len(prefix) < 8 || prefix[:8] != "fc_test_" {
				t.Fatal("explicit isolated MySQL fixture prefix required")
			}
			for _, character := range prefix {
				if character != '_' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
					t.Fatal("unsafe MySQL fixture prefix")
				}
			}
			// Match SQLite's new database per fixture, including repeated calls
			// within one test. No prior test's media/identity can certify emptiness.
			sum := sha256.Sum256([]byte(t.Name()))
			name = prefix + hex.EncodeToString(sum[:8]) + "_" + strconv.FormatUint(mysqlFixtureSequence.Add(1), 10)
			isolatedDatabase = name
			isolatedConfig = mysqlstore.Config{Host: host, Port: port, Database: os.Getenv("FRONTIERCLOUD_TEST_MYSQL_DATABASE"), User: os.Getenv("FRONTIERCLOUD_TEST_MYSQL_USER"), PasswordFile: os.Getenv("FRONTIERCLOUD_TEST_MYSQL_PASSWORD_FILE")}
			bootstrap, e := mysqlstore.Open(isolatedConfig)
			if e != nil {
				t.Fatal(e)
			}
			_, e = bootstrap.Database().Exec("CREATE DATABASE `" + name + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
			closeErr := bootstrap.Close()
			if e != nil || closeErr != nil {
				t.Fatal("fresh isolated MySQL database allocation failed", e, closeErr)
			}
		}
		db, err = mysqlstore.Open(mysqlstore.Config{Host: host, Port: port, Database: name, User: os.Getenv("FRONTIERCLOUD_TEST_MYSQL_USER"), PasswordFile: os.Getenv("FRONTIERCLOUD_TEST_MYSQL_PASSWORD_FILE")})
	} else {
		db, err = sqlitestore.Open(filepath.Join(t.TempDir(), "database.db"))
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		if isolatedDatabase != "" && !t.Failed() {
			// Successful temporary databases are reclaimed only after caller
			// cleanup and all assertions. Failed fixtures retain their evidence.
			bootstrap, e := mysqlstore.Open(isolatedConfig)
			if e != nil {
				t.Error("isolated MySQL fixture cleanup connection failed", e)
				return
			}
			if _, e = bootstrap.Database().Exec("DROP DATABASE `" + isolatedDatabase + "`"); e != nil {
				t.Error("isolated MySQL fixture cleanup failed", e)
			}
			bootstrap.Close()
		}
	})
	if err := db.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestMediaRepositoryConcurrentStableIDsAndPlayback(t *testing.T) {
	db := database(t)
	repo := db.Media()
	ctx := context.Background()
	// Test-specific path namespace makes the same suite safe on a shared test DB.
	name := "music/" + t.Name() + "/track.mp3"
	track := store.MediaObject{Path: name, Kind: "audio"}
	var wg sync.WaitGroup
	failures := make(chan error, 32)
	ids := make(chan string, 32)
	for range 16 {
		wg.Go(func() {
			values, err := repo.EnsureObjects(ctx, []store.MediaObject{track})
			if err != nil {
				failures <- err
				return
			}
			ids <- values[name]
		})
	}
	wg.Wait()
	close(failures)
	close(ids)
	for err := range failures {
		t.Fatal(err)
	}
	var expected string
	for id := range ids {
		if len(id) != 64 {
			t.Fatalf("invalid ID %s", id)
		}
		if expected == "" {
			expected = id
		} else if expected != id {
			t.Fatal("concurrent IDs differ")
		}
	}
	result, err := repo.EnsureObjects(ctx, []store.MediaObject{{Path: "music/" + t.Name() + "/TRACK.mp3", Kind: "audio"}})
	if err != nil {
		t.Fatal(err)
	}
	if result["music/"+t.Name()+"/TRACK.mp3"] == expected {
		t.Fatal("case distinct paths merged")
	}
	object, err := repo.ObjectByID(ctx, expected)
	if err != nil || object.Path != name {
		t.Fatalf("lookup: %+v %v", object, err)
	}
	counts := make(chan bool, 16)
	failures = make(chan error, 16)
	for range 16 {
		wg.Go(func() {
			value, err := repo.RecordPlayback(ctx, track, "2775bcdc-9f7d-42b5-a3c3-c10caa131bee")
			if err != nil {
				failures <- err
				return
			}
			counts <- value.Counted
		})
	}
	wg.Wait()
	close(counts)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	counted := 0
	for value := range counts {
		if value {
			counted++
		}
	}
	if counted != 1 {
		t.Fatalf("counted %d events", counted)
	}
	stats, err := repo.Stats(ctx, []string{expected})
	if err != nil || stats[expected].PlayScore != 1 {
		t.Fatalf("stats: %+v %v", stats, err)
	}
	lyric := store.MediaObject{Path: "lyrics/" + t.Name() + ".lrc", Kind: "lyric"}
	if err := repo.BindLyric(ctx, track, lyric); err != nil {
		t.Fatal(err)
	}
	path, err := repo.LyricPath(ctx, expected)
	if err != nil || path != lyric.Path {
		t.Fatalf("link: %s %v", path, err)
	}
}

func TestSQLiteLegacyIDAndAtomicRollback(t *testing.T) {
	db, err := sqlitestore.Open(filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	path := "music/category/legacy.mp3"
	sum := sha256.Sum256([]byte(path))
	legacy := hex.EncodeToString(sum[:])
	if _, err := db.Database().Exec("INSERT INTO media_playback_stats (media_id,media_path,play_score,preference,created_at,updated_at) VALUES (?,?,4,0,'2026-01-01','2026-01-01')", legacy, path); err != nil {
		t.Fatal(err)
	}
	ids, err := db.Media().EnsureObjects(ctx, []store.MediaObject{{Path: path, Kind: "audio"}})
	if err != nil || ids[path] != legacy {
		t.Fatalf("legacy ID not preserved: %v %v", ids, err)
	}
	_, err = db.Media().EnsureObjects(ctx, []store.MediaObject{{Path: "music/category/new.mp3", Kind: "audio"}, {Path: path, Kind: "video"}})
	if err == nil {
		t.Fatal("conflicting kind accepted")
	}
	var count int
	if err := db.Database().QueryRow("SELECT COUNT(*) FROM media_objects WHERE media_path='music/category/new.mp3'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("transaction partially committed: %d %v", count, err)
	}
}
