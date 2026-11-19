package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
)

// Optional isolated build-tagged exercise of the encrypted capture prototype.
// Normal tests and the shipping binary do not register this callback.
var fixtureMaintenanceCapture func(*testing.T, *maintenance.Gate, string, string, string, *sql.DB)

func TestNativeServerMaintenanceProcess(t *testing.T) {
	if os.Getenv("FRONTIERCLOUD_TEST_NATIVE_SERVER") == "1" {
		if err := serve(); err != nil {
			t.Fatal(err)
		}
		return
	}
	redisURL := os.Getenv("FRONTIERCLOUD_TEST_REDIS_URL")
	if redisURL == "" || runtime.GOOS == "windows" {
		t.Skip("requires isolated Redis and Unix signal handling")
	}
	directory := t.TempDir()
	data := filepath.Join(directory, "data")
	secrets := filepath.Join(directory, "secrets")
	for _, path := range []string{filepath.Join(data, "media", "music"), filepath.Join(data, "media", "vido"), filepath.Join(data, "media", "lyrics"), filepath.Join(data, "recordings"), secrets} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(secrets, "admin_key"), []byte("isolated-test-admin-key"), 0600); err != nil {
		t.Fatal(err)
	}
	static, err := filepath.Abs("../../static")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	for key, value := range map[string]string{
		"DB_TYPE": "sqlite", "SQLITE_PATH": filepath.Join(data, "node.sqlite"),
		"DATA_ROOT": data, "STATIC_ROOT": static, "SECRETS_DIR": secrets,
		"HTTP_ADDR": address, "REDIS_URL": redisURL, "TLS_ENABLED": "false",
		"FRONTIERCLOUD_TEST_NATIVE_SERVER": "1",
	} {
		t.Setenv(key, value)
	}
	start := func() <-chan error {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestNativeServerMaintenanceProcess$", "-test.count=1")
		var output bytes.Buffer
		cmd.Stdout, cmd.Stderr = &output, &output
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait(); close(done) }()
		t.Cleanup(func() { cmd.Process.Kill(); <-done })
		client := &http.Client{Timeout: 250 * time.Millisecond}
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case err := <-done:
				t.Fatalf("native process exited before readiness: %v\n%s", err, output.String())
			default:
			}
			response, err := client.Get("http://" + address + "/health/ready")
			if err == nil {
				io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
				response.Body.Close()
				if response.StatusCode == http.StatusOK {
					return done
				}
			}
			time.Sleep(25 * time.Millisecond)
		}
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
			t.Fatalf("readiness timeout\n%s", output.String())
		case <-time.After(2 * time.Second):
			t.Fatal("readiness timeout and shutdown did not complete")
		}
		return nil
	}
	gate, err := maintenance.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	settings, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	check := func(ctx context.Context) error {
		db, err := openExistingStore(ctx, settings)
		if err != nil {
			return err
		}
		defer db.Close()
		snapshot, err := db.Maintenance().InspectMaintenance(ctx)
		if err == nil && (snapshot.Role != "Standalone" || !snapshot.LogicalIdle) {
			return errors.New("process did not leave an idle Standalone fixture")
		}
		return err
	}
	// The test database is small and synthetic; do not use whole-file reads for
	// production-sized databases. Detect mutation as well as sidecar removal.
	journalState := func() map[string][sha256.Size]byte {
		t.Helper()
		state := make(map[string][sha256.Size]byte)
		for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
			contents, err := os.ReadFile(settings.SQLitePath + suffix)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			state[suffix] = sha256.Sum256(contents)
		}
		return state
	}
	for iteration := 0; iteration < 2; iteration++ {
		done := start()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := gate.Enter(ctx, check)
		cancel()
		if err != nil {
			t.Fatal("could not drain real native server", err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatal("native server shutdown failed", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("process retained work after its runtime lease released")
		}
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		cleanExpected := true
		err = gate.InspectSQLiteFile(ctx, data, settings.SQLitePath, func(_ context.Context, file *os.File, recheck func() error) error {
			var header [100]byte
			if _, e := file.ReadAt(header[:], 0); e != nil || string(header[:16]) != "SQLite format 3\x00" {
				return errors.New("drained runtime did not expose the selected SQLite file")
			}
			if header[18] != header[19] || (header[18] != 1 && header[18] != 2) {
				return errors.New("unsupported SQLite journal header")
			}
			t.Logf("drained SQLite journal header version: %d", header[18])
			if header[18] != 1 {
				cleanExpected = false
			}
			for _, suffix := range []string{"-wal", "-shm", "-journal"} {
				if info, e := os.Lstat(settings.SQLitePath + suffix); !errors.Is(e, os.ErrNotExist) {
					if e != nil {
						return e
					}
					t.Logf("drained SQLite %s sidecar size: %d", suffix, info.Size())
					cleanExpected = false
				}
			}
			return recheck()
		})
		cancel()
		if err != nil {
			t.Fatal("could not inspect the drained runtime SQLite FD", err)
		}
		beforePreflight := journalState()
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		called := false
		err = gate.InspectSQLiteCleanFile(ctx, data, settings.SQLitePath, func(_ context.Context, _ *os.File, check func() error) error { called = true; return check() })
		cancel()
		if cleanExpected && (err != nil || !called) || !cleanExpected && (!errors.Is(err, maintenance.ErrState) || called) {
			t.Fatalf("clean preflight mismatch: expected=%v callback=%v err=%v", cleanExpected, called, err)
		}
		if !cleanExpected {
			t.Log("offline capture preflight correctly refused outstanding SQLite WAL state")
		}
		afterPreflight := journalState()
		if len(beforePreflight) != len(afterPreflight) {
			t.Fatal("offline capture preflight added or removed a SQLite file")
		}
		for name, digest := range beforePreflight {
			if actual, ok := afterPreflight[name]; !ok || actual != digest {
				t.Fatalf("offline capture preflight changed SQLite file %q", name)
			}
		}
		// Model a committed, uncheckpointed WAL on the real stopped server's
		// isolated test database. Keep the seeding connection alive so SQLite
		// does not checkpoint as its last connection closes.
		u := url.URL{Scheme: "file", Path: settings.SQLitePath, RawQuery: url.Values{"mode": {"rw"}, "_pragma": {"busy_timeout(100)", "wal_autocheckpoint(0)"}}.Encode()}
		seed, err := sql.Open("sqlite", u.String())
		if err != nil {
			t.Fatal(err)
		}
		seed.SetMaxOpenConns(1)
		if _, err = seed.Exec(`CREATE TABLE IF NOT EXISTS isolated_wal_capture(id INTEGER PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
			t.Fatal(err)
		}
		if _, err = seed.Exec(`INSERT INTO isolated_wal_capture(value) VALUES('committed WAL fixture')`); err != nil {
			t.Fatal(err)
		}
		mediaID := fmt.Sprintf("wal-fixture-%d", iteration)
		if _, err = seed.Exec(`INSERT INTO media_objects(media_id,object_kind,media_path,path_locator,created_at,updated_at) VALUES(?,'audio',?,?, 'old','old')`, mediaID, "music/"+mediaID+".mp3", mediaID); err != nil {
			t.Fatal(err)
		}
		if info, e := os.Stat(settings.SQLitePath + "-wal"); e != nil || info.Size() <= 32 {
			t.Fatal("fixture lacks committed WAL pages", e)
		}
		if fixtureMaintenanceCapture != nil {
			fixtureMaintenanceCapture(t, gate, data, settings.SQLitePath, mediaID, seed)
		}
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		err = gate.InspectSQLite(ctx, data, settings.SQLitePath, func(ctx context.Context, check func() error) error {
			if check() != nil {
				return maintenance.ErrState
			}
			u.RawQuery = url.Values{"mode": {"rw"}, "_txlock": {"immediate"}, "_pragma": {"busy_timeout(100)"}}.Encode()
			capture, e := sql.Open("sqlite", u.String())
			if e != nil {
				return e
			}
			defer capture.Close()
			capture.SetMaxOpenConns(1)
			tx, e := capture.BeginTx(ctx, nil)
			if e != nil {
				return e
			}
			defer tx.Rollback()
			var count int
			if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM isolated_wal_capture WHERE value='committed WAL fixture'`).Scan(&count); e != nil || count != iteration+1 {
				return errors.New("committed WAL rows not visible on capture transaction")
			}
			if _, e = seed.ExecContext(ctx, `INSERT INTO isolated_wal_capture(value) VALUES('should be blocked')`); e == nil || !strings.Contains(strings.ToLower(e.Error()), "locked") {
				return errors.New("concurrent SQLite writer was not blocked")
			}
			if check() != nil {
				return maintenance.ErrState
			}
			return tx.Rollback()
		})
		cancel()
		if err != nil {
			t.Fatal("real runtime offline WAL snapshot lock", err)
		}
		if err = seed.Close(); err != nil {
			t.Fatal(err)
		}
		if err := serve(); !errors.Is(err, maintenance.ErrEnabled) {
			t.Fatal("native startup bypassed persistent maintenance", err)
		}
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		err = gate.Resume(ctx, check)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
	}
}
