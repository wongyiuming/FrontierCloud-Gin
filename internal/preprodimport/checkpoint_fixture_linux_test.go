//go:build linux && ledger_fixture

package preprodimport

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// This tests SQLite mechanics only. It does not prove that the application
// maintenance gate controls old or external processes, nor activate capture.
func TestFixtureSingleConnectionCheckpointAndActiveReader(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "checkpoint.db")
	open := func(create bool) *sql.DB {
		t.Helper()
		u := url.URL{Scheme: "file", Path: path}
		q := url.Values{"_pragma": {"busy_timeout(100)"}}
		if !create {
			q.Set("mode", "rw")
		}
		u.RawQuery = q.Encode()
		db, err := sql.Open("sqlite", u.String())
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	writer := open(true)
	for _, q := range []string{`PRAGMA journal_mode=WAL`, `PRAGMA wal_autocheckpoint=0`, `CREATE TABLE fixture(id INTEGER PRIMARY KEY)`, `INSERT INTO fixture VALUES(1)`} {
		if _, err := writer.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	reader := open(false)
	tx, err := reader.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM fixture`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("establish reader snapshot: %d %v", count, err)
	}
	if _, err := writer.ExecContext(ctx, `INSERT INTO fixture VALUES(2)`); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path + "-wal"); err != nil || info.Size() <= 32 {
		t.Fatal("fixture lacks committed WAL frames", err)
	}
	checkpoint := open(false)
	conn, err := checkpoint.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var busy, frames, done int
	if err := conn.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &frames, &done); err != nil || busy == 0 {
		t.Fatalf("active reader should block complete checkpoint: busy=%d frames=%d done=%d err=%v", busy, frames, done, err)
	}
	var mode string
	err = conn.QueryRowContext(ctx, `PRAGMA journal_mode=DELETE`).Scan(&mode)
	if err == nil && mode == "delete" {
		t.Fatal("active reader unexpectedly allowed journal conversion")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &frames, &done); err != nil || busy != 0 {
		t.Fatalf("checkpoint retry: busy=%d frames=%d done=%d err=%v", busy, frames, done, err)
	}
	if err := conn.QueryRowContext(ctx, `PRAGMA journal_mode=DELETE`).Scan(&mode); err != nil || mode != "delete" {
		t.Fatalf("journal conversion: %q %v", mode, err)
	}
	var integrity string
	if err := conn.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("integrity: %q %v", integrity, err)
	}
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM fixture`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("committed rows not recovered: %d %v", count, err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := checkpoint.Close(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Stat(path + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("sidecar remains after conversion %q: %v", suffix, err)
		}
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var header [20]byte
	if _, err := file.ReadAt(header[:], 0); err != nil || header[18] != 1 || header[19] != 1 {
		t.Fatalf("unexpected rollback-mode header: %v", err)
	}
}
