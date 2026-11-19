//go:build linux && owner_publish_fixture && ledger_fixture

package preprodimport

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This is a negative-control fixture, NOT a production fence. It demonstrates
// why an independent pathname/file handle plus PRAGMA database_list cannot
// authenticate the inode already held by an existing database/sql connection.
// The real import gate must stay closed until the driver connection itself is
// bound to an authenticated inode under an appropriate persistent fence.
func TestFixtureSourceFenceCanPinDifferentInodeThanSQLiteConnection(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	primary, replacement, parked := filepath.Join(dir, "source.sqlite"), filepath.Join(dir, "replacement.sqlite"), filepath.Join(dir, "parked.sqlite")
	open := func(path, marker string) *sql.DB {
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		for _, statement := range []string{
			`PRAGMA journal_mode=DELETE`,
			`CREATE TABLE preprod_source_evidence(evidence_tag TEXT PRIMARY KEY,salt BLOB NOT NULL UNIQUE,nonce BLOB NOT NULL,cipher BLOB NOT NULL,challenge_tag TEXT NOT NULL UNIQUE)`,
			`CREATE TABLE fixture_identity(marker TEXT NOT NULL)`,
		} {
			if _, err = db.ExecContext(ctx, statement); err != nil {
				t.Fatal(err)
			}
		}
		if _, err = db.ExecContext(ctx, `INSERT INTO preprod_source_evidence VALUES(?,?,?,?,?)`, "tag", bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 12), bytes.Repeat([]byte{3}, 4096), "challenge"); err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, `INSERT INTO fixture_identity VALUES(?)`, marker); err != nil {
			t.Fatal(err)
		}
		if err = os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
		return db
	}
	oldDB := open(primary, "old-connection")
	defer oldDB.Close()
	newDB := open(replacement, "new-path")
	if err := newDB.Close(); err != nil {
		t.Fatal(err)
	}
	// The original SQLite handle remains pooled. Swap a separate, otherwise
	// valid evidence database into its pathname before acquiring the fixture.
	if err := os.Rename(primary, parked); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, primary); err != nil {
		t.Fatal(err)
	}
	conn, err := oldDB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := fixtureEvidenceRowHash(ctx, conn, "tag")
	if err != nil {
		t.Fatal(err)
	}
	var sqlitePath, marker string
	if err = conn.QueryRowContext(ctx, `SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&sqlitePath); err != nil {
		t.Fatal(err)
	}
	if err = conn.QueryRowContext(ctx, `SELECT marker FROM fixture_identity`).Scan(&marker); err != nil {
		t.Fatal(err)
	}
	if sqlitePath != primary || marker != "old-connection" {
		t.Fatalf("unexpected control: path=%q marker=%q", sqlitePath, marker)
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	fence, err := fixtureAcquireEvidenceFence(ctx, oldDB, primary, "tag", expected, time.Now().Add(time.Minute).Unix())
	if err != nil {
		t.Fatal("negative control unexpectedly rejected", err)
	}
	defer fence.Release()
	if err = fence.conn.QueryRowContext(ctx, `SELECT marker FROM fixture_identity`).Scan(&marker); err != nil || marker != "old-connection" {
		t.Fatal("fence SQLite identity", marker, err)
	}
	check, err := sql.Open("sqlite", primary)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	if err = check.QueryRowContext(ctx, `SELECT marker FROM fixture_identity`).Scan(&marker); err != nil || marker != "new-path" {
		t.Fatal("pathname identity", marker, err)
	}
	if err = fence.Check(ctx); err != nil {
		t.Fatal("fixture did not show the mismatch", err)
	}
}
