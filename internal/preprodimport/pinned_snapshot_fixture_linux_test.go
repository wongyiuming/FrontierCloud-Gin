//go:build linux && ledger_fixture

package preprodimport

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func fixtureClosedSnapshot(t *testing.T) (string, string, [32]byte) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	name := "evidence.sqlite"
	path := filepath.Join(dir, name)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{`PRAGMA journal_mode=DELETE`, `CREATE TABLE fixture(value TEXT NOT NULL)`, `INSERT INTO fixture VALUES('signed snapshot')`} {
		if _, err = db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return dir, name, sha256.Sum256(raw)
}

func TestFixtureSealedSnapshotReadOnlyAndIntegrity(t *testing.T) {
	ctx := context.Background()
	dir, name, digest := fixtureClosedSnapshot(t)
	p, err := openImmutableSnapshotFixture(ctx, dir, name, digest)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.inspect(ctx, func(tx *sql.Tx) error {
		var value string
		if err := tx.QueryRowContext(ctx, `SELECT value FROM fixture`).Scan(&value); err != nil || value != "signed snapshot" {
			t.Fatalf("snapshot value %q %v", value, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO fixture VALUES('forbidden')`); err == nil {
			t.Fatal("snapshot accepted write")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = p.sealed.WriteAt([]byte{0}, 0); err == nil {
		t.Fatal("sealed memfd accepted write")
	}
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
	if err = p.Close(); err != nil {
		t.Fatal("repeated close", err)
	}
	if err = p.inspect(ctx, func(*sql.Tx) error { return nil }); err == nil {
		t.Fatal("closed snapshot reused")
	}
}

func TestFixtureSealedSnapshotRejectsReplacementAndTampering(t *testing.T) {
	ctx := context.Background()
	for _, change := range []string{"path replacement", "same inode change", "closed source fd", "closed sealed fd", "added hot journal", "added wal", "added shm"} {
		t.Run(change, func(t *testing.T) {
			dir, name, digest := fixtureClosedSnapshot(t)
			p, err := openImmutableSnapshotFixture(ctx, dir, name, digest)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			path := filepath.Join(dir, name)
			switch change {
			case "path replacement":
				if err = os.Rename(path, filepath.Join(dir, "parked.sqlite")); err == nil {
					err = os.WriteFile(path, []byte("replacement"), 0600)
				}
			case "same inode change":
				var f *os.File
				f, err = os.OpenFile(path, os.O_WRONLY, 0)
				if err == nil {
					_, err = f.WriteAt([]byte{0xff}, 200)
					err = errors.Join(err, f.Close())
				}
			case "closed source fd":
				err = p.source.Close()
			case "closed sealed fd":
				err = p.sealed.Close()
			case "added hot journal":
				err = os.WriteFile(path+"-journal", []byte{1}, 0600)
			case "added wal":
				err = os.WriteFile(path+"-wal", []byte{1}, 0600)
			case "added shm":
				err = os.WriteFile(path+"-shm", []byte{1}, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			called := false
			if err = p.inspect(ctx, func(*sql.Tx) error { called = true; return nil }); err == nil || called {
				t.Fatal("changed source was inspected", err)
			}
		})
	}
}

func TestFixtureSealedSnapshotRejectsChangeDuringRead(t *testing.T) {
	ctx := context.Background()
	dir, name, digest := fixtureClosedSnapshot(t)
	p, err := openImmutableSnapshotFixture(ctx, dir, name, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	err = p.inspect(ctx, func(tx *sql.Tx) error {
		var value string
		if err := tx.QueryRow(`SELECT value FROM fixture`).Scan(&value); err != nil || value != "signed snapshot" {
			return errors.New("fixture query failed")
		}
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		_, err = f.WriteAt([]byte{0xff}, 200)
		return errors.Join(err, f.Close())
	})
	if err == nil {
		t.Fatal("mid-read mutation accepted")
	}
}

func TestFixtureSealedSnapshotRejectsInvalidInput(t *testing.T) {
	ctx := context.Background()
	for _, change := range []string{"wrong digest", "wal page header", "hot journal", "wal sidecar", "shm sidecar", "hard link"} {
		t.Run(change, func(t *testing.T) {
			dir, name, digest := fixtureClosedSnapshot(t)
			path := filepath.Join(dir, name)
			switch change {
			case "wrong digest":
				digest[0] ^= 1
			case "wal page header":
				f, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.WriteAt([]byte{2, 2}, 18); err != nil {
					t.Fatal(err)
				}
				if err = f.Close(); err != nil {
					t.Fatal(err)
				}
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				digest = sha256.Sum256(raw)
			case "hot journal":
				if err := os.WriteFile(path+"-journal", []byte{1}, 0600); err != nil {
					t.Fatal(err)
				}
			case "wal sidecar":
				if err := os.WriteFile(path+"-wal", []byte{1}, 0600); err != nil {
					t.Fatal(err)
				}
			case "shm sidecar":
				if err := os.WriteFile(path+"-shm", []byte{1}, 0600); err != nil {
					t.Fatal(err)
				}
			case "hard link":
				if err := os.Link(path, filepath.Join(dir, "linked.sqlite")); err != nil {
					t.Fatal(err)
				}
			}
			p, err := openImmutableSnapshotFixture(ctx, dir, name, digest)
			if err == nil {
				p.Close()
				t.Fatal("unsafe snapshot accepted")
			}
		})
	}
}
