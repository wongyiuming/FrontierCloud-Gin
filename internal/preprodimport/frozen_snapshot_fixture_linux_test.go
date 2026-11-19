//go:build linux && ledger_fixture

package preprodimport

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"modernc.org/sqlite"
	"modernc.org/sqlite/vfs"
)

// pinnedSnapshotFixtureFS exposes one already-open file to SQLite's read-only
// VFS. SectionReader gives every VFS open its own seek position; Close on one
// VFS handle does not close the outer pinned descriptor. This is a test-only
// primitive and does not establish snapshot authenticity or write exclusion.
type pinnedSnapshotFixtureFS struct{ file *os.File }
type pinnedSnapshotFixtureFile struct {
	*io.SectionReader
	info os.FileInfo
}

func (f pinnedSnapshotFixtureFS) Open(name string) (fs.File, error) {
	if name != "snapshot.db" || f.file == nil {
		return nil, fs.ErrNotExist
	}
	info, err := f.file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fs.ErrInvalid
	}
	return &pinnedSnapshotFixtureFile{SectionReader: io.NewSectionReader(f.file, 0, info.Size()), info: info}, nil
}
func (f *pinnedSnapshotFixtureFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *pinnedSnapshotFixtureFile) Close() error               { return nil }

func TestFixtureSQLiteWALBackupAndPinnedReadOnlySnapshot(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	sourcePath, snapshotPath := filepath.Join(dir, "source.db"), filepath.Join(dir, "snapshot.db")
	source, err := sql.Open("sqlite", sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	source.SetMaxOpenConns(1)
	for _, statement := range []string{
		`PRAGMA journal_mode=WAL`, `PRAGMA wal_autocheckpoint=0`,
		`CREATE TABLE fixture_data(id INTEGER PRIMARY KEY, value TEXT NOT NULL)`,
		`INSERT INTO fixture_data VALUES(1,'committed-in-wal')`,
	} {
		if _, err = source.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	wal, err := os.Stat(sourcePath + "-wal")
	if err != nil || wal.Size() <= 32 {
		t.Fatal("fixture did not retain committed WAL pages", err)
	}
	conn, err := source.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	err = conn.Raw(func(raw any) error {
		backuper, ok := raw.(interface {
			NewBackup(string) (*sqlite.Backup, error)
		})
		if !ok {
			return errors.New("driver backup API unavailable")
		}
		backup, e := backuper.NewBackup(snapshotPath)
		if e != nil {
			return e
		}
		for {
			more, e := backup.Step(32)
			if e != nil {
				_ = backup.Finish()
				return e
			}
			if !more {
				break
			}
		}
		return backup.Finish()
	})
	if closeErr := conn.Close(); err != nil || closeErr != nil {
		t.Fatal("backup", err, closeErr)
	}
	// Produce a self-contained rollback-journal snapshot before using the
	// read-only VFS, which does not support a live WAL or SQLite locks.
	snapshot, err := sql.Open("sqlite", snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	var mode, integrity string
	if err = snapshot.QueryRowContext(ctx, `PRAGMA journal_mode=DELETE`).Scan(&mode); err != nil || mode != "delete" {
		t.Fatal("snapshot mode", mode, err)
	}
	if err = snapshot.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatal("snapshot integrity", integrity, err)
	}
	if err = snapshot.Close(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-journal"} {
		if _, err = os.Stat(snapshotPath + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("snapshot sidecar is present", suffix, err)
		}
	}
	if err = os.Chmod(snapshotPath, 0600); err != nil {
		t.Fatal(err)
	}
	pinned, err := os.Open(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.Close()
	openedInfo, err := pinned.Stat()
	if err != nil {
		t.Fatal(err)
	}
	name, adapter, err := vfs.New(pinnedSnapshotFixtureFS{file: pinned})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := adapter.Close(); e != nil {
			t.Error(e)
		}
	}()
	readOnly, err := sql.Open("sqlite", "file:snapshot.db?vfs="+name+"&immutable=1")
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	assertSnapshot := func() {
		t.Helper()
		var count int
		var value string
		if e := readOnly.QueryRowContext(ctx, `SELECT count(*),min(value) FROM fixture_data`).Scan(&count, &value); e != nil || count != 1 || value != "committed-in-wal" {
			t.Fatalf("snapshot rows: %d %q %v", count, value, e)
		}
	}
	assertSnapshot()
	if _, err = source.ExecContext(ctx, `INSERT INTO fixture_data VALUES(2,'after-snapshot')`); err != nil {
		t.Fatal(err)
	}
	assertSnapshot()
	if _, err = readOnly.ExecContext(ctx, `INSERT INTO fixture_data VALUES(3,'forbidden')`); err == nil {
		t.Fatal("read-only snapshot accepted a write")
	}
	parked := filepath.Join(dir, "parked.db")
	if err = os.Rename(snapshotPath, parked); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(snapshotPath, []byte("different inode"), 0600); err != nil {
		t.Fatal(err)
	}
	current, err := os.Stat(snapshotPath)
	if err != nil || os.SameFile(openedInfo, current) {
		t.Fatal("path replacement not detected", err)
	}
	assertSnapshot()
}
