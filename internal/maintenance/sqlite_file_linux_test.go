//go:build linux

package maintenance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fixtureSQLiteFile(t *testing.T) (*Gate, string, string) {
	t.Helper()
	gate, dir := fixture(t)
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "source.sqlite")
	if err := os.WriteFile(path, []byte("synthetic source contents"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := gate.Enter(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	return gate, dir, path
}

func TestInspectSQLiteFileHoldsOfflineLeaseAndReadOnlyFD(t *testing.T) {
	gate, dir, path := fixtureSQLiteFile(t)
	var escaped *os.File
	err := gate.InspectSQLiteFile(context.Background(), dir, path, func(ctx context.Context, file *os.File, check func() error) error {
		escaped = file
		var content [9]byte
		if _, e := file.ReadAt(content[:], 0); e != nil || string(content[:]) != "synthetic" {
			t.Fatal("wrong held fd", string(content[:]), e)
		}
		if _, e := file.WriteAt([]byte("x"), 0); e == nil {
			t.Fatal("source fd is writable")
		}
		short, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		if _, e := gate.Runtime(short); !errors.Is(e, context.DeadlineExceeded) && !errors.Is(e, ErrEnabled) {
			t.Fatal("runtime bypassed offline marker", e)
		}
		return check()
	})
	if err != nil {
		t.Fatal(err)
	}
	if escaped == nil {
		t.Fatal("callback not called")
	}
	if _, err = escaped.Stat(); err == nil {
		t.Fatal("callback retained open descriptor")
	}
}

func TestInspectSQLiteFileRejectsSourceOrFenceChanges(t *testing.T) {
	for _, change := range []string{"path replacement", "same inode write", "closed fd", "replaced runtime lock", "cancel"} {
		t.Run(change, func(t *testing.T) {
			gate, dir, path := fixtureSQLiteFile(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err := gate.InspectSQLiteFile(ctx, dir, path, func(ctx context.Context, file *os.File, check func() error) error {
				switch change {
				case "path replacement":
					if e := os.Rename(path, filepath.Join(dir, "parked.sqlite")); e != nil {
						t.Fatal(e)
					}
					if e := os.WriteFile(path, []byte("replacement"), 0600); e != nil {
						t.Fatal(e)
					}
				case "same inode write":
					f, e := os.OpenFile(path, os.O_WRONLY, 0)
					if e != nil {
						t.Fatal(e)
					}
					if _, e = f.WriteAt([]byte("X"), 0); e != nil {
						t.Fatal(e)
					}
					if e = f.Close(); e != nil {
						t.Fatal(e)
					}
					future := time.Now().Add(3 * time.Second)
					if e = os.Chtimes(path, future, future); e != nil {
						t.Fatal(e)
					}
				case "closed fd":
					if e := file.Close(); e != nil {
						t.Fatal(e)
					}
				case "replaced runtime lock":
					lock := filepath.Join(dir, runtimeLock)
					if e := os.Remove(lock); e != nil {
						t.Fatal(e)
					}
					if e := os.WriteFile(lock, nil, 0600); e != nil {
						t.Fatal(e)
					}
				case "cancel":
					cancel()
				}
				if e := check(); !errors.Is(e, ErrState) {
					t.Fatal("changed state accepted", e)
				}
				return nil
			})
			if !errors.Is(err, ErrState) {
				t.Fatal("inspection accepted changed state", err)
			}
		})
	}
}

func TestInspectSQLiteFileRejectsUnsafeEntryAndPropagatesCallback(t *testing.T) {
	gate, dir, path := fixtureSQLiteFile(t)
	sentinel := errors.New("synthetic failure")
	if err := gate.InspectSQLiteFile(context.Background(), dir, path, func(context.Context, *os.File, func() error) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	if enabled, err := gate.Enabled(); err != nil || !enabled {
		t.Fatal("failed callback reopened maintenance", enabled, err)
	}
	outside := filepath.Join(t.TempDir(), "outside.sqlite")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := gate.InspectSQLiteFile(context.Background(), dir, outside, func(context.Context, *os.File, func() error) error { t.Fatal("outside callback"); return nil }); !errors.Is(err, ErrState) {
		t.Fatal("outside path accepted", err)
	}
	if err := os.Link(path, filepath.Join(dir, "second-link")); err != nil {
		t.Fatal(err)
	}
	if err := gate.InspectSQLiteFile(context.Background(), dir, path, func(context.Context, *os.File, func() error) error { t.Fatal("hard link callback"); return nil }); !errors.Is(err, ErrState) {
		t.Fatal("hard link accepted", err)
	}
}

func TestInspectSQLiteCleanFileRejectsWALAndJournal(t *testing.T) {
	for _, change := range []string{"clean", "wal header", "wal sidecar", "shm sidecar", "hot journal", "sidecar created during read"} {
		t.Run(change, func(t *testing.T) {
			gate, dir, path := fixtureSQLiteFile(t)
			header := make([]byte, 100)
			copy(header, []byte("SQLite format 3\x00"))
			header[18], header[19] = 1, 1
			if change == "wal header" {
				header[18], header[19] = 2, 2
			}
			if err := os.WriteFile(path, header, 0600); err != nil {
				t.Fatal(err)
			}
			var suffix string
			switch change {
			case "wal sidecar":
				suffix = "-wal"
			case "shm sidecar":
				suffix = "-shm"
			case "hot journal":
				suffix = "-journal"
			}
			if suffix != "" {
				if err := os.WriteFile(path+suffix, []byte{1}, 0600); err != nil {
					t.Fatal(err)
				}
			}
			called := false
			err := gate.InspectSQLiteCleanFile(context.Background(), dir, path, func(_ context.Context, _ *os.File, check func() error) error {
				called = true
				if change == "sidecar created during read" {
					if e := os.WriteFile(path+"-wal", []byte{1}, 0600); e != nil {
						t.Fatal(e)
					}
					if !errors.Is(check(), ErrState) {
						t.Fatal("new WAL accepted")
					}
					return nil
				}
				return check()
			})
			if change == "clean" {
				if err != nil || !called {
					t.Fatal("clean fixture rejected", err)
				}
				return
			}
			if !errors.Is(err, ErrState) {
				t.Fatal("unsafe journal accepted", err)
			}
			if change != "sidecar created during read" && called {
				t.Fatal("unsafe callback invoked")
			}
			if enabled, e := gate.Enabled(); e != nil || !enabled {
				t.Fatal("refusal reopened maintenance", enabled, e)
			}
		})
	}
}
