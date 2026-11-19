//go:build linux && ledger_fixture

package preprodimport

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"modernc.org/sqlite/vfs"
)

func fixtureCipherFile(t *testing.T, data []byte) (*os.File, encryptedSnapshotFixtureDescriptor) {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "encrypted-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	desc, err := captureEncryptedSnapshotFixture(context.Background(), file, bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	return file, desc
}

func TestFixtureEncryptedSnapshotStreamingAndAuthentication(t *testing.T) {
	data := bytes.Repeat([]byte("sensitive-name-秘密/"), 12000)
	file, desc := fixtureCipherFile(t, data)
	disk, err := os.ReadFile(file.Name())
	if err != nil || bytes.Contains(disk, []byte("sensitive-name-秘密")) {
		t.Fatal("plaintext name appears on disk", err)
	}
	r, err := openEncryptedSnapshotFixture(file, desc)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for _, offset := range []int64{0, fixtureEncryptedChunkSize - 11, fixtureEncryptedChunkSize + 77, int64(len(data)) - 32} {
		length := min(100, len(data)-int(offset))
		out := make([]byte, length)
		if n, err := r.ReadAt(out, offset); err != nil || n != length || !bytes.Equal(out, data[offset:offset+int64(length)]) {
			t.Fatalf("read %d: %d %v", offset, n, err)
		}
	}
	// Mutate the second chunk; a read crossing from a valid first chunk must
	// return no partial plaintext when any requested chunk fails authentication.
	var original [1]byte
	if _, err = file.ReadAt(original[:], fixtureEncryptedChunkSize+16+5); err != nil {
		t.Fatal(err)
	}
	original[0] ^= 1
	if _, err = file.WriteAt(original[:], fixtureEncryptedChunkSize+16+5); err != nil {
		t.Fatal(err)
	}
	out := bytes.Repeat([]byte{0xa5}, 20)
	before := append([]byte(nil), out...)
	if n, err := r.ReadAt(out, fixtureEncryptedChunkSize-10); err == nil || n != 0 || !bytes.Equal(out, before) {
		t.Fatal("tampered cross-chunk read leaked partial output", n, err)
	}
	r.Close()
	if _, err = r.ReadAt(out, 0); err == nil {
		t.Fatal("closed reader accepted read")
	}
}

func TestFixtureEncryptedSnapshotRejectsReorderMixTruncationAndWrongKey(t *testing.T) {
	data := bytes.Repeat([]byte("a"), int(fixtureEncryptedChunkSize*2+100))
	other := bytes.Repeat([]byte("b"), len(data))
	for _, mutation := range []string{"reordered", "mixed snapshot", "truncated", "wrong key"} {
		t.Run(mutation, func(t *testing.T) {
			file, desc := fixtureCipherFile(t, data)
			if mutation == "truncated" {
				if err := file.Truncate(int64(len(data))); err != nil {
					t.Fatal(err)
				}
				if r, err := openEncryptedSnapshotFixture(file, desc); err == nil {
					r.Close()
					t.Fatal("truncated file accepted")
				}
				return
			}
			if mutation == "wrong key" {
				desc.key[0] ^= 1
			}
			if mutation == "reordered" || mutation == "mixed snapshot" {
				size := int(fixtureEncryptedChunkSize) + 16
				var otherFile *os.File
				if mutation == "mixed snapshot" {
					otherFile, _ = fixtureCipherFile(t, other)
				} else {
					otherFile = file
				}
				block := make([]byte, size)
				pos := int64(0)
				if mutation == "reordered" {
					pos = int64(size)
				}
				if _, err := otherFile.ReadAt(block, pos); err != nil {
					t.Fatal(err)
				}
				if _, err := file.WriteAt(block, 0); err != nil {
					t.Fatal(err)
				}
			}
			r, err := openEncryptedSnapshotFixture(file, desc)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			out := bytes.Repeat([]byte{0xa5}, 10)
			before := append([]byte(nil), out...)
			if n, err := r.ReadAt(out, 0); err == nil || n != 0 || !bytes.Equal(out, before) {
				t.Fatal("invalid ciphertext accepted", n, err)
			}
		})
	}
}

type fixtureBrokenWriter struct{}

func (fixtureBrokenWriter) Write([]byte) (int, error) { return 0, errors.New("synthetic disk failure") }

func TestFixtureEncryptedSnapshotFailureReturnsNoKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		dst  io.Writer
		src  io.Reader
		size int64
	}{
		{"disk error", fixtureBrokenWriter{}, bytes.NewReader([]byte("abc")), 3},
		{"short source", io.Discard, bytes.NewReader([]byte("ab")), 3},
		{"long source", io.Discard, bytes.NewReader([]byte("abcd")), 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			desc, err := captureEncryptedSnapshotFixture(context.Background(), tc.dst, tc.src, tc.size)
			if err == nil || desc != (encryptedSnapshotFixtureDescriptor{}) {
				t.Fatal("failed capture returned descriptor", err)
			}
		})
	}
}

type fixtureEncryptedInfo struct {
	fs.FileInfo
	size int64
}

func (v fixtureEncryptedInfo) Size() int64 { return v.size }

type fixtureEncryptedFile struct {
	*io.SectionReader
	info fs.FileInfo
}

func (f *fixtureEncryptedFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *fixtureEncryptedFile) Close() error               { return nil }

type fixtureEncryptedFS struct {
	reader *encryptedSnapshotFixtureReader
	info   fs.FileInfo
	size   int64
}

func (f fixtureEncryptedFS) Open(name string) (fs.File, error) {
	if name != "snapshot.db" {
		return nil, fs.ErrNotExist
	}
	return &fixtureEncryptedFile{SectionReader: io.NewSectionReader(f.reader, 0, f.size), info: fixtureEncryptedInfo{FileInfo: f.info, size: f.size}}, nil
}

func TestFixtureEncryptedSnapshotSQLiteReadOnlyVFS(t *testing.T) {
	dir, name, _ := fixtureClosedSnapshot(t)
	plain, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	file, desc := fixtureCipherFile(t, plain)
	r, err := openEncryptedSnapshotFixture(file, desc)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	vfsName, adapter, err := vfs.New(fixtureEncryptedFS{reader: r, info: info, size: desc.size})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := adapter.Close(); e != nil {
			t.Error(e)
		}
	}()
	db, err := sql.Open("sqlite", "file:snapshot.db?vfs="+vfsName+"&mode=ro&immutable=1")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var integrity, value string
	if err = db.QueryRow(`PRAGMA quick_check(1)`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatal("encrypted SQLite integrity", integrity, err)
	}
	if err = db.QueryRow(`SELECT value FROM fixture`).Scan(&value); err != nil || value != "signed snapshot" {
		t.Fatal("encrypted SQLite value", value, err)
	}
	if _, err = db.Exec(`INSERT INTO fixture VALUES('forbidden')`); err == nil {
		t.Fatal("encrypted VFS accepted write")
	}
}
