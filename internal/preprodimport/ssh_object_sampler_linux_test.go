//go:build linux

package preprodimport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestSourceSamplerReadOnlyAndMissingLock(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "music"), 0700); err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("synthetic-media"), 1024)
	if err := os.WriteFile(filepath.Join(dir, "music", "file"), data, 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err = sampleSourceObject(ctx, root, "music/file", int64(len(data)), 4*1024*1024); err == nil {
		t.Fatal("missing lock accepted")
	}
	if _, err = os.Lstat(filepath.Join(dir, sourceLockName)); !os.IsNotExist(err) {
		t.Fatal("sampler created lock", err)
	}
	if err = os.WriteFile(filepath.Join(dir, sourceLockName), nil, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(filepath.Join(dir, "music", "file"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := sampleSourceObject(ctx, root, "music/file", int64(len(data)), 4*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(data)
	if got.SHA256 != hex.EncodeToString(want[:]) || got.Size != int64(len(data)) || got.Inode == 0 {
		t.Fatal("wrong candidate digest")
	}
	if err = os.WriteFile(filepath.Join(dir, "music", "empty"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	empty, err := sampleSourceObject(ctx, root, "music/empty", 0, 4*1024*1024)
	if err != nil {
		t.Fatal("empty source", err)
	}
	emptyHash := sha256.Sum256(nil)
	if empty.Size != 0 || empty.SHA256 != hex.EncodeToString(emptyHash[:]) {
		t.Fatal("empty source digest")
	}
	after, err := os.Stat(filepath.Join(dir, "music", "file"))
	if err != nil || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("source changed", err)
	}
	if err = os.Symlink(".", filepath.Join(dir, "music", "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err = sampleSourceObject(ctx, root, "music/alias/file", int64(len(data)), 4*1024*1024); err == nil {
		t.Fatal("symlink parent accepted")
	}
}

func TestSourceSamplerRejectsChangeDuringUnlockedHash(t *testing.T) {
	dir := t.TempDir()
	data := bytes.Repeat([]byte{1}, 512*1024)
	if err := os.Mkdir(filepath.Join(dir, "music"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "music", "file"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sourceLockName), nil, 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	done := make(chan error, 1)
	go func() {
		time.Sleep(100 * time.Millisecond)
		file, e := os.OpenFile(filepath.Join(dir, "music", "file"), os.O_WRONLY, 0)
		if e == nil {
			_, e = file.WriteAt([]byte{2}, 0)
			file.Close()
		}
		done <- e
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = sampleSourceObject(ctx, root, "music/file", int64(len(data)), 1024*1024)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if err == nil {
		t.Fatal("in-place source change accepted")
	}
}

func TestSourceSamplerNeverWaitsLongForSourceLock(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "music"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "music", "file"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(dir, sourceLockName), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	if _, err = sampleSourceObject(ctx, root, "music/file", 4, 1024*1024); err == nil {
		t.Fatal("busy lock accepted")
	}
}
