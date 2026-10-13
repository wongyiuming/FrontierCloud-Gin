package resourceinventory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type contentHookContext struct {
	context.Context
	calls int
	at    int
	hook  func()
}

func (c *contentHookContext) Err() error {
	c.calls++
	if c.calls == c.at {
		c.hook()
	}
	return c.Context.Err()
}
func TestContentObservationActualBytesPathsAndMutation(t *testing.T) {
	dir := t.TempDir()
	if e := os.MkdirAll(filepath.Join(dir, "media", "nested"), 0700); e != nil {
		t.Fatal(e)
	}
	name := "media/nested/hidden.bin"
	file := filepath.Join(dir, filepath.FromSlash(name))
	payload := bytes.Repeat([]byte("fixture ciphertext bytes\x00\xff"), 21000)
	if e := os.WriteFile(file, payload, 0600); e != nil {
		t.Fatal(e)
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	observed, e := ContentAt(context.Background(), root, name, int64(len(payload)))
	sha := sha256.Sum256(payload)
	if e != nil || observed.SHA256 != hex.EncodeToString(sha[:]) || observed.Bytes != int64(len(payload)) {
		t.Fatal("actual byte observation", observed, e)
	}
	if _, e = ContentAt(context.Background(), root, name, int64(len(payload)-1)); e == nil {
		t.Fatal("incorrect declared length accepted")
	}
	for _, bad := range []string{"../secret", "media/nested/../hidden.bin", "/etc/passwd", "C:/secret", "media\\nested\\hidden.bin"} {
		if _, e = ContentAt(context.Background(), root, bad, 0); e == nil {
			t.Fatal("invalid path", bad)
		}
	}
	if e = os.Symlink(file, filepath.Join(dir, "link")); e != nil {
		t.Fatal(e)
	}
	if _, e = ContentAt(context.Background(), root, "link", int64(len(payload))); e == nil {
		t.Fatal("symlink followed")
	}
	if e = os.Symlink(filepath.Join(dir, "media"), filepath.Join(dir, "alias")); e != nil {
		t.Fatal(e)
	}
	if _, e = ContentAt(context.Background(), root, "alias/nested/hidden.bin", int64(len(payload))); e == nil {
		t.Fatal("ancestor link followed")
	}
	hook := &contentHookContext{Context: context.Background(), at: 5, hook: func() {
		f, e := os.OpenFile(file, os.O_WRONLY, 0)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.WriteAt([]byte("changed"), 100000); e != nil {
			t.Fatal(e)
		}
		f.Close()
		future := time.Now().Add(time.Hour)
		if e = os.Chtimes(file, future, future); e != nil {
			t.Fatal(e)
		}
	}}
	if value, e := ContentAt(hook, root, name, int64(len(payload))); !errors.Is(e, ErrChanged) || value.SHA256 != "" {
		t.Fatal("mutation accepted", value, e)
	}
	if e = os.WriteFile(file, payload, 0600); e != nil {
		t.Fatal(e)
	}
	hook = &contentHookContext{Context: context.Background(), at: 5, hook: func() {
		if e = os.Rename(file, file+".old"); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(file, payload, 0600); e != nil {
			t.Fatal(e)
		}
	}}
	if value, e := ContentAt(hook, root, name, int64(len(payload))); !errors.Is(e, ErrChanged) || value.SHA256 != "" {
		t.Fatal("path replacement accepted", value, e)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = ContentAt(canceled, root, name, int64(len(payload))); !errors.Is(e, context.Canceled) {
		t.Fatal("cancel ignored", e)
	}
	if e = os.WriteFile(filepath.Join(dir, "empty"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	empty, e := ContentAt(context.Background(), root, "empty", 0)
	sum := sha256.Sum256(nil)
	if e != nil || empty.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("empty observation", empty, e)
	}
}
