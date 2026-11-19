//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

type errorReader struct{ done bool }

func (r *errorReader) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		return copy(p, []byte("short")), nil
	}
	return 0, errors.New("injected read error")
}

func TestPreparedBlobSinglePassAndIdentity(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	pub, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("fixture ciphertext with tag")
	digest := sha256.Sum256(data)
	hash := hex.EncodeToString(digest[:])
	op, blob := strings.Repeat("1", 64), strings.Repeat("2", 64)
	prepared, err := pub.Prepare(context.Background(), op, blob, int64(len(data)), hash, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err = prepared.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = prepared.Close(); err != nil {
		t.Fatal(err)
	}
	path, _ := BlobPath(blob)
	f, err := root.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(f)
	f.Close()
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("different output", err)
	}
}
func TestPreparedBlobRejectsReplacementAndIncomplete(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	pub, _ := NewBlobPublisher(root)
	data := []byte("fixture ciphertext with tag")
	digest := sha256.Sum256(data)
	hash := hex.EncodeToString(digest[:])
	blob := strings.Repeat("2", 64)
	t.Run("reader-error", func(t *testing.T) {
		op := strings.Repeat("3", 64)
		if _, err := pub.Prepare(context.Background(), op, blob, int64(len(data)), hash, &errorReader{}); err == nil {
			t.Fatal("partial input accepted")
		}
		dest, _ := BlobPath(blob)
		if _, err := root.Stat(dest); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("partial input published", err)
		}
	})
	t.Run("path-replaced", func(t *testing.T) {
		op := strings.Repeat("4", 64)
		prepared, err := pub.Prepare(context.Background(), op, blob, int64(len(data)), hash, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		defer prepared.Close()
		stage, _ := stagePath(op)
		if err = root.Remove(stage); err != nil {
			t.Fatal(err)
		}
		f, err := root.OpenFile(stage, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.Write(data)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err = prepared.Publish(context.Background()); err == nil {
			t.Fatal("replacement accepted")
		}
		dest, _ := BlobPath(blob)
		if _, err = root.Stat(dest); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("replacement published", err)
		}
	})
	t.Run("same-inode-size-changed", func(t *testing.T) {
		op := strings.Repeat("5", 64)
		prepared, err := pub.Prepare(context.Background(), op, blob, int64(len(data)), hash, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		defer prepared.Close()
		stage, _ := stagePath(op)
		f, err := root.OpenFile(stage, os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.Write([]byte("x"))
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err = prepared.Publish(context.Background()); err == nil {
			t.Fatal("concurrent modification accepted")
		}
		dest, _ := BlobPath(blob)
		if _, err = root.Stat(dest); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("changed inode published", err)
		}
	})
}
