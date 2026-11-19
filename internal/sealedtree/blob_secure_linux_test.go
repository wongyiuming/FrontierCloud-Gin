//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestBlobRecoveryRejectsSymlinkLeavesAndParents(t *testing.T) {
	data := []byte("opaque-test-data")
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	ctx := context.Background()
	for _, which := range []string{"destination", "stage", "parent"} {
		t.Run(which, func(t *testing.T) {
			dir := t.TempDir()
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			pub, _ := NewBlobPublisher(root)
			op := strings.Repeat("a", 64)
			blob := strings.Repeat("b", 64)
			if err = pub.Stage(ctx, op, blob, int64(len(data)), digest, bytes.NewReader(data)); err != nil {
				t.Fatal(err)
			}
			dest, _ := BlobPath(blob)
			stage := "staging/" + op + ".part"
			outside := filepath.Join(t.TempDir(), "outside")
			if err = os.WriteFile(outside, data, 0600); err != nil {
				t.Fatal(err)
			}
			switch which {
			case "destination":
				if err = os.Symlink(outside, filepath.Join(dir, filepath.FromSlash(dest))); err != nil {
					t.Fatal(err)
				}
			case "stage":
				if err = root.Remove(stage); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(outside, filepath.Join(dir, filepath.FromSlash(stage))); err != nil {
					t.Fatal(err)
				}
			case "parent":
				parent := filepath.Dir(filepath.Join(dir, filepath.FromSlash(dest)))
				moved := parent + ".moved"
				if err = os.Rename(parent, moved); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(moved, parent); err != nil {
					t.Fatal(err)
				}
			}
			if err = pub.PublishStaged(ctx, op, blob, int64(len(data)), digest); err == nil {
				t.Fatal("symlink publication accepted")
			}
			actual, err := os.ReadFile(outside)
			if err != nil || !bytes.Equal(actual, data) {
				t.Fatal("outside file changed", err)
			}
		})
	}
}

func TestBlobLinkRejectsStageInodeReplacement(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err = root.MkdirAll("staging", 0700); err != nil {
		t.Fatal(err)
	}
	if err = root.MkdirAll("objects/bb/bb", 0700); err != nil {
		t.Fatal(err)
	}
	source := "staging/operation.part"
	target := "objects/bb/bb/object.blob"
	if err = os.WriteFile(filepath.Join(dir, filepath.FromSlash(source)), []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	old, err := blobOpen(root, source, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	info, err := old.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err = root.Rename(source, source+".old"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, filepath.FromSlash(source)), []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = blobLink(root, source, target, info, false); err == nil {
		t.Fatal("different inode accepted")
	}
	if _, err = root.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("unexpected target: %v", err)
	}
}

func TestBlobOpenRejectsFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err = unix.Mkfifo(filepath.Join(dir, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- verifyBlob(context.Background(), root, "fifo", 0, strings.Repeat("0", 64)) }()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO blocked verification")
	}
}
