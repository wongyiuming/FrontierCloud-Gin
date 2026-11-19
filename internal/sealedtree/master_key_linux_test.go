//go:build linux

package sealedtree

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func TestIndependentMasterTreeKeyFileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err = OpenTreeSecretFile(root); !errors.Is(err, ErrInvalid) {
		t.Fatal("missing key should fail")
	}
	key, err := CreateTreeSecretFile(root)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	if _, err = CreateTreeSecretFile(root); !errors.Is(err, ErrInvalid) {
		t.Fatal("existing key replaced")
	}
	reopened, err := OpenTreeSecretFile(root)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(reopened)
	if !bytes.Equal(key, reopened) {
		t.Fatal("key changed")
	}
	if err = os.Chmod(dir+"/"+treeKeyFile, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenTreeSecretFile(root); !errors.Is(err, ErrInvalid) {
		t.Fatal("public key file accepted")
	}
}

func TestMasterTreeKeyRejectsSymlinkAndPartialFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := checkPrivateDirectory(root); err != nil {
		t.Fatal(err)
	}
	if err = root.Symlink("other", treeKeyFile); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenTreeSecretFile(root); !errors.Is(err, ErrInvalid) {
		t.Fatal("symlink accepted")
	}
	if _, err = CreateTreeSecretFile(root); !errors.Is(err, ErrInvalid) {
		t.Fatal("symlink overwritten")
	}
	if err = root.Remove(treeKeyFile); err != nil {
		t.Fatal(err)
	}
	f, err := root.OpenFile(treeKeyFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte("partial")); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenTreeSecretFile(root); !errors.Is(err, ErrInvalid) {
		t.Fatal("partial key accepted")
	}
	if _, err = CreateTreeSecretFile(root); !errors.Is(err, ErrInvalid) {
		t.Fatal("partial key silently regenerated")
	}
}

func TestMasterTreeKeyRejectsPublicDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err = CreateTreeSecretFile(root); !errors.Is(err, ErrInvalid) {
		t.Fatal("public directory accepted for creation")
	}
	if _, err = OpenTreeSecretFile(root); !errors.Is(err, ErrInvalid) {
		t.Fatal("public directory accepted for opening")
	}
}
