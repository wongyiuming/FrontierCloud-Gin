//go:build linux

package recovery

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestTreeMaterialPublishPreservesExistingTarget(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	root, publish, closeParent, err := openTreeMaterialStage(target)
	if err != nil {
		t.Fatal(err)
	}
	defer closeParent()
	defer root.Close()
	stage := root.Name()
	if err = os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	original, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	if err = publish(context.Background()); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing target was not refused: %v", err)
	}
	if current, err := os.Lstat(target); err != nil || !os.SameFile(original, current) {
		t.Fatalf("existing target changed: %v", err)
	}
	staged, err := root.Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	if current, err := os.Lstat(stage); err != nil || !os.SameFile(staged, current) {
		t.Fatalf("private stage changed: %v", err)
	}
	if err = os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err = publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if current, err := os.Lstat(target); err != nil || !os.SameFile(staged, current) {
		t.Fatalf("wrong directory published: %v", err)
	}
}

func TestTreeMaterialPublishRejectsReplacedParent(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "original")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "target")
	root, publish, closeParent, err := openTreeMaterialStage(target)
	if err != nil {
		t.Fatal(err)
	}
	defer closeParent()
	defer root.Close()
	moved := filepath.Join(base, "moved")
	if err = os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err = publish(context.Background()); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("replaced parent was not refused: %v", err)
	}
	for _, path := range []string{target, filepath.Join(moved, "target")} {
		if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("target was published after parent replacement: %v", err)
		}
	}
}
