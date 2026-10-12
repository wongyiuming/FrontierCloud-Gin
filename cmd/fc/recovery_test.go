package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRestoreCheckAndApplyNeverCreateTargetForInvalidArchive(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "invalid.tar")
	if e := os.WriteFile(input, []byte("not an archive"), 0600); e != nil {
		t.Fatal(e)
	}
	for _, action := range []string{"check", "apply"} {
		target := filepath.Join(root, action)
		code := recoveryCommand(context.Background(), root, []string{"restore", action, "--file", input, "--target", target})
		if code != 2 {
			t.Fatal(code)
		}
		if _, e := os.Stat(target); !os.IsNotExist(e) {
			t.Fatal("invalid archive modified target", e)
		}
	}
}
