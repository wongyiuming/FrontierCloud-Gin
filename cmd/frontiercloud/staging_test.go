package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestStagingReleaseRejectsProductionWithoutCreatingState(t *testing.T) {
	root := t.TempDir()
	t.Setenv("DATA_ROOT", root)
	t.Setenv("STAGING_CD", "false")
	t.Setenv("SQLITE_PATH", filepath.Join(root, "missing.db"))
	var output bytes.Buffer
	if err := stagingReleaseCommand(&output); err == nil {
		t.Fatal("production accepted staging controller")
	}
	if output.Len() != 0 {
		t.Fatal("rejected staging emitted success")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("rejected controller mutated data", entries, err)
	}
}
