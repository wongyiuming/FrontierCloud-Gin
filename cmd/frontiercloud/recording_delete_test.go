package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOperatorRecordingDeletionRejectsMissingStoreWithoutBootstrap(t *testing.T) {
	root := t.TempDir()
	database := filepath.Join(root, "missing", "native.db")
	t.Setenv("DATA_ROOT", root)
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("SQLITE_PATH", database)
	args := []string{"--confirm-master-id", strings.Repeat("a", 32), "--confirm-storage-id", strings.Repeat("b", 32), "--recording", strings.Repeat("c", 32)}
	var output bytes.Buffer
	if err := deleteStorageRecordingCommand(args, &output); err == nil {
		t.Fatal("missing store bootstrapped")
	}
	if _, err := os.Stat(filepath.Dir(database)); !os.IsNotExist(err) {
		t.Fatal("created database", err)
	}
	if output.Len() != 0 {
		t.Fatal("failed deletion emitted success")
	}
	if err := deleteStorageRecordingCommand([]string{"--recording", "*"}, &output); err == nil {
		t.Fatal("wildcard deletion accepted")
	}
	if err := deleteOwnedRecordingCommand([]string{"--confirm-node-id", strings.Repeat("b", 32), "--relationship", strings.Repeat("a", 32), "--recording", strings.Repeat("c", 32)}, &output); err == nil {
		t.Fatal("owned deletion bootstrapped a missing database")
	}
	if _, err := os.Stat(database); !os.IsNotExist(err) {
		t.Fatal("owned deletion created database", err)
	}
	if err := deleteOwnedRecordingCommand([]string{"--recording", "*"}, &output); err == nil {
		t.Fatal("owned wildcard accepted")
	}
}
