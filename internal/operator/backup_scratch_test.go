package operator

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSuccessfulBackupScratchCleanupIsPinnedAndNeverFollowsSourceLinks(t *testing.T) {
	parent := t.TempDir()
	workspace, e := os.MkdirTemp(parent, ".fc-backup-")
	if e != nil {
		t.Fatal(e)
	}
	root, e := os.OpenRoot(workspace)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	source := filepath.Join(parent, "source.sql")
	if e = os.WriteFile(source, []byte("retained source bytes"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(filepath.Join(workspace, "deployment"), 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(workspace, "deployment", ".env"), []byte("private scratch"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(source, filepath.Join(workspace, "mysql_dump")); e != nil {
		t.Fatal(e)
	}
	if e = removeBackupScratch(root, workspace); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Lstat(workspace); !os.IsNotExist(e) {
		t.Fatal("scratch not removed", e)
	}
	if raw, e := os.ReadFile(source); e != nil || string(raw) != "retained source bytes" {
		t.Fatal("source link was followed", e)
	}
}

func TestBackupScratchReboundPathIsNotADeletionTarget(t *testing.T) {
	parent := t.TempDir()
	workspace, e := os.MkdirTemp(parent, ".fc-backup-")
	if e != nil {
		t.Fatal(e)
	}
	root, e := os.OpenRoot(workspace)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	if e = os.Rename(workspace, workspace+"-retained"); e != nil {
		t.Fatal(e)
	}
	if e = os.MkdirAll(filepath.Join(workspace, "deployment"), 0700); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(workspace, "deployment", "unknown")
	if e = os.WriteFile(file, []byte("keep"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = removeBackupScratch(root, workspace); e == nil {
		t.Fatal("rebound scratch accepted")
	}
	if raw, e := os.ReadFile(file); e != nil || string(raw) != "keep" {
		t.Fatal("rebound directory was erased", e)
	}
}
