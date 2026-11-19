//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
)

func TestTreeBackupRuntimeInspectReportsOnlyBoundMountIdentity(t *testing.T) {
	base := t.TempDir()
	var paths [3]string
	for i, n := range []string{"data", "secrets", "tmp"} {
		paths[i] = filepath.Join(base, n)
		if err := os.Mkdir(paths[i], 0700); err != nil {
			t.Fatal(err)
		}
	}
	secret := []byte("never-print-secret-fixture")
	if err := os.WriteFile(filepath.Join(paths[1], "key"), secret, 0600); err != nil {
		t.Fatal(err)
	}
	nonce := strings.Repeat("a", 64)
	var out bytes.Buffer
	if err := inspectTreeBackupRuntimePaths([]string{nonce}, &out, paths); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out.Bytes(), secret) || strings.Contains(out.String(), base) {
		t.Fatal("inspection leaked file contents or host path")
	}
	var proof runtimefacts.TreeBackupRuntime
	if err := json.Unmarshal(out.Bytes(), &proof); err != nil {
		t.Fatal(err)
	}
	if proof.Nonce != nonce || proof.UID != uint32(os.Geteuid()) || proof.GID != uint32(os.Getegid()) {
		t.Fatal("incorrect identity")
	}
	expected := []runtimefacts.TreeBackupMount{proof.Data, proof.Secrets, proof.Scratch}
	for i, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		st := info.Sys().(*syscall.Stat_t)
		if expected[i] != (runtimefacts.TreeBackupMount{Device: uint64(st.Dev), Inode: st.Ino, UID: st.Uid, GID: st.Gid, Mode: st.Mode}) {
			t.Fatal("incorrect mount identity", i)
		}
	}
	if err := inspectTreeBackupRuntimePaths([]string{strings.Repeat("Z", 64)}, &bytes.Buffer{}, paths); err == nil {
		t.Fatal("invalid nonce accepted")
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(paths[0], link); err != nil {
		t.Fatal(err)
	}
	paths[0] = link
	if err := inspectTreeBackupRuntimePaths([]string{nonce}, &bytes.Buffer{}, paths); err == nil {
		t.Fatal("symlink mount accepted")
	}
}
