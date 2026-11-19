//go:build linux

package maintenance

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func TestOfflineSQLiteCrossUIDProcess(t *testing.T) {
	if root := os.Getenv("FC_TEST_UID_GATE_ROOT"); root != "" {
		expected, err := strconv.Atoi(os.Getenv("FC_TEST_UID_GATE_UID"))
		if err != nil || os.Geteuid() != expected {
			t.Fatal("wrong helper identity")
		}
		gate, err := Open(root)
		if err != nil {
			t.Fatal(err)
		}
		defer gate.Close()
		if err = gate.InspectSQLite(context.Background(), root, filepath.Join(root, "state.sqlite"), func(_ context.Context, check func() error) error { return check() }); err != nil {
			t.Fatal("same owner inspection", err)
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("cross-UID process fixture requires root")
	}
	root, err := os.MkdirTemp("", "fc-gate-uid-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	const uid, gid = 12345, 12345
	if err = os.Chown(root, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(root, "state.sqlite")
	if err = os.WriteFile(database, []byte("isolated-test"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(database, uid, gid); err != nil {
		t.Fatal(err)
	}
	gate, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err = gate.Enter(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err = gate.InspectSQLite(context.Background(), root, database, func(_ context.Context, check func() error) error { return check() }); !errors.Is(err, ErrState) {
		t.Fatal("different owner was accepted", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cmd := exec.Command("/proc/self/fd/3", "-test.run=^TestOfflineSQLiteCrossUIDProcess$", "-test.count=1")
	cmd.ExtraFiles = []*os.File{f}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}}
	cmd.Env = append(os.Environ(), "FC_TEST_UID_GATE_ROOT="+root, fmt.Sprintf("FC_TEST_UID_GATE_UID=%d", uid))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("owner helper failed: %v: %s", err, output)
	}
	info, err := os.Stat(database)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || info.Mode().Perm() != 0600 {
		t.Fatal("database ownership or mode changed")
	}
	raw, err := os.ReadFile(database)
	if err != nil || string(raw) != "isolated-test" {
		t.Fatal("database content changed", err)
	}
}
