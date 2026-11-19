//go:build linux

package sealedtree

import (
	"bufio"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestEmptyDestinationNodeControlFence(t *testing.T) {
	if name := os.Getenv("FRONTIERCLOUD_TEST_EMPTY_CONTROL_LOCK"); name != "" {
		f, err := os.OpenFile(name, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err = unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
			t.Fatal(err)
		}
		fmt.Println("LOCKED")
		_, _ = bufio.NewReader(os.Stdin).ReadByte()
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
		return
	}
	base := t.TempDir()
	for _, name := range []string{"media/music", "media/vido", "media/lyrics", "recordings", "media/.opaque-aliases"} {
		if err := os.MkdirAll(filepath.Join(base, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"media/.node-control.lock", "media/.media-mutation.lock", "media/.opaque-aliases/.owner-control-binding", "media/.opaque-aliases/.owner-control-lock"} {
		if err := os.WriteFile(filepath.Join(base, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	check := func(want bool) {
		t.Helper()
		err := CheckEmptyStorageDestination(root)
		if (err == nil) != want {
			t.Fatalf("empty destination: want=%v got=%v", want, err)
		}
	}
	check(true)
	lock := filepath.Join(base, "media/.node-control.lock")
	child := exec.Command(os.Args[0], "-test.run=^TestEmptyDestinationNodeControlFence$", "-test.timeout=30s")
	child.Env = append(os.Environ(), "FRONTIERCLOUD_TEST_EMPTY_CONTROL_LOCK="+lock)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var childErr error
	go func() { childErr = child.Wait(); close(done) }()
	defer func() {
		_ = stdin.Close()
		_ = child.Process.Kill()
		<-done
	}()
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if line != "LOCKED\n" {
			t.Fatal("child did not lock")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lock startup timeout")
	}
	check(false)
	_ = stdin.Close()
	select {
	case <-done:
		if childErr != nil {
			t.Fatal(childErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lock child did not exit")
	}
	check(true)
	if err = os.WriteFile(lock, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	check(false)
	if err = os.WriteFile(lock, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(lock, 0644); err != nil {
		t.Fatal(err)
	}
	check(false)
	if err = os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(".media-mutation.lock", lock); err != nil {
		t.Fatal(err)
	}
	check(false)
	if err = os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(base, "media/unexpected"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	check(false)
}
