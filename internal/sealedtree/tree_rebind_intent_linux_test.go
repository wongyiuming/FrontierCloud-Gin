//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

func testTreeRebindIntent(t *testing.T, identity string) []byte {
	t.Helper()
	intent := treeRebindIntent{Version: 1, ArchiveSHA: identity, EvidenceMAC: "fixture-evidence", NodeID: "fixture-node", DatabaseDevice: 1, DatabaseInode: 2, FenceDevice: 3, FenceInode: 4}
	mac, err := treeRebindIntentMAC(bytes.Repeat([]byte{42}, 32), intent)
	if err != nil {
		t.Fatal(err)
	}
	intent.MAC = mac
	raw, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func requireIntentFile(t *testing.T, root *os.Root, want []byte) {
	t.Helper()
	info, err := root.Lstat(treeRebindIntentName)
	if err != nil || !privateBindingFile(info) || info.Mode().Perm() != 0600 {
		t.Fatalf("intent is not one private file: %v", err)
	}
	raw, err := root.ReadFile(treeRebindIntentName)
	if err != nil || !bytes.Equal(raw, want) {
		t.Fatalf("intent bytes differ: %v", err)
	}
}

func TestTreeRebindIntentAtomicPublication(t *testing.T) {
	t.Run("cancel-before-publish-retry", func(t *testing.T) {
		dir := t.TempDir()
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		raw := testTreeRebindIntent(t, "source")
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		err = publishTreeRebindIntent(ctx, root, raw, func() error {
			calls++
			if calls == 2 {
				cancel()
			}
			return nil
		})
		if !errors.Is(err, ErrFenceRequired) {
			t.Fatalf("cancel accepted: %v", err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatalf("cancel left named material: %v %v", entries, err)
		}
		if err = publishTreeRebindIntent(context.Background(), root, raw, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		requireIntentFile(t, root, raw)
	})
	t.Run("cancel-after-publish-preserves-complete-intent", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		raw := testTreeRebindIntent(t, "source")
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		err = publishTreeRebindIntent(ctx, root, raw, func() error {
			calls++
			if calls == 3 {
				cancel()
			}
			return nil
		})
		if !errors.Is(err, ErrFenceRequired) {
			t.Fatalf("cancel accepted: %v", err)
		}
		requireIntentFile(t, root, raw)
		if err = publishTreeRebindIntent(context.Background(), root, raw, func() error { return nil }); !errors.Is(err, os.ErrExist) {
			t.Fatalf("retry replaced existing intent: %v", err)
		}
		requireIntentFile(t, root, raw)
	})
	t.Run("competing-name-never-replaced", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		raw := testTreeRebindIntent(t, "source")
		competing := testTreeRebindIntent(t, "other")
		calls := 0
		err = publishTreeRebindIntent(context.Background(), root, raw, func() error {
			calls++
			if calls == 2 {
				f, openErr := root.OpenFile(treeRebindIntentName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if openErr != nil {
					return openErr
				}
				_, writeErr := f.Write(competing)
				return errors.Join(writeErr, f.Close())
			}
			return nil
		})
		if !errors.Is(err, os.ErrExist) {
			t.Fatalf("competing name was accepted: %v", err)
		}
		requireIntentFile(t, root, competing)
	})
	t.Run("concurrent-writers-publish-exactly-once", func(t *testing.T) {
		dir := t.TempDir()
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		const workers = 8
		values := make([][]byte, workers)
		for i := range values {
			values[i] = testTreeRebindIntent(t, fmt.Sprintf("source-%d", i))
		}
		errs := make(chan error, workers)
		var wg sync.WaitGroup
		for i := range values {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				errs <- publishTreeRebindIntent(context.Background(), root, values[i], func() error { return nil })
			}(i)
		}
		wg.Wait()
		close(errs)
		successes := 0
		for err := range errs {
			if err == nil {
				successes++
			} else if !errors.Is(err, os.ErrExist) {
				t.Fatalf("unexpected publish result: %v", err)
			}
		}
		if successes != 1 {
			t.Fatalf("published %d intents", successes)
		}
		got, err := root.ReadFile(treeRebindIntentName)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, value := range values {
			found = found || bytes.Equal(got, value)
		}
		if !found {
			t.Fatal("published intent is not one complete input")
		}
		requireIntentFile(t, root, got)
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 1 || entries[0].Name() != treeRebindIntentName {
			t.Fatalf("unexpected named publication material: %v %v", entries, err)
		}
	})
}

func TestTreeRebindIntentCrashBeforePublish(t *testing.T) {
	if directory := os.Getenv("FC_TEST_TREE_INTENT_CRASH_DIR"); directory != "" {
		root, err := os.OpenRoot(directory)
		if err != nil {
			os.Exit(71)
		}
		calls := 0
		_ = publishTreeRebindIntent(context.Background(), root, []byte("complete-intent"), func() error {
			calls++
			if calls == 2 {
				os.Exit(73)
			}
			return nil
		})
		os.Exit(74)
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestTreeRebindIntentCrashBeforePublish$", "-test.count=1")
	cmd.Env = append(os.Environ(), "FC_TEST_TREE_INTENT_CRASH_DIR="+dir)
	if err := cmd.Run(); err == nil {
		t.Fatal("crash helper unexpectedly succeeded")
	} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 73 {
		t.Fatalf("crash helper failed before interruption: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("crash left named material: %v %v", entries, err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	raw := testTreeRebindIntent(t, filepath.Base(dir))
	if err = publishTreeRebindIntent(context.Background(), root, raw, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	requireIntentFile(t, root, raw)
}

func TestTreeRebindIntentCrashAfterPublish(t *testing.T) {
	if directory := os.Getenv("FC_TEST_TREE_INTENT_PUBLISHED_DIR"); directory != "" {
		root, err := os.OpenRoot(directory)
		if err != nil {
			os.Exit(71)
		}
		calls := 0
		_ = publishTreeRebindIntent(context.Background(), root, []byte("complete-intent"), func() error {
			calls++
			if calls == 3 {
				os.Exit(73)
			}
			return nil
		})
		os.Exit(74)
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestTreeRebindIntentCrashAfterPublish$", "-test.count=1")
	cmd.Env = append(os.Environ(), "FC_TEST_TREE_INTENT_PUBLISHED_DIR="+dir)
	if err := cmd.Run(); err == nil {
		t.Fatal("crash helper unexpectedly succeeded")
	} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 73 {
		t.Fatalf("crash helper failed before interruption: %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	requireIntentFile(t, root, []byte("complete-intent"))
	if err = publishTreeRebindIntent(context.Background(), root, []byte("replacement"), func() error { return nil }); !errors.Is(err, os.ErrExist) {
		t.Fatalf("published intent was replaced: %v", err)
	}
	requireIntentFile(t, root, []byte("complete-intent"))
}
