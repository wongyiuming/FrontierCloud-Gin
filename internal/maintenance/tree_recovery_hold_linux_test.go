//go:build linux

package maintenance

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestTreeRecoveryHoldBindingAndGate(t *testing.T) {
	ctx := context.Background()
	gate, dir := fixture(t)
	good := strings.Repeat("a", 64)
	if err := gate.HoldTreeRecovery(ctx, good); !errors.Is(err, ErrState) {
		t.Fatalf("hold admitted without native maintenance: %v", err)
	}
	if err := gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("g", 64)} {
		if err := gate.HoldTreeRecovery(ctx, bad); !errors.Is(err, ErrState) {
			t.Fatalf("invalid binding %q accepted: %v", bad, err)
		}
	}
	if err := gate.HoldTreeRecovery(ctx, good); err != nil {
		t.Fatal(err)
	}
	if err := gate.HoldTreeRecovery(ctx, good); err != nil {
		t.Fatalf("same binding retry: %v", err)
	}
	if err := gate.HoldTreeRecovery(ctx, strings.Repeat("b", 64)); !errors.Is(err, ErrState) {
		t.Fatalf("different binding accepted: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, TreeRecoveryHold))
	if err != nil || string(raw) != treeRecoveryHoldPrefix+good+"\n" {
		t.Fatalf("hold changed: %q %v", raw, err)
	}
	if err := gate.Resume(ctx, func(context.Context) error { t.Fatal("resume callback ran"); return nil }); !errors.Is(err, ErrState) {
		t.Fatalf("hold did not prevent resume: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, Marker)); err != nil {
		t.Fatal(err)
	}
	other, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err = other.Runtime(ctx); !errors.Is(err, ErrState) {
		t.Fatalf("hold did not prevent restart with marker absent: %v", err)
	}
}

func TestTreeRecoveryHoldConcurrentPlansAndCancellation(t *testing.T) {
	gate, dir := fixture(t)
	if err := gate.Enter(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := gate.HoldTreeRecovery(canceled, strings.Repeat("c", 64)); err == nil {
		t.Fatal("canceled hold succeeded")
	}
	if _, err := os.Lstat(filepath.Join(dir, TreeRecoveryHold)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled hold published: %v", err)
	}
	other, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	results := make(chan error, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, g := range []*Gate{gate, other} {
		binding := strings.Repeat(string(rune('a'+i)), 64)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- g.HoldTreeRecovery(context.Background(), binding)
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	success, denied := 0, 0
	for result := range results {
		if result == nil {
			success++
		} else if errors.Is(result, ErrState) {
			denied++
		} else {
			t.Fatalf("unexpected result: %v", result)
		}
	}
	if success != 1 || denied != 1 {
		t.Fatalf("success=%d denied=%d", success, denied)
	}
}

func TestTreeRecoveryHoldUnsafeObjectsFailClosed(t *testing.T) {
	for _, kind := range []string{"wrong-content", "directory", "symlink", "hardlink", "permissions"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			gate, dir := fixture(t)
			if err := gate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(dir, TreeRecoveryHold)
			good := strings.Repeat("a", 64)
			raw := []byte(treeRecoveryHoldPrefix + good + "\n")
			var err error
			switch kind {
			case "wrong-content":
				err = os.WriteFile(name, []byte("bad"), 0600)
			case "directory":
				err = os.Mkdir(name, 0700)
			case "symlink":
				err = os.Symlink("missing", name)
			case "hardlink":
				other := filepath.Join(dir, "other")
				if err = os.WriteFile(other, raw, 0600); err == nil {
					err = os.Link(other, name)
				}
			case "permissions":
				if err = os.WriteFile(name, raw, 0600); err == nil {
					err = os.Chmod(name, 0644)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = gate.HoldTreeRecovery(ctx, good); !errors.Is(err, ErrState) {
				t.Fatalf("unsafe hold accepted: %v", err)
			}
			if err = gate.Resume(ctx, func(context.Context) error { return nil }); !errors.Is(err, ErrState) {
				t.Fatalf("unsafe hold allowed resume: %v", err)
			}
			if err = os.Remove(filepath.Join(dir, Marker)); err != nil {
				t.Fatal(err)
			}
			if _, err = gate.Runtime(ctx); !errors.Is(err, ErrState) {
				t.Fatalf("unsafe hold allowed runtime: %v", err)
			}
		})
	}
}

// A process exit at either publication boundary must leave either no named
// marker or an exact complete marker that the ordinary API can retry.
func TestTreeRecoveryHoldCrashPublication(t *testing.T) {
	if dir := os.Getenv("FC_TEST_TREE_HOLD_DIR"); dir != "" {
		gate, err := Open(dir)
		if err != nil {
			os.Exit(91)
		}
		n := 0
		_ = gate.publishTreeRecoveryHold(context.Background(), []byte(treeRecoveryHoldPrefix+strings.Repeat("a", 64)+"\n"), func() error {
			n++
			if os.Getenv("FC_TEST_TREE_HOLD_PHASE") == "before" && n == 1 || os.Getenv("FC_TEST_TREE_HOLD_PHASE") == "after" && n == 2 {
				os.Exit(23)
			}
			return nil
		})
		os.Exit(92)
	}
	for _, phase := range []string{"before", "after"} {
		t.Run(phase, func(t *testing.T) {
			gate, dir := fixture(t)
			if err := gate.Enter(context.Background(), func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestTreeRecoveryHoldCrashPublication$")
			cmd.Env = append(os.Environ(), "FC_TEST_TREE_HOLD_DIR="+dir, "FC_TEST_TREE_HOLD_PHASE="+phase)
			err := cmd.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 23 {
				t.Fatalf("unexpected child result: %v", err)
			}
			name := filepath.Join(dir, TreeRecoveryHold)
			_, err = os.Lstat(name)
			if phase == "before" && !errors.Is(err, os.ErrNotExist) || phase == "after" && err != nil {
				t.Fatalf("unexpected publication state: %v", err)
			}
			if err = gate.HoldTreeRecovery(context.Background(), strings.Repeat("a", 64)); err != nil {
				t.Fatalf("retry after %s crash: %v", phase, err)
			}
		})
	}
}
