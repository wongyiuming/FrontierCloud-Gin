//go:build linux

package operator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

func TestRetainedTreeJournalResumesWithoutReplacingBoundInodes(t *testing.T) {
	ctx := context.Background()
	dir, root, binding := retainedTreeJournalFixture(t)
	crash := errors.New("interrupted after publishing intent")
	missingSnapshot := errors.New("retained snapshot missing")
	var snapshotErr error
	retained, installed, rebound := 0, 0, 0
	steps := retainedTreeSteps{
		database: "database", fenced: func(c context.Context, run func(context.Context, *os.Root) error) error { return run(c, root) },
		retain:         func(context.Context) error { retained++; return nil },
		verifyRetained: func(context.Context) error { return snapshotErr },
		install:        func(context.Context) error { installed++; return nil },
		repair:         func(context.Context) error { t.Fatal("published intent admitted SQLite replacement"); return nil },
		rebind: func(context.Context) error {
			rebound++
			if rebound == 1 {
				// The real runtime authenticates the marker. This test models its
				// publication point and the loss of the response to the host.
				if err := root.WriteFile(sealedtree.MasterRebindIntentFile, []byte("published intent"), 0600); err != nil {
					return err
				}
				return crash
			}
			return nil
		},
	}
	if _, err := advanceRetainedTreeState(ctx, dir, binding, steps); !errors.Is(err, crash) {
		t.Fatalf("missing simulated interruption: %v", err)
	}
	before, err := readRetainedTreeProgress(dir, binding)
	if err != nil || before.Phase != treeRebinding {
		t.Fatal(before, err)
	}
	snapshotErr = missingSnapshot
	if _, err = advanceRetainedTreeState(ctx, dir, binding, steps); !errors.Is(err, missingSnapshot) || rebound != 1 {
		t.Fatal("missing failed snapshot allowed rebind retry", err, rebound)
	}
	snapshotErr = nil
	after, err := advanceRetainedTreeState(ctx, dir, binding, steps)
	if err != nil || after.Phase != treeReboundFenced || after.Database != before.Database || after.Fence != before.Fence || retained != 1 || installed != 1 || rebound != 2 {
		t.Fatal(after, err, retained, installed, rebound)
	}
	if err = root.WriteFile(sealedtree.MasterRebindIntentFile, []byte("changed marker"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = advanceRetainedTreeState(ctx, dir, binding, steps); err == nil {
		t.Fatal("persisted completion accepted a changed rebind marker")
	}
}

func TestRetainedTreeJournalResumesInterruptedPreIntentSQLiteRepair(t *testing.T) {
	ctx := context.Background()
	dir, root, binding := retainedTreeJournalFixture(t)
	crash := errors.New("simulated interruption")
	installed, repaired, rebound := 0, 0, 0
	steps := retainedTreeSteps{
		database: "database", fenced: func(c context.Context, run func(context.Context, *os.Root) error) error { return run(c, root) },
		retain:         func(context.Context) error { return nil },
		verifyRetained: func(context.Context) error { return nil },
		install:        func(context.Context) error { installed++; return nil },
		repair: func(context.Context) error {
			repaired++
			if repaired == 1 {
				if err := root.Rename("database", "interrupted-database"); err != nil {
					return err
				}
				if err := root.WriteFile("database", []byte("archive"), 0600); err != nil {
					return err
				}
				return crash
			}
			return nil
		},
		rebind: func(context.Context) error {
			rebound++
			if rebound == 1 {
				if err := root.WriteFile("database-wal", []byte("sqlite sidecar"), 0600); err != nil {
					return err
				}
				return crash
			}
			return root.WriteFile(sealedtree.MasterRebindIntentFile, []byte("published"), 0600)
		},
	}
	for _, phase := range []string{treeRebinding, treeRepairingSQLite} {
		if _, err := advanceRetainedTreeState(ctx, dir, binding, steps); !errors.Is(err, crash) {
			t.Fatalf("missing simulated interruption in %s: %v", phase, err)
		}
		if state, err := readRetainedTreeProgress(dir, binding); err != nil || state.Phase != phase {
			t.Fatal(state, err)
		}
	}
	before, err := readRetainedTreeProgress(dir, binding)
	if err != nil {
		t.Fatal(err)
	}
	after, err := advanceRetainedTreeState(ctx, dir, binding, steps)
	if err != nil || after.Phase != treeReboundFenced || after.Database == before.Database || after.Fence != before.Fence || installed != 1 || repaired != 2 || rebound != 2 {
		t.Fatal(after, err, installed, repaired, rebound)
	}
}

func retainedTreeJournalFixture(t *testing.T) (string, *os.Root, string) {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	if err = root.Mkdir(sealedtree.MasterFenceDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"database", sealedtree.MasterStatePaths()[0]} {
		if err = root.WriteFile(file, []byte(file), 0600); err != nil {
			t.Fatal(err)
		}
	}
	binding := strings.Repeat("a", 64)
	if err = exclusiveJSON(filepath.Join(dir, treeRetainedJournal), retainedTreeProgress{Version: 1, Binding: binding, Phase: treePreparing}); err != nil {
		t.Fatal(err)
	}
	return dir, root, binding
}
