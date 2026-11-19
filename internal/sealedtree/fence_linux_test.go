//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fencedFixture(t *testing.T) (*sql.DB, *SQLStore, *os.Root, string, string) {
	t.Helper()
	db, s, dbPath := sqliteFixture(t)
	s.unsafePrototype = false
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	if _, err = InitializeFence(context.Background(), s, root, dir); err != nil {
		t.Fatal(err)
	}
	return db, s, root, dbPath, dir
}

func TestFencedVisibleObjectReadKeepsPlacementAndVisibilityTogether(t *testing.T) {
	ctx := context.Background()
	db, s, root, _, _ := fencedFixture(t)
	dir := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("c", 64), Kind: "directory", Name: "album"}
	if err := s.CreateDirectoryWithFacts(ctx, dir, Facts{ObjectID: dir.ObjectID}); err != nil {
		t.Fatal(err)
	}
	entry := Entry{ParentID: dir.ObjectID, ObjectID: strings.Repeat("b", 64), Kind: "audio", Name: "track.mp3"}
	content := []byte("synthetic audio")
	sum := sha256.Sum256(content)
	loc := fixturePlacement(t, entry.ObjectID)
	loc.Bytes, loc.SHA256 = int64(len(content)), hex.EncodeToString(sum[:])
	loc.BlobID, loc.ReadAlias = "", ""
	prepared, err := s.PrepareFileWithFreshLocators(ctx, entry, loc, Facts{ObjectID: entry.ObjectID})
	if err != nil {
		t.Fatal(err)
	}
	loc.BlobID, loc.ReadAlias = prepared.BlobID, prepared.ReadAlias
	pub, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.PublishPending(ctx, prepared.OperationID, pub, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, other, _, _, _ := fencedFixture(t)
	if _, err = other.ReadVisibleObjectWithLease(ctx, lease, entry.ObjectID); !errors.Is(err, ErrFenceRequired) {
		t.Fatalf("foreign namespace lease accepted: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = s.ReadVisibleObjectWithLease(cancelled, lease, entry.ObjectID); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled read accepted: %v", err)
	}
	got, err := s.ReadVisibleObjectWithLease(ctx, lease, entry.ObjectID)
	if err != nil || got.Path != "album/track.mp3" || got.Entry != entry || got.EntryRevision != 1 || got.FactsRevision != 1 || got.PlacementRevision != 1 || got.Facts.ObjectID != entry.ObjectID || got.Placement.BlobID != loc.BlobID {
		t.Fatalf("inconsistent protected view: %v", err)
	}
	byAlias, err := s.ReadVisibleObjectByAliasWithLease(ctx, lease, loc.ReadAlias)
	if err != nil || byAlias.Entry != entry || byAlias.Placement.BlobID != loc.BlobID || byAlias.Placement.ReadAlias != loc.ReadAlias {
		t.Fatal("alias did not resolve to the authenticated placement", err)
	}
	if value, err := s.ReadVisibleObjectByAliasWithLease(ctx, lease, strings.Repeat("d", 64)); !errors.Is(err, ErrInvalid) || value.Path != "" {
		t.Fatal("unknown alias returned a result", err)
	}
	lease.Release()
	if _, err = s.ReadVisibleObjectWithLease(ctx, lease, entry.ObjectID); !errors.Is(err, ErrFenceChanged) {
		t.Fatalf("released lease accepted: %v", err)
	}
	if _, err = s.SetFacts(ctx, Facts{ObjectID: dir.ObjectID, Visibility: &VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}}, 1); err != nil {
		t.Fatal(err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadVisibleObjectWithLease(ctx, lease, entry.ObjectID); !errors.Is(err, ErrHidden) {
		t.Fatalf("hidden ancestor was exposed: %v", err)
	}
	if _, err = s.ReadVisibleObjectByAliasWithLease(ctx, lease, loc.ReadAlias); !errors.Is(err, ErrHidden) {
		t.Fatalf("alias bypassed hidden ancestor: %v", err)
	}
	lease.Release()
	if _, err = s.SetFacts(ctx, Facts{ObjectID: dir.ObjectID}, 2); err != nil {
		t.Fatal(err)
	}
	aliasIndex, err := s.tree.BlobIndex(loc.ReadAlias)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE sealed_tree_aliases SET object_index=? WHERE alias_index=?`, strings.Repeat("0", 64), aliasIndex); err != nil {
		t.Fatal(err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if value, err := s.ReadVisibleObjectByAliasWithLease(ctx, lease, loc.ReadAlias); !errors.Is(err, ErrInvalid) || value.Path != "" {
		t.Fatal("tampered alias returned a result", err)
	}
	lease.Release()
	objectIndex, err := s.tree.ObjectIndex(entry.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE sealed_tree_aliases SET object_index=? WHERE alias_index=?`, objectIndex, aliasIndex); err != nil {
		t.Fatal(err)
	}
	var sealed []byte
	if err = db.QueryRow(`SELECT sealed FROM sealed_tree_placements`).Scan(&sealed); err != nil || len(sealed) == 0 {
		t.Fatal("missing synthetic placement", err)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err = db.Exec(`UPDATE sealed_tree_placements SET sealed=?`, sealed); err != nil {
		t.Fatal(err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if got, err = s.ReadVisibleObjectWithLease(ctx, lease, entry.ObjectID); err == nil || got.Path != "" || got.Placement.BlobID != "" {
		t.Fatal("tampered placement exposed a partial result")
	}
}

func TestFenceRequiredBeforeMutationOrPhysicalPublication(t *testing.T) {
	ctx := context.Background()
	_, s, _ := sqliteFixture(t)
	s.unsafePrototype = false
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "album"}
	if err := s.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: entry.ObjectID}); !errors.Is(err, ErrFenceRequired) {
		t.Fatal("unfenced write accepted", err)
	}
	if _, err := s.AcquireReadFence(ctx); !errors.Is(err, ErrFenceRequired) {
		t.Fatal("unfenced lease accepted", err)
	}
	if _, err := s.ResolveVisiblePath(ctx, entry.ObjectID); !errors.Is(err, ErrFenceRequired) {
		t.Fatal("unfenced visibility accepted", err)
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	pub, _ := NewBlobPublisher(root)
	if err = s.PublishPending(ctx, strings.Repeat("c", 64), pub, strings.NewReader("")); !errors.Is(err, ErrFenceRequired) {
		t.Fatal("unfenced publisher accepted", err)
	}
	if _, err = root.Stat("staging"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unfenced operation wrote stage", err)
	}
}

func TestFencedStoreRefusesPrototypeIntentWithoutFacts(t *testing.T) {
	ctx := context.Background()
	_, s, root, _, _ := fencedFixture(t)
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("c", 64), Kind: "audio", Name: "synthetic.mp3"}
	loc := fixturePlacement(t, entry.ObjectID)
	s.unsafePrototype = true
	op, err := s.PrepareFile(ctx, entry, loc)
	if err != nil {
		t.Fatal(err)
	}
	s.unsafePrototype = false
	pub, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.PublishPending(ctx, op, pub, strings.NewReader("")); !errors.Is(err, ErrFactsRequired) {
		t.Fatalf("prototype intent was activated: %v", err)
	}
	if _, err = root.Stat("staging"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("prototype intent wrote a physical stage", err)
	}
}

func TestFenceInitializationFailureNeverSilentlyRegenerates(t *testing.T) {
	ctx := context.Background()
	db, s, _ := sqliteFixture(t)
	s.unsafePrototype = false
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err = db.Exec(`CREATE TRIGGER reject_fence BEFORE INSERT ON sealed_tree_fence BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = InitializeFence(ctx, s, root, dir); !errors.Is(err, ErrFenceRequired) {
		t.Fatal("injected binding failure accepted", err)
	}
	if info, err := root.Lstat(treeFenceFile); err != nil || !info.Mode().IsRegular() {
		t.Fatal("partial fence was discarded", err)
	}
	if _, err = db.Exec(`DROP TRIGGER reject_fence`); err != nil {
		t.Fatal(err)
	}
	if _, err = InitializeFence(ctx, s, root, dir); !errors.Is(err, ErrFenceRequired) {
		t.Fatal("partial fence silently regenerated", err)
	}
	var n int
	if err = db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_fence`).Scan(&n); err != nil || n != 0 {
		t.Fatal("failed binding committed", err)
	}
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "album"}
	if err = s.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: entry.ObjectID}); !errors.Is(err, ErrFenceRequired) {
		t.Fatal("write allowed after failed fence initialization", err)
	}
}

func TestFenceReadBlocksWriterAndProtectsVisibleResolution(t *testing.T) {
	ctx := context.Background()
	_, s, _, _, _ := fencedFixture(t)
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "album"}
	if err := s.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: entry.ObjectID}); err != nil {
		t.Fatal(err)
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if path, err := s.ResolveVisibleWithLease(ctx, lease, entry.ObjectID); err != nil || path != "album" {
		t.Fatal("fenced resolve failed", err)
	}
	if err = lease.Check(ctx); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err = lease.Check(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled lease check accepted", err)
	}
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		close(started)
		_, err := s.SetFacts(ctx, Facts{ObjectID: entry.ObjectID, Visibility: &VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}}, 1)
		result <- err
	}()
	<-started
	select {
	case err := <-result:
		t.Fatal("writer passed live read lease", err)
	case <-time.After(100 * time.Millisecond):
	}
	lease.Release()
	lease.Release()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer did not resume")
	}
	if err = lease.Check(ctx); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("released lease accepted", err)
	}
	next, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Release()
	if path, err := s.ResolveVisibleWithLease(ctx, next, entry.ObjectID); !errors.Is(err, ErrHidden) || path != "" {
		t.Fatal("updated hidden rule not enforced", err)
	}
}

func TestFenceDetectsReplacedInodeAndUnfencedGenerationChange(t *testing.T) {
	ctx := context.Background()
	db, s, root, _, _ := fencedFixture(t)
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE sealed_tree_meta SET write_fence=write_fence+1 WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	if err = lease.Check(ctx); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("unfenced database generation change accepted", err)
	}
	lease.Release()
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	original, err := root.Open(treeFenceFile)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err = original.Read(id); err != nil {
		t.Fatal(err)
	}
	_ = original.Close()
	if err = root.Rename(treeFenceFile, "prior-fence"); err != nil {
		t.Fatal(err)
	}
	newFile, err := root.OpenFile(treeFenceFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = newFile.Write(id); err != nil {
		t.Fatal(err)
	}
	_ = newFile.Close()
	if err = lease.Check(ctx); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("replaced fence inode accepted", err)
	}
	lease.Release()
	reopened, err := OpenSQLite(ctx, db, fixture(t), s.rootID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenFence(ctx, reopened, root, root.Name()); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("replaced inode was accepted by a fresh process", err)
	}
}

func TestTreeFenceCrossProcess(t *testing.T) {
	if os.Getenv("FC_TREE_FENCE_CHILD") == "1" {
		db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(os.Getenv("FC_TREE_FENCE_DB"))+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
		if err != nil {
			os.Exit(81)
		}
		defer db.Close()
		s, err := OpenSQLite(context.Background(), db, fixture(t), strings.Repeat("a", 64))
		if err != nil {
			os.Exit(82)
		}
		root, err := os.OpenRoot(os.Getenv("FC_TREE_FENCE_DIR"))
		if err != nil {
			os.Exit(83)
		}
		defer root.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		if _, err = OpenFence(ctx, s, root, os.Getenv("FC_TREE_FENCE_DIR")); err != nil {
			os.Exit(84)
		}
		entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("c", 64), Kind: "directory", Name: "child"}
		err = s.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: entry.ObjectID})
		if errors.Is(err, context.DeadlineExceeded) {
			os.Exit(42)
		}
		if err != nil {
			os.Exit(85)
		}
		os.Exit(0)
	}
	ctx := context.Background()
	_, s, _, dbPath, dir := fencedFixture(t)
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	run := func() error {
		testCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(testCtx, os.Args[0], "-test.run=^TestTreeFenceCrossProcess$")
		cmd.Env = append(os.Environ(), "FC_TREE_FENCE_CHILD=1", "FC_TREE_FENCE_DB="+dbPath, "FC_TREE_FENCE_DIR="+dir)
		return cmd.Run()
	}
	err = run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 42 {
		lease.Release()
		t.Fatalf("other process bypassed fence or failed setup: %v", err)
	}
	lease.Release()
	if err = run(); err != nil {
		t.Fatalf("other process could not proceed after release: %v", err)
	}
	if _, _, err = s.Get(ctx, strings.Repeat("c", 64)); err != nil {
		t.Fatal("child write missing", err)
	}
}
