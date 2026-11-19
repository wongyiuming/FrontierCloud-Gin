//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestSelectedHiddenDirectoryAtomicAndInherited(t *testing.T) {
	ctx := context.Background()
	db, tree, root, _, _ := fencedFixture(t)
	if err := tree.PrepareSelectedHiddenDirectory(ctx, "music/private"); err != nil {
		t.Fatal(err)
	}
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tree.ResolveVisibleDirectoryWithLease(ctx, lease, "music/private"); !errors.Is(err, ErrHidden) {
		t.Fatal("hidden directory publicly resolvable", err)
	}
	id, err := tree.ResolveDirectoryWithLease(ctx, lease, "music/private", true)
	lease.Release()
	if err != nil || id == "" {
		t.Fatal("Admin hidden directory resolution", err)
	}
	facts, rev, err := tree.GetFacts(ctx, id)
	if err != nil || rev != 1 || facts.Visibility == nil || facts.Visibility.Hidden != 1 || facts.Visibility.UpdatedAt == "" {
		t.Fatal("missing directly hidden encrypted facts", err)
	}
	var before int
	if err = db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_encryption_ids`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err = tree.PrepareSelectedHiddenDirectory(ctx, "music/private"); err != nil {
		t.Fatal("idempotent retry", err)
	}
	if got, err := tree.EnsureSelectedDirectories(ctx, "music/private"); err != nil || got != id {
		t.Fatal("normal upload cannot use hidden ancestor", err)
	}
	var after int
	if err = db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_encryption_ids`).Scan(&after); err != nil || before != after {
		t.Fatal("retry changed encryption reservations", err)
	}
	if _, err = tree.EnsureSelectedDirectories(ctx, "music/visible"); err != nil {
		t.Fatal(err)
	}
	if err = tree.PrepareSelectedHiddenDirectory(ctx, "music/visible"); !errors.Is(err, ErrConflict) {
		t.Fatal("existing visible directory accepted", err)
	}
	if _, err = tree.EnsureSelectedDirectories(ctx, "music/private/visible"); err != nil {
		t.Fatal(err)
	}
	if err = tree.PrepareSelectedHiddenDirectory(ctx, "music/private/visible"); !errors.Is(err, ErrConflict) {
		t.Fatal("inherited hidden state treated as directly hidden", err)
	}
	for _, invalid := range []string{"music", "vido", "lyrics/private", "music/../private", "music/private/too/deep"} {
		if err := tree.PrepareSelectedHiddenDirectory(ctx, invalid); err == nil {
			t.Fatal("invalid hidden directory accepted")
		}
	}
	entry := Entry{ParentID: id, ObjectID: strings.Repeat("b", 64), Kind: "audio", Name: "song.mp3"}
	content := []byte("synthetic hidden audio")
	sum := sha256.Sum256(content)
	placement := fixturePlacement(t, entry.ObjectID)
	placement.BlobID, placement.ReadAlias = "", ""
	placement.Bytes, placement.SHA256 = int64(len(content)), hex.EncodeToString(sum[:])
	prepared, err := tree.PrepareFileWithFreshLocators(ctx, entry, placement, Facts{ObjectID: entry.ObjectID})
	if err != nil {
		t.Fatal("prepare under hidden ancestor", err)
	}
	publisher, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = tree.PublishPending(ctx, prepared.OperationID, publisher, bytes.NewReader(content)); err != nil {
		t.Fatal("publish under hidden ancestor", err)
	}
	lease, err = tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if _, err = tree.ReadVisibleObjectWithLease(ctx, lease, entry.ObjectID); !errors.Is(err, ErrHidden) {
		t.Fatal("file below hidden ancestor visible", err)
	}
}

func TestSelectedHiddenDirectoryRollsBackPartialCreation(t *testing.T) {
	ctx := context.Background()
	db, tree, _, _, _ := fencedFixture(t)
	if _, err := tree.EnsureSelectedDirectories(ctx, "music"); err != nil {
		t.Fatal(err)
	}
	var before int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_records`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER reject_hidden_facts BEFORE INSERT ON sealed_tree_facts BEGIN SELECT RAISE(ABORT,'fixture failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := tree.PrepareSelectedHiddenDirectory(ctx, "music/new/nested"); err == nil {
		t.Fatal("failing transaction succeeded")
	}
	var after int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_records`).Scan(&after); err != nil || before != after {
		t.Fatal("partial directory escaped rollback", err)
	}
	if _, err := db.Exec(`DROP TRIGGER reject_hidden_facts`); err != nil {
		t.Fatal(err)
	}
	if err := tree.PrepareSelectedHiddenDirectory(ctx, "music/new/nested"); err != nil {
		t.Fatal("retry after rollback", err)
	}
}
