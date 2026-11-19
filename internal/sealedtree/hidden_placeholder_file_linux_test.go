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

func TestOrphanHiddenRuleToFileRecoversAtomically(t *testing.T) {
	ctx := context.Background()
	db, s, root, _, _ := fencedFixture(t)
	music := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "music"}
	if err := s.CreateDirectoryWithFacts(ctx, music, Facts{ObjectID: music.ObjectID}); err != nil {
		t.Fatal(err)
	}
	ghost, err := s.StageHiddenDirectoryRuleForImport(ctx, "music/later.mp3", "2026-01-01")
	if err != nil {
		t.Fatal(err)
	}
	entry := Entry{ParentID: music.ObjectID, ObjectID: strings.Repeat("c", 64), Kind: "audio", Name: "later.mp3"}
	loc := fixturePlacement(t, entry.ObjectID)
	sum := sha256.Sum256(nil)
	loc.Bytes, loc.SHA256, loc.BlobID, loc.ReadAlias = 0, hex.EncodeToString(sum[:]), "", ""
	prepared, err := s.PrepareFileForHiddenRuleWithFreshLocators(ctx, ghost, entry, loc, Facts{ObjectID: entry.ObjectID})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state, found, err := s.FindPendingObjectWithLease(ctx, lease, entry.ObjectID)
	if err != nil || !found || state.OperationID != prepared.OperationID || state.Facts.PendingPlaceholder == nil || state.Facts.PendingPlaceholder.ObjectID != ghost {
		t.Fatal("pending recovery", err)
	}
	lease.Release()
	if _, err = db.Exec(`CREATE TRIGGER fail_hidden_file BEFORE INSERT ON sealed_tree_placements BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	pub, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.PublishPending(ctx, prepared.OperationID, pub, bytes.NewReader(nil)); err == nil {
		t.Fatal("injected commit accepted")
	}
	if _, err = db.Exec(`DROP TRIGGER fail_hidden_file`); err != nil {
		t.Fatal(err)
	}
	if again, e := s.StageHiddenDirectoryRuleForImport(ctx, "music/later.mp3", "2026-01-01"); e != nil || again != ghost {
		t.Fatal("old rule lost on rollback", e)
	}
	if err = s.PublishPending(ctx, prepared.OperationID, pub, bytes.NewReader(nil)); err != nil {
		t.Fatal("retry", err)
	}
	if err = s.PublishPending(ctx, prepared.OperationID, pub, bytes.NewReader(nil)); err != nil {
		t.Fatal("completed retry", err)
	}
	facts, _, err := s.GetFacts(ctx, entry.ObjectID)
	if err != nil || facts.PendingPlaceholder != nil || facts.Visibility == nil || facts.Visibility.Hidden != 1 || facts.Visibility.UpdatedAt != "2026-01-01" {
		t.Fatal("rule not retained", err)
	}
	if _, _, err = s.Get(ctx, ghost); err == nil {
		t.Fatal("internal placeholder retained after commit")
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if _, err = s.ReadVisibleObjectWithLease(ctx, lease, entry.ObjectID); !errors.Is(err, ErrHidden) {
		t.Fatal("hidden file became readable", err)
	}
	items, _, err := s.ListCatalogPageWithLease(ctx, lease, music.ObjectID, "", 10, true)
	if err != nil || len(items) != 1 || items[0].Entry.ObjectID != entry.ObjectID {
		t.Fatal("hidden catalog display", err)
	}
}

func TestOrphanHiddenRuleCannotBecomeFileWithChildren(t *testing.T) {
	ctx := context.Background()
	_, s, _, _, _ := fencedFixture(t)
	music := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "music"}
	if err := s.CreateDirectoryWithFacts(ctx, music, Facts{ObjectID: music.ObjectID}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StageHiddenDirectoryRuleForImport(ctx, "music/future/child", "2026-01-01"); err != nil {
		t.Fatal(err)
	}
	ghost, _, err := s.Find(ctx, music.ObjectID, "future")
	if err != nil {
		t.Fatal(err)
	}
	entry := Entry{ParentID: music.ObjectID, ObjectID: strings.Repeat("c", 64), Kind: "audio", Name: "future"}
	loc := fixturePlacement(t, entry.ObjectID)
	loc.BlobID, loc.ReadAlias = "", ""
	if _, err = s.PrepareFileForHiddenRuleWithFreshLocators(ctx, ghost.ObjectID, entry, loc, Facts{ObjectID: entry.ObjectID}); !errors.Is(err, ErrConflict) {
		t.Fatal("non-leaf placeholder became file", err)
	}
}
