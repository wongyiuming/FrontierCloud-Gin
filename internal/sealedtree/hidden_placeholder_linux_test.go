//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestOrphanHiddenRuleIsPrivateAndSurvivesParentMove(t *testing.T) {
	ctx := context.Background()
	db, s, root, dbPath, _ := fencedFixture(t)
	music := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "music"}
	album := Entry{ParentID: music.ObjectID, ObjectID: strings.Repeat("c", 64), Kind: "directory", Name: "album"}
	for _, entry := range []Entry{music, album} {
		if err := s.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: entry.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	id, err := s.StageHiddenDirectoryRuleForImport(ctx, "music/album/unborn", "2026-01-01")
	if err != nil {
		t.Fatal(err)
	}
	if again, e := s.StageHiddenDirectoryRuleForImport(ctx, "music/album/unborn", "2026-01-01"); e != nil || again != id {
		t.Fatal("idempotent staging", e)
	}
	reopened, e := OpenSQLite(ctx, db, fixture(t), s.rootID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = OpenFence(ctx, reopened, root, root.Name()); e != nil {
		t.Fatal(e)
	}
	s = reopened
	if again, e := s.StageHiddenDirectoryRuleForImport(ctx, "music/album/unborn", "2026-01-01"); e != nil || again != id {
		t.Fatal("reopened staging", e)
	}
	if _, e = db.Exec(`CREATE TRIGGER reject_hidden_insert BEFORE INSERT ON sealed_tree_facts BEGIN SELECT RAISE(ABORT,'fixture'); END`); e != nil {
		t.Fatal(e)
	}
	if _, e = s.StageHiddenDirectoryRuleForImport(ctx, "music/album/another/nested", "2026-01-01"); e == nil {
		t.Fatal("failed staging committed")
	}
	if _, e = db.Exec(`DROP TRIGGER reject_hidden_insert`); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Find(ctx, album.ObjectID, "another"); e == nil {
		t.Fatal("partial placeholder persisted")
	}
	for _, name := range []string{dbPath, dbPath + "-wal"} {
		raw, e := os.ReadFile(name)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		if bytes.Contains(raw, []byte("unborn")) || bytes.Contains(raw, []byte("music/album")) {
			t.Fatal("placeholder rule leaked to SQLite")
		}
	}
	if _, err = s.SetFacts(ctx, Facts{ObjectID: id}, 1); err == nil {
		t.Fatal("generic update promoted placeholder")
	}
	blocked := Entry{ParentID: id, ObjectID: strings.Repeat("d", 64), Kind: "directory", Name: "child"}
	if err = s.CreateDirectoryWithFacts(ctx, blocked, Facts{ObjectID: blocked.ObjectID}); err == nil {
		t.Fatal("unpromoted placeholder accepted as parent")
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, include := range []bool{false, true} {
		if items, next, e := s.ListDirectoryWithLease(ctx, lease, album.ObjectID, "", 5, include); e != nil || len(items) != 0 || next != "" {
			t.Fatal("placeholder exposed in catalog", e)
		}
		if _, e := s.ResolveDirectoryWithLease(ctx, lease, "music/album/unborn", include); e == nil {
			t.Fatal("placeholder exposed by path")
		}
	}
	lease.Release()
	if _, err = s.Move(ctx, album.ObjectID, music.ObjectID, "renamed", 1); err != nil {
		t.Fatal(err)
	}
	if again, e := s.StageHiddenDirectoryRuleForImport(ctx, "music/renamed/unborn", "2026-01-01"); e != nil || again != id {
		t.Fatal("rule did not follow parent move", e)
	}
	// A failed promotion must leave the internal rule and encrypted row intact.
	if _, err = db.Exec(`CREATE TRIGGER reject_placeholder BEFORE UPDATE ON sealed_tree_facts BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if err = s.PromoteHiddenPlaceholderForImport(ctx, id, 1, Facts{ObjectID: id}); err == nil {
		t.Fatal("failed promotion committed")
	}
	if _, err = db.Exec(`DROP TRIGGER reject_placeholder`); err != nil {
		t.Fatal(err)
	}
	if err = s.PromoteHiddenPlaceholderForImport(ctx, id, 1, Facts{ObjectID: id}); err != nil {
		t.Fatal(err)
	}
	if err = s.PromoteHiddenPlaceholderForImport(ctx, id, 1, Facts{ObjectID: id}); err != nil {
		t.Fatal("promotion recovery", err)
	}
	if err = s.PromoteHiddenPlaceholderForImport(ctx, id, 1, Facts{ObjectID: id, Visibility: &VisibilityFact{Hidden: 0, UpdatedAt: "2026-01-01"}}); !errors.Is(err, ErrConflict) {
		t.Fatal("changed promotion retry accepted", err)
	}
	facts, rev, err := s.GetFacts(ctx, id)
	if err != nil || rev != 2 || facts.InternalPlaceholder || !facts.InternalPromotedPlaceholder || facts.Visibility == nil || facts.Visibility.Hidden != 1 || facts.Visibility.UpdatedAt != "2026-01-01" {
		t.Fatal("hide rule lost on promotion", err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if _, e := s.ResolveVisibleDirectoryWithLease(ctx, lease, "music/renamed/unborn"); !errors.Is(e, ErrHidden) {
		t.Fatal("promoted directory is public", e)
	}
	if got, e := s.ResolveDirectoryWithLease(ctx, lease, "music/renamed/unborn", true); e != nil || got != id {
		t.Fatal("include hidden cannot resolve promoted directory", e)
	}
}
