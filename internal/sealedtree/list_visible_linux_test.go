//go:build linux

package sealedtree

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestListVisibleWithLeaseFiltersAndPaginates(t *testing.T) {
	ctx := context.Background()
	_, s, _, _, _ := fencedFixture(t)
	parent := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "album"}
	if err := s.CreateDirectoryWithFacts(ctx, parent, Facts{ObjectID: parent.ObjectID}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 7; i++ {
		id := fmt.Sprintf("%064x", i+20)
		entry := Entry{ParentID: parent.ObjectID, ObjectID: id, Kind: "directory", Name: fmt.Sprintf("item-%d", i)}
		facts := Facts{ObjectID: id}
		if i >= 2 {
			facts.Visibility = &VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}
		}
		if err := s.CreateDirectoryWithFacts(ctx, entry, facts); err != nil {
			t.Fatal(err)
		}
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		entries, next, e := s.ListVisibleWithLease(ctx, lease, parent.ObjectID, cursor, 1)
		if e != nil {
			t.Fatal(e)
		}
		if len(entries) != 1 {
			t.Fatal("hidden-only page exposed or visible successor omitted")
		}
		for _, entry := range entries {
			if entry.Name != "item-0" && entry.Name != "item-1" {
				t.Fatal("hidden child exposed")
			}
			seen[entry.Name] = true
		}
		pages++
		if pages > 10 {
			t.Fatal("cursor did not advance")
		}
		if next == "" {
			break
		}
		if next == cursor {
			t.Fatal("cursor repeated")
		}
		cursor = next
	}
	if len(seen) != 2 || pages != 2 {
		t.Fatal("visible items or raw pagination incorrect", len(seen), pages)
	}
	hiddenCursor, err := s.tree.Lookup(parent.ObjectID, "item-2")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.ListVisibleWithLease(ctx, lease, parent.ObjectID, hiddenCursor, 1); !errors.Is(err, ErrInvalid) {
		t.Fatal("hidden cursor accepted", err)
	}
	rootEntries, _, err := s.ListVisibleWithLease(ctx, lease, s.rootID, "", 20)
	if err != nil || len(rootEntries) != 1 || rootEntries[0] != parent {
		t.Fatal("root listing", err)
	}
	_, other, _, _, _ := fencedFixture(t)
	if _, _, err = other.ListVisibleWithLease(ctx, lease, other.rootID, "", 2); !errors.Is(err, ErrFenceRequired) {
		t.Fatal("foreign lease accepted", err)
	}
	lease.Release()
	if _, _, err = s.ListVisibleWithLease(ctx, lease, parent.ObjectID, "", 2); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("released lease accepted", err)
	}
	for i := 0; i < 2; i++ {
		id := fmt.Sprintf("%064x", i+20)
		if _, err = s.SetFacts(ctx, Facts{ObjectID: id, Visibility: &VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}}, 1); err != nil {
			t.Fatal(err)
		}
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if entries, next, e := s.ListVisibleWithLease(ctx, lease, parent.ObjectID, "", 2); e != nil || len(entries) != 0 || next != "" {
		t.Fatal("hidden-only directory leaked a cursor", e)
	}
	lease.Release()
	if _, err = s.SetFacts(ctx, Facts{ObjectID: parent.ObjectID, Visibility: &VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}}, 1); err != nil {
		t.Fatal(err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if entries, _, err := s.ListVisibleWithLease(ctx, lease, parent.ObjectID, "", 2); !errors.Is(err, ErrHidden) || len(entries) != 0 {
		t.Fatal("hidden parent exposed", err)
	}
}

func TestListVisibleWithLeaseRejectsTamperedFacts(t *testing.T) {
	ctx := context.Background()
	db, s, _, _, _ := fencedFixture(t)
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "private"}
	if err := s.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: entry.ObjectID}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE sealed_tree_facts SET sealed=zeroblob(length(sealed))`); err != nil {
		t.Fatal(err)
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if entries, _, err := s.ListVisibleWithLease(ctx, lease, s.rootID, "", 5); err == nil || len(entries) != 0 {
		t.Fatal("corrupt facts exposed", err)
	}
}

func TestListVisibleWithLeaseLargeDirectoryAndStaleCursor(t *testing.T) {
	ctx := context.Background()
	_, s, _, _, _ := fencedFixture(t)
	parent := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "large"}
	if err := s.CreateDirectoryWithFacts(ctx, parent, Facts{ObjectID: parent.ObjectID}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 513; i++ {
		id := fmt.Sprintf("%064x", i+1000)
		entry := Entry{ParentID: parent.ObjectID, ObjectID: id, Kind: "directory", Name: fmt.Sprintf("private-%d", i)}
		if err := s.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: id, Visibility: &VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}}); err != nil {
			t.Fatal(err)
		}
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	entries, next, err := s.ListVisibleWithLease(ctx, lease, parent.ObjectID, "", 1)
	if err != nil || len(entries) != 0 || next != "" {
		t.Fatal("hidden-only large directory leaked a cursor", err)
	}
	lease.Release()
	for i := 0; i < 513; i++ {
		id := fmt.Sprintf("%064x", i+3000)
		entry := Entry{ParentID: parent.ObjectID, ObjectID: id, Kind: "directory", Name: fmt.Sprintf("public-%d", i)}
		if err = s.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: id}); err != nil {
			t.Fatal(err)
		}
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cursor := ""
	firstCursor := ""
	total := 0
	pages := 0
	started := time.Now()
	for {
		items, next, e := s.ListVisibleWithLease(ctx, lease, parent.ObjectID, cursor, 64)
		if e != nil {
			t.Fatal(e)
		}
		for _, item := range items {
			if !strings.HasPrefix(item.Name, "public-") {
				t.Fatal("hidden name exposed")
			}
		}
		total += len(items)
		pages++
		if firstCursor == "" {
			firstCursor = next
		}
		if next == "" {
			break
		}
		if next == cursor {
			t.Fatal("cursor repeated")
		}
		cursor = next
	}
	t.Logf("visible listing: %d entries in %d pages, elapsed %s (setup excluded)", total, pages, time.Since(started))
	if total != 513 || firstCursor == "" {
		t.Fatal("large directory truncated", total)
	}
	lease.Release()
	added := Entry{ParentID: parent.ObjectID, ObjectID: fmt.Sprintf("%064x", 9000), Kind: "directory", Name: "new"}
	if err = s.CreateDirectoryWithFacts(ctx, added, Facts{ObjectID: added.ObjectID}); err != nil {
		t.Fatal(err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if _, _, err = s.ListVisibleWithLease(ctx, lease, parent.ObjectID, firstCursor, 64); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("stale cursor accepted", err)
	}
}
