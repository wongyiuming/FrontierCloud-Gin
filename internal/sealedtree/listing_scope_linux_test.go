//go:build linux

package sealedtree

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestListingExplicitIncludeHiddenScope(t *testing.T) {
	ctx := context.Background()
	_, s, _, _, _ := fencedFixture(t)
	parent := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "parent"}
	if err := s.CreateDirectoryWithFacts(ctx, parent, Facts{ObjectID: parent.ObjectID}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		e := Entry{ParentID: parent.ObjectID, ObjectID: fmt.Sprintf("%064x", i+100), Kind: "directory", Name: fmt.Sprintf("item-%d", i)}
		f := Facts{ObjectID: e.ObjectID}
		if i >= 3 {
			f.Visibility = &VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}
		}
		if err := s.CreateDirectoryWithFacts(ctx, e, f); err != nil {
			t.Fatal(err)
		}
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, visibleCursor, err := s.ListVisibleWithLease(ctx, lease, parent.ObjectID, "", 1)
	if err != nil || visibleCursor == "" {
		t.Fatal("visible cursor", err)
	}
	_, allCursor, err := s.ListDirectoryWithLease(ctx, lease, parent.ObjectID, "", 1, true)
	if err != nil || allCursor == "" {
		t.Fatal("all cursor", err)
	}
	if _, _, err = s.ListDirectoryWithLease(ctx, lease, parent.ObjectID, visibleCursor, 1, true); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("visible cursor accepted in all scope", err)
	}
	if _, _, err = s.ListVisibleWithLease(ctx, lease, parent.ObjectID, allCursor, 1); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("all cursor accepted in visible scope", err)
	}
	seen := map[string]bool{}
	for cursor := ""; ; {
		items, next, e := s.ListDirectoryWithLease(ctx, lease, parent.ObjectID, cursor, 2, true)
		if e != nil {
			t.Fatal(e)
		}
		for _, item := range items {
			if seen[item.ObjectID] {
				t.Fatal("duplicate")
			}
			seen[item.ObjectID] = true
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != 6 {
		t.Fatal("all scope omitted entries", len(seen))
	}
	lease.Release()
	hidden := Entry{ParentID: parent.ObjectID, ObjectID: strings.Repeat("e", 64), Kind: "directory", Name: "new-hidden"}
	if err = s.CreateDirectoryWithFacts(ctx, hidden, Facts{ObjectID: hidden.ObjectID, Visibility: &VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}}); err != nil {
		t.Fatal(err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.ListDirectoryWithLease(ctx, lease, parent.ObjectID, allCursor, 1, true); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("all scope missed hidden mutation", err)
	}
	if _, _, err = s.ListVisibleWithLease(ctx, lease, parent.ObjectID, visibleCursor, 1); err != nil {
		t.Fatal("hidden mutation leaked into visible cursor", err)
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
	if _, err = s.ResolveVisibleDirectoryWithLease(ctx, lease, "parent"); !errors.Is(err, ErrHidden) {
		t.Fatal("default resolved hidden path", err)
	}
	if id, err := s.ResolveDirectoryWithLease(ctx, lease, "parent", true); err != nil || id != parent.ObjectID {
		t.Fatal("include scope did not resolve hidden path", err)
	}
	if items, _, err := s.ListDirectoryWithLease(ctx, lease, parent.ObjectID, "", 10, true); err != nil || len(items) != 7 {
		t.Fatal("include scope did not list hidden parent", err)
	}
}
