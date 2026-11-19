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

func TestListingCursorTracksDirectoryAndAncestors(t *testing.T) {
	ctx := context.Background()
	_, s, _, _, _ := fencedFixture(t)
	parent := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "parent"}
	other := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("c", 64), Kind: "directory", Name: "other"}
	for _, e := range []Entry{parent, other} {
		if err := s.CreateDirectoryWithFacts(ctx, e, Facts{ObjectID: e.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		e := Entry{ParentID: parent.ObjectID, ObjectID: fmt.Sprintf("%064x", 100+i), Kind: "directory", Name: fmt.Sprintf("child-%d", i)}
		if err := s.CreateDirectoryWithFacts(ctx, e, Facts{ObjectID: e.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, cursor, err := s.ListVisibleWithLease(ctx, lease, parent.ObjectID, "", 1)
	if err != nil || len(first) != 1 || cursor == "" {
		t.Fatal("first page", err)
	}
	done := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		e := Entry{ParentID: other.ObjectID, ObjectID: strings.Repeat("d", 64), Kind: "directory", Name: "unrelated"}
		close(started)
		done <- s.CreateDirectoryWithFacts(ctx, e, Facts{ObjectID: e.ObjectID})
	}()
	<-started
	select {
	case e := <-done:
		t.Fatal("writer passed held read fence", e)
	case <-time.After(100 * time.Millisecond):
	}
	lease.Release()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	// Hidden-only activity in this directory is not exposed as cursor failure.
	hidden := Entry{ParentID: parent.ObjectID, ObjectID: strings.Repeat("e", 64), Kind: "directory", Name: "hidden"}
	if err = s.CreateDirectoryWithFacts(ctx, hidden, Facts{ObjectID: hidden.ObjectID, Visibility: &VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}}); err != nil {
		t.Fatal(err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{first[0].ObjectID: true}
	for cursor != "" {
		items, next, e := s.ListVisibleWithLease(ctx, lease, parent.ObjectID, cursor, 1)
		if e != nil || len(items) != 1 || seen[items[0].ObjectID] {
			t.Fatal("unrelated change disrupted listing", e)
		}
		seen[items[0].ObjectID] = true
		cursor = next
	}
	if len(seen) != 3 {
		t.Fatal("listing missed an entry", len(seen))
	}
	_, cursor, err = s.ListVisibleWithLease(ctx, lease, parent.ObjectID, "", 1)
	if err != nil || cursor == "" {
		t.Fatal("new cursor", err)
	}
	lease.Release()
	added := Entry{ParentID: parent.ObjectID, ObjectID: strings.Repeat("f", 64), Kind: "directory", Name: "added"}
	if err = s.CreateDirectoryWithFacts(ctx, added, Facts{ObjectID: added.ObjectID}); err != nil {
		t.Fatal(err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.ListVisibleWithLease(ctx, lease, parent.ObjectID, cursor, 1); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("same-directory change accepted", err)
	}
	_, cursor, err = s.ListVisibleWithLease(ctx, lease, parent.ObjectID, "", 1)
	if err != nil || cursor == "" {
		t.Fatal("cursor before child facts", err)
	}
	lease.Release()
	if _, err = s.SetFacts(ctx, Facts{ObjectID: added.ObjectID}, 1); err != nil {
		t.Fatal(err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.ListVisibleWithLease(ctx, lease, parent.ObjectID, cursor, 1); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("visible child facts change accepted stale cursor", err)
	}
	_, cursor, err = s.ListVisibleWithLease(ctx, lease, parent.ObjectID, "", 1)
	if err != nil || cursor == "" {
		t.Fatal("cursor before hide", err)
	}
	lease.Release()
	if _, err = s.SetFacts(ctx, Facts{ObjectID: parent.ObjectID, Visibility: &VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}}, 1); err != nil {
		t.Fatal(err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.ListVisibleWithLease(ctx, lease, parent.ObjectID, cursor, 1); !errors.Is(err, ErrHidden) {
		t.Fatal("hidden ancestor accepted", err)
	}
	lease.Release()
	if _, err = s.SetFacts(ctx, Facts{ObjectID: parent.ObjectID}, 2); err != nil {
		t.Fatal(err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.ListVisibleWithLease(ctx, lease, parent.ObjectID, cursor, 1); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("ancestor hide/unhide accepted stale cursor", err)
	}
	_, cursor, err = s.ListVisibleWithLease(ctx, lease, parent.ObjectID, "", 1)
	if err != nil || cursor == "" {
		t.Fatal("cursor before move", err)
	}
	lease.Release()
	if _, err = s.Move(ctx, parent.ObjectID, other.ObjectID, "parent", 1); err != nil {
		t.Fatal(err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if _, _, err = s.ListVisibleWithLease(ctx, lease, parent.ObjectID, cursor, 1); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("ancestor move accepted stale cursor", err)
	}
}
