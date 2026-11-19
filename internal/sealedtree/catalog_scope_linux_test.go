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

func TestCatalogScopeProofAcrossShortLeases(t *testing.T) {
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
		e := Entry{ParentID: parent.ObjectID, ObjectID: fmt.Sprintf("%064x", i+100), Kind: "directory", Name: fmt.Sprintf("item-%d", i)}
		if err := s.CreateDirectoryWithFacts(ctx, e, Facts{ObjectID: e.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := s.CaptureCatalogScopeWithLease(ctx, lease, parent.ObjectID, false)
	if err != nil {
		t.Fatal(err)
	}
	first, next, err := s.ListCatalogPageWithLease(ctx, lease, parent.ObjectID, "", 1, false)
	if err != nil || next == "" || len(first) != 1 {
		t.Fatal("first page", err)
	}
	lease.Release()
	unrelated := Entry{ParentID: other.ObjectID, ObjectID: strings.Repeat("d", 64), Kind: "directory", Name: "unrelated"}
	if err = s.CreateDirectoryWithFacts(ctx, unrelated, Facts{ObjectID: unrelated.ObjectID}); err != nil {
		t.Fatal(err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CheckCatalogScopeWithLease(ctx, lease, parent.ObjectID, false, proof); err != nil {
		t.Fatal("unrelated write", err)
	}
	if err = s.CheckCatalogScopeWithLease(ctx, lease, parent.ObjectID, true, proof); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("scope confusion", err)
	}
	forged := proof
	forged.sealed = "invalid"
	if err = s.CheckCatalogScopeWithLease(ctx, lease, parent.ObjectID, false, forged); err == nil {
		t.Fatal("forged proof accepted")
	}
	lease.Release()
	if _, err = s.SetFacts(ctx, Facts{ObjectID: first[0].Entry.ObjectID}, 1); err != nil {
		t.Fatal(err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CheckCatalogScopeWithLease(ctx, lease, parent.ObjectID, false, proof); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("first-page facts change accepted", err)
	}
	proof, err = s.CaptureCatalogScopeWithLease(ctx, lease, parent.ObjectID, false)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		e := Entry{ParentID: parent.ObjectID, ObjectID: strings.Repeat("e", 64), Kind: "directory", Name: "new"}
		done <- s.CreateDirectoryWithFacts(ctx, e, Facts{ObjectID: e.ObjectID})
	}()
	<-started
	select {
	case e := <-done:
		t.Fatal("writer passed final lease", e)
	case <-time.After(100 * time.Millisecond):
	}
	lease.Release()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CheckCatalogScopeWithLease(ctx, lease, parent.ObjectID, false, proof); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("changed scope accepted", err)
	}
	proof, err = s.CaptureCatalogScopeWithLease(ctx, lease, parent.ObjectID, false)
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	if _, err = s.SetFacts(ctx, Facts{ObjectID: parent.ObjectID, Visibility: &VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err = s.SetFacts(ctx, Facts{ObjectID: parent.ObjectID}, 2); err != nil {
		t.Fatal(err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if err = s.CheckCatalogScopeWithLease(ctx, lease, parent.ObjectID, false, proof); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("ancestor hide/unhide accepted", err)
	}
}

func TestCatalogScopeBatchValidatesAllDirectoriesTogether(t *testing.T) {
	ctx := context.Background()
	_, s, _, _, _ := fencedFixture(t)
	parent := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "parent"}
	child := Entry{ParentID: parent.ObjectID, ObjectID: strings.Repeat("c", 64), Kind: "directory", Name: "child"}
	for _, entry := range []Entry{parent, child} {
		if err := s.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: entry.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.CaptureCatalogScopeWithLease(ctx, lease, parent.ObjectID, false)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.CaptureCatalogScopeWithLease(ctx, lease, child.ObjectID, false)
	if err != nil {
		t.Fatal(err)
	}
	checks := []CatalogScopeCheck{{ParentID: parent.ObjectID, Proof: p}, {ParentID: child.ObjectID, Proof: c}, {ParentID: child.ObjectID, Proof: c}}
	if err = s.CheckCatalogScopesWithLease(ctx, lease, checks); err != nil {
		t.Fatal("valid batch rejected", err)
	}
	forged := append([]CatalogScopeCheck(nil), checks...)
	forged[1].Proof.sealed = "invalid"
	if err = s.CheckCatalogScopesWithLease(ctx, lease, forged); err == nil {
		t.Fatal("forged proof accepted")
	}
	cross := append([]CatalogScopeCheck(nil), checks...)
	cross[1].IncludeHidden = true
	if err = s.CheckCatalogScopesWithLease(ctx, lease, cross); err == nil {
		t.Fatal("wrong range accepted")
	}
	lease.Release()
	added := Entry{ParentID: child.ObjectID, ObjectID: strings.Repeat("d", 64), Kind: "directory", Name: "added"}
	if err = s.CreateDirectoryWithFacts(ctx, added, Facts{ObjectID: added.ObjectID}); err != nil {
		t.Fatal(err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if err = s.CheckCatalogScopesWithLease(ctx, lease, checks); err == nil {
		t.Fatal("changed child scope accepted")
	}
}
