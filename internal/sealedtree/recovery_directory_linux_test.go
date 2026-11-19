//go:build linux

package sealedtree

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRecoveryDirectoryLeaseAllowsHiddenWithoutGrantingVisibility(t *testing.T) {
	ctx := context.Background()
	_, s, _, _, _ := fencedFixture(t)
	hidden := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("c", 64), Kind: "directory", Name: "music"}
	if err := s.CreateDirectoryWithFacts(ctx, hidden, Facts{ObjectID: hidden.ObjectID, Visibility: &VisibilityFact{Hidden: 1, UpdatedAt: "fixture"}}); err != nil {
		t.Fatal(err)
	}
	child := Entry{ParentID: hidden.ObjectID, ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "album"}
	if err := s.CreateDirectoryWithFacts(ctx, child, Facts{ObjectID: child.ObjectID}); err != nil {
		t.Fatal(err)
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if value, err := s.ResolveDirectoryForRecoveryWithLease(ctx, lease, child.ObjectID); err != nil || value != "music/album" {
		t.Fatal("hidden recovery path", err)
	}
	if _, err := s.ResolveVisibleWithLease(ctx, lease, child.ObjectID); !errors.Is(err, ErrHidden) {
		t.Fatal("recovery path granted visibility", err)
	}
	_, other, _, _, _ := fencedFixture(t)
	if _, err := other.ResolveDirectoryForRecoveryWithLease(ctx, lease, child.ObjectID); !errors.Is(err, ErrFenceRequired) {
		t.Fatal("foreign lease accepted", err)
	}
	if _, err := s.ResolveDirectoryForRecoveryWithLease(ctx, lease, s.rootID); !errors.Is(err, ErrInvalid) {
		t.Fatal("virtual root accepted", err)
	}
	lease.Release()
	if _, err := s.ResolveDirectoryForRecoveryWithLease(ctx, lease, child.ObjectID); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("released lease accepted", err)
	}
}
