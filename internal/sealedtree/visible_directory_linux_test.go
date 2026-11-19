//go:build linux

package sealedtree

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestResolveVisibleDirectoryWithLease(t *testing.T) {
	ctx := context.Background()
	_, s, _, _, _ := fencedFixture(t)
	a := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "音乐"}
	b := Entry{ParentID: a.ObjectID, ObjectID: strings.Repeat("c", 64), Kind: "directory", Name: "album"}
	for _, entry := range []Entry{a, b} {
		if err := s.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: entry.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := s.ResolveVisibleDirectoryWithLease(ctx, lease, ""); err != nil || id != s.rootID {
		t.Fatal("root", err)
	}
	if id, err := s.ResolveVisibleDirectoryWithLease(ctx, lease, "音乐/album"); err != nil || id != b.ObjectID {
		t.Fatal("nested", err)
	}
	for _, path := range []string{"/音乐", "音乐/../album", "音乐//album", "音乐/"} {
		if _, err = s.ResolveVisibleDirectoryWithLease(ctx, lease, path); err == nil {
			t.Fatal("noncanonical path accepted", path)
		}
	}
	_, other, _, _, _ := fencedFixture(t)
	if _, err = other.ResolveVisibleDirectoryWithLease(ctx, lease, ""); !errors.Is(err, ErrFenceRequired) {
		t.Fatal("foreign lease", err)
	}
	lease.Release()
	if _, err = s.ResolveVisibleDirectoryWithLease(ctx, lease, "音乐"); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("released lease", err)
	}
	if _, err = s.SetFacts(ctx, Facts{ObjectID: a.ObjectID, Visibility: &VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}}, 1); err != nil {
		t.Fatal(err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if id, err := s.ResolveVisibleDirectoryWithLease(ctx, lease, "音乐/album"); !errors.Is(err, ErrHidden) || id != "" {
		t.Fatal("hidden ancestor", err)
	}
}

func TestVisibleDirectoryFourBytePathBoundary(t *testing.T) {
	ctx := context.Background()
	_, s, _, _, _ := fencedFixture(t)
	parent := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "music"}
	child := Entry{ParentID: parent.ObjectID, ObjectID: strings.Repeat("c", 64), Kind: "directory", Name: strings.Repeat("😀", 1018)}
	for _, entry := range []Entry{parent, child} {
		if err := s.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: entry.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	over := Entry{ParentID: child.ObjectID, ObjectID: strings.Repeat("d", 64), Kind: "directory", Name: "x"}
	if err := s.CreateDirectoryWithFacts(ctx, over, Facts{ObjectID: over.ObjectID}); !errors.Is(err, ErrInvalid) {
		t.Fatal("overlong full path created", err)
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	path := parent.Name + "/" + child.Name
	if len(path) <= 1024 {
		t.Fatal("fixture does not exceed old byte cap")
	}
	if got, err := s.ResolveVisibleDirectoryWithLease(ctx, lease, path); err != nil || got != child.ObjectID {
		t.Fatal("legal 1024-rune path", err)
	}
	if _, err := s.ResolveVisibleDirectoryWithLease(ctx, lease, path+"😀"); !errors.Is(err, ErrInvalid) {
		t.Fatal("1025-rune path accepted", err)
	}
}
