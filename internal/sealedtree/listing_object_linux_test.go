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

func TestListingObjectIncludeHiddenDoesNotGrantRead(t *testing.T) {
	ctx := context.Background()
	db, s, root, _, _ := fencedFixture(t)
	dir := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "private"}
	if err := s.CreateDirectoryWithFacts(ctx, dir, Facts{ObjectID: dir.ObjectID, Visibility: &VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}}); err != nil {
		t.Fatal(err)
	}
	entry := Entry{ParentID: dir.ObjectID, ObjectID: strings.Repeat("c", 64), Kind: "audio", Name: "song.mp3"}
	loc := fixturePlacement(t, entry.ObjectID)
	empty := sha256.Sum256(nil)
	loc.Bytes, loc.SHA256, loc.BlobID, loc.ReadAlias = 0, hex.EncodeToString(empty[:]), "", ""
	pending, err := s.PrepareFileWithFreshLocators(ctx, entry, loc, Facts{ObjectID: entry.ObjectID, Visibility: &VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.PublishPending(ctx, pending.OperationID, pub, bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadListingObjectWithLease(ctx, lease, entry.ObjectID, false); !errors.Is(err, ErrHidden) {
		t.Fatal("default scope read hidden object", err)
	}
	got, err := s.ReadListingObjectWithLease(ctx, lease, entry.ObjectID, true)
	if err != nil || got.Path != "private/song.mp3" || got.Entry.ObjectID != entry.ObjectID || got.Placement.BlobID != pending.BlobID {
		t.Fatal("include scope", err)
	}
	byAlias, err := s.ReadListingObjectByAliasWithLease(ctx, lease, pending.ReadAlias, true)
	if err != nil || byAlias.Path != got.Path || byAlias.Entry != got.Entry || byAlias.Placement.ReadAlias != pending.ReadAlias {
		t.Fatal("exact alias lost the hidden object binding", err)
	}
	if _, err = s.ReadListingObjectByAliasWithLease(ctx, lease, pending.BlobID, true); err == nil {
		t.Fatal("physical blob ID was accepted as an alias")
	}
	if _, err = s.ReadVisibleObjectWithLease(ctx, lease, entry.ObjectID); !errors.Is(err, ErrHidden) {
		t.Fatal("catalog scope granted media read", err)
	}
	lease.Release()
	if _, err = s.ReadListingObjectWithLease(ctx, lease, entry.ObjectID, true); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("released lease", err)
	}
	index, err := s.tree.ObjectIndex(entry.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO sealed_tree_revocations(operation_index,object_index) VALUES(?,?)`, strings.Repeat("e", 64), index); err != nil {
		t.Fatal(err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if _, err = s.ReadListingObjectWithLease(ctx, lease, entry.ObjectID, true); err == nil {
		t.Fatal("unexpected pending revocation accepted")
	}
	if _, err = s.ReadListingObjectByAliasWithLease(ctx, lease, pending.ReadAlias, true); err == nil {
		t.Fatal("alias bypassed pending revocation")
	}
}
