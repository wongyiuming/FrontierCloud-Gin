//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestFencedZeroByteObjectPublishesAndResolves(t *testing.T) {
	ctx := context.Background()
	_, s, root, _, _ := fencedFixture(t)
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "audio", Name: "empty.mp3"}
	loc := fixturePlacement(t, entry.ObjectID)
	empty := sha256.Sum256(nil)
	loc.Bytes = 0
	loc.SHA256 = hex.EncodeToString(empty[:])
	loc.BlobID = ""
	loc.ReadAlias = ""
	prepared, err := s.PrepareFileWithFreshLocators(ctx, entry, loc, Facts{ObjectID: entry.ObjectID})
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.PublishPending(ctx, prepared.OperationID, publisher, bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	visible, err := s.ReadVisibleObjectWithLease(ctx, lease, entry.ObjectID)
	if err != nil || visible.Placement.Bytes != 0 || visible.Placement.SHA256 != hex.EncodeToString(empty[:]) || visible.Placement.BlobID != prepared.BlobID {
		t.Fatal("empty placement", err)
	}
	path, err := BlobPath(prepared.BlobID)
	if err != nil {
		t.Fatal(err)
	}
	info, err := root.Stat(path)
	if err != nil || info.Size() != 0 {
		t.Fatal("empty blob", err)
	}
}
