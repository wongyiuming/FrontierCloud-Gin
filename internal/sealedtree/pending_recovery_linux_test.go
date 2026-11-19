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

func TestPendingRecoveryReopensPagesAndPublishesExactMapping(t *testing.T) {
	ctx := context.Background()
	db, source, root, _, dir := fencedFixture(t)
	content := []byte("synthetic recoverable bytes")
	sum := sha256.Sum256(content)
	for _, c := range []string{"b", "c"} {
		entry := Entry{ParentID: source.rootID, ObjectID: strings.Repeat(c, 64), Kind: "audio", Name: "track-" + c}
		placement := fixturePlacement(t, entry.ObjectID)
		placement.Bytes, placement.SHA256 = int64(len(content)), hex.EncodeToString(sum[:])
		placement.BlobID, placement.ReadAlias = "", ""
		if _, err := source.PrepareFileWithFreshLocators(ctx, entry, placement, Facts{ObjectID: entry.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	// Reopen from persisted tree metadata as after a process restart.
	reopened, err := OpenSQLite(ctx, db, source.tree, source.rootID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenFence(ctx, reopened, root, dir); err != nil {
		t.Fatal(err)
	}
	lease, err := reopened.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, more, err := reopened.RecoverPendingWithLease(ctx, lease, "", 1)
	if err != nil || !more || len(first) != 1 || first[0].Entry.ObjectID != first[0].Facts.ObjectID || first[0].Placement.ObjectID != first[0].Entry.ObjectID {
		t.Fatal("first durable page invalid", err)
	}
	byObject, found, err := reopened.FindPendingObjectWithLease(ctx, lease, first[0].Entry.ObjectID)
	if err != nil || !found || byObject.OperationID != first[0].OperationID || byObject.Placement.BlobID != first[0].Placement.BlobID || byObject.Placement.ReadAlias != first[0].Placement.ReadAlias {
		t.Fatal("lost operation response could not be recovered", err)
	}
	if value, found, err := reopened.FindPendingObjectWithLease(ctx, lease, strings.Repeat("d", 64)); err != nil || found || value.OperationID != "" {
		t.Fatal("missing pending object was misidentified", err)
	}
	second, more, err := reopened.RecoverPendingWithLease(ctx, lease, first[0].OperationID, 1)
	if err != nil || more || len(second) != 1 || second[0].OperationID <= first[0].OperationID {
		t.Fatal("second durable page invalid", err)
	}
	lease.Release()
	pub, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = reopened.PublishPending(ctx, first[0].OperationID, pub, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	lease, err = reopened.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.ReadVisibleObjectWithLease(ctx, lease, first[0].Entry.ObjectID)
	if err != nil || got.Placement.BlobID != first[0].Placement.BlobID || got.Placement.ReadAlias != first[0].Placement.ReadAlias || got.Placement.SHA256 != first[0].Placement.SHA256 {
		t.Fatal("published physical mapping changed", err)
	}
	lease.Release()
	// Database damage must never return a partial recovery page.
	if _, err = db.Exec(`UPDATE sealed_tree_pending_files SET operation_mac=? WHERE operation_id=?`, strings.Repeat("0", 64), second[0].OperationID); err != nil {
		t.Fatal(err)
	}
	lease, err = reopened.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if items, _, err := reopened.RecoverPendingWithLease(ctx, lease, "", 64); !errors.Is(err, ErrInvalid) || items != nil {
		t.Fatal("tampered pending intent was returned", err)
	}
	if item, found, err := reopened.FindPendingObjectWithLease(ctx, lease, second[0].Entry.ObjectID); !errors.Is(err, ErrInvalid) || found || item.OperationID != "" {
		t.Fatal("tampered object lookup was returned", err)
	}
}

func TestFreshPendingLocatorsAreMasterGeneratedAndRecoverable(t *testing.T) {
	ctx := context.Background()
	_, s, _, _, _ := fencedFixture(t)
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "audio", Name: "synthetic"}
	pl := fixturePlacement(t, entry.ObjectID)
	if _, err := s.PrepareFileWithFacts(ctx, entry, pl, Facts{ObjectID: entry.ObjectID}); !errors.Is(err, ErrExternalLocators) {
		t.Fatal("caller-chosen legacy locator path was accepted", err)
	}
	if _, err := s.PrepareFileWithFreshLocators(ctx, entry, pl, Facts{ObjectID: entry.ObjectID}); !errors.Is(err, ErrInvalid) {
		t.Fatal("caller-chosen locators were accepted", err)
	}
	pl.BlobID, pl.ReadAlias = "", ""
	prepared, err := s.PrepareFileWithFreshLocators(ctx, entry, pl, Facts{ObjectID: entry.ObjectID})
	if err != nil || !hexID(prepared.OperationID) || !hexID(prepared.BlobID) || !hexID(prepared.ReadAlias) || prepared.BlobID == prepared.ReadAlias || prepared.BlobID == entry.ObjectID || prepared.ReadAlias == entry.ObjectID {
		t.Fatal("fresh locators were not independent", err)
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	got, found, err := s.FindPendingObjectWithLease(ctx, lease, entry.ObjectID)
	if err != nil || !found || got.OperationID != prepared.OperationID || got.Placement.BlobID != prepared.BlobID || got.Placement.ReadAlias != prepared.ReadAlias {
		t.Fatal("fresh locators were not durably recoverable", err)
	}
}
