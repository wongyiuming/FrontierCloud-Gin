//go:build linux

package sealedtree

import (
	"context"
	"errors"
	"testing"
)

func TestVisitRecoveryMediaRequiresSameSharedLease(t *testing.T) {
	ctx := context.Background()
	_, store, _, _, _ := fencedFixture(t)
	_, other, _, _, _ := fencedFixture(t)
	lease, err := store.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	visit := func(RecoveryMediaPlacement) error {
		t.Fatal("empty tree reached the visitor")
		return nil
	}
	if _, err = other.VisitRecoveryMedia(ctx, lease, visit); !errors.Is(err, ErrFenceRequired) {
		t.Fatalf("foreign lease accepted: %v", err)
	}
	got, err := store.VisitRecoveryMedia(ctx, lease, visit)
	if err != nil || got.TreeGeneration != lease.generation || got.Objects != 0 {
		t.Fatalf("empty inventory did not prove its fenced generation: %+v %v", got, err)
	}
	lease.Release()
	if _, err = store.VisitRecoveryMedia(ctx, lease, visit); !errors.Is(err, ErrFenceChanged) {
		t.Fatalf("released lease accepted: %v", err)
	}
}

func TestVisitRecoveryMediaPreservesSignedHiddenBlob(t *testing.T) {
	ctx := context.Background()
	store, entry, placement, intent := hideIntentFixture(t)
	ackHideFixture(t, store, entry, intent)
	if err := store.FinishOpaqueHide(ctx, entry.ObjectID, intent.OperationID, "2026-11-06"); err != nil {
		t.Fatal(err)
	}
	lease, err := store.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	got, err := store.VisitRecoveryMedia(ctx, lease, func(item RecoveryMediaPlacement) error {
		if item.ObjectID != entry.ObjectID || item.BlobID != placement.BlobID ||
			item.ReadAlias != placement.ReadAlias || !item.AliasRevoked || item.AliasRevision != intent.Revision || item.AliasRevocationOperationID != intent.OperationID {
			t.Fatal("signed hidden alias must retain the expected physical blob")
		}
		return nil
	})
	if err != nil || got.Objects != 1 {
		t.Fatalf("signed hidden blob inventory failed: %+v %v", got, err)
	}
}
