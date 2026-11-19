package sealedtree

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestRecoveryMediaChecksExpectedPlacements(t *testing.T) {
	ctx := context.Background()
	db, store, _ := sqliteFixture(t)
	native := Entry{ParentID: store.rootID, ObjectID: strings.Repeat("1", 64), Kind: "audio", Name: "hidden-native.mp3"}
	placement := fixturePlacement(t, native.ObjectID)
	placement.State = "active"
	if err := store.CreateFile(ctx, native, placement); err != nil {
		t.Fatal(err)
	}
	hidden := &VisibilityFact{Hidden: 1, UpdatedAt: "2026-11-06"}
	if _, err := store.SetFacts(ctx, Facts{ObjectID: native.ObjectID, Visibility: hidden}, 0); err != nil {
		t.Fatal(err)
	}
	s3 := fixtureS3Placement()
	s3.ObjectID = strings.Repeat("2", 64)
	s3.Proof.MediaID = s3.ObjectID
	remote := Entry{ParentID: store.rootID, ObjectID: s3.ObjectID, Kind: "video", Name: "hidden-s3.mp4"}
	if err := store.createImportedS3Fixture(ctx, remote, Facts{ObjectID: remote.ObjectID, Visibility: hidden}, s3); err != nil {
		t.Fatal(err)
	}

	found := make(map[string]RecoveryMediaPlacement)
	if _, err := store.check(ctx, func(item RecoveryMediaPlacement) error {
		found[item.ObjectID] = item
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 {
		t.Fatalf("want two hidden file placements, got %d", len(found))
	}
	got := found[native.ObjectID]
	if got.OwnerID != placement.OwnerID || got.BlobID != placement.BlobID || got.Bytes != placement.Bytes ||
		got.NativeSHA256 != placement.SHA256 || got.ReadAlias != placement.ReadAlias ||
		got.AliasRevision == "" || got.Descriptor == "" || got.AliasRevoked || got.S3CompositeSHA256 != "" {
		t.Fatal("native placement lost its authenticated physical expectations")
	}
	got = found[remote.ObjectID]
	if got.OwnerID != s3.MemberID || got.BlobID != s3.Proof.ObjectID || got.Bytes != s3.Proof.Bytes ||
		got.S3CompositeSHA256 != s3.Proof.CompositeSHA256 || got.S3ETag != s3.Proof.ETag ||
		got.S3VersionID != s3.Proof.VersionID || got.S3ObjectRevision != s3.ObjectRevision ||
		got.NativeSHA256 != "" || got.ReadAlias != "" {
		t.Fatal("S3 placement lost its separate authenticated provider expectations")
	}
	raw, err := json.Marshal(found)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{native.Name, remote.Name, s3.Proof.Key, s3.Location.Endpoint, s3.Location.Bucket} {
		if strings.Contains(string(raw), private) {
			t.Fatal("inventory exposed a logical or physical storage location")
		}
	}

	stop := errors.New("stop recovery inventory")
	if _, err = store.check(ctx, func(RecoveryMediaPlacement) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("visitor error was lost: %v", err)
	}
	index, err := store.tree.ObjectIndex(native.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE sealed_tree_placements SET sealed=zeroblob(length(sealed)) WHERE object_index=?`, index); err != nil {
		t.Fatal(err)
	}
	if _, err = store.check(ctx, func(item RecoveryMediaPlacement) error {
		if item.ObjectID == native.ObjectID {
			t.Fatal("corrupted placement reached the visitor")
		}
		return nil
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("corrupted placement accepted: %v", err)
	}
}

func TestRecoveryMediaRejectsUnsettledUpload(t *testing.T) {
	ctx := context.Background()
	_, store, _ := sqliteFixture(t)
	entry := Entry{ParentID: store.rootID, ObjectID: strings.Repeat("3", 64), Kind: "audio", Name: "pending.mp3"}
	if _, err := store.PrepareFile(ctx, entry, fixturePlacement(t, entry.ObjectID)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Check(ctx); err != nil {
		t.Fatalf("ordinary Check should authenticate a pending upload: %v", err)
	}
	if _, err := store.check(ctx, func(RecoveryMediaPlacement) error {
		t.Fatal("unsettled tree reached the recovery visitor")
		return nil
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("unsettled inventory accepted: %v", err)
	}
}
