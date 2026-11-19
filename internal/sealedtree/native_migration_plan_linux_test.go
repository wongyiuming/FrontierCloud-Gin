//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

const nativeMigrationTestSource = "11111111111111111111111111111111"
const nativeMigrationTestOther = "22222222222222222222222222222222"

func nativeMigrationTestDirectory(t *testing.T, tree *SQLStore, parentID, name string) string {
	t.Helper()
	id, err := NewBlobID()
	if err != nil {
		t.Fatal(err)
	}
	entry := Entry{ParentID: parentID, ObjectID: id, Kind: "directory", Name: name}
	if err = tree.CreateDirectoryWithFacts(context.Background(), entry, Facts{ObjectID: id}); err != nil {
		t.Fatal(err)
	}
	return id
}

func nativeMigrationTestFile(t *testing.T, tree *SQLStore, publisher *BlobPublisher, parentID, ownerID, name string, hidden bool) NativeMigrationObject {
	t.Helper()
	ctx := context.Background()
	id, err := NewBlobID()
	if err != nil {
		t.Fatal(err)
	}
	entry := Entry{ParentID: parentID, ObjectID: id, Kind: "audio", Name: name}
	metadata, err := mediacrypto.NewMetadata(1)
	if err != nil {
		t.Fatal(err)
	}
	content := bytes.Repeat([]byte{7}, int(metadata.CiphertextSize))
	digest := sha256.Sum256(content)
	placement := fixturePlacement(t, id)
	placement.NativeObjectID, err = NewBlobID()
	if err != nil {
		t.Fatal(err)
	}
	placement.OwnerID, placement.Bytes, placement.SHA256 = ownerID, metadata.CiphertextSize, hex.EncodeToString(digest[:])
	placement.BlobID, placement.ReadAlias, placement.State, placement.Encryption = "", "", "active", &metadata
	facts := Facts{ObjectID: id}
	if hidden {
		facts.Visibility = &VisibilityFact{Hidden: 1, UpdatedAt: "fixture"}
	}
	pending, err := tree.PrepareFileWithFreshLocators(ctx, entry, placement, facts)
	if err != nil {
		t.Fatal(err)
	}
	if publisher != nil {
		if err = tree.PublishPending(ctx, pending.OperationID, publisher, bytes.NewReader(content)); err != nil {
			t.Fatal(err)
		}
	}
	descriptor, err := protocol.IngressMediaDescriptor(placement.Bytes, &metadata)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := protocol.OpaquePlacementRevision(pending.ReadAlias, pending.BlobID, placement.SHA256, placement.Bytes, &metadata)
	if err != nil {
		t.Fatal(err)
	}
	return NativeMigrationObject{
		ObjectID: id, NativeObjectID: placement.NativeObjectID, Kind: entry.Kind, BlobID: pending.BlobID, ReadAlias: pending.ReadAlias,
		SHA256: placement.SHA256, Descriptor: descriptor, SourceRevision: revision, Bytes: placement.Bytes,
	}
}

func readNativeMigrationTestPlan(t *testing.T, tree *SQLStore, parentID, ownerID string) (NativeMigrationUnit, []NativeMigrationObject, error) {
	t.Helper()
	ctx := context.Background()
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	var observed []NativeMigrationObject
	unit, err := tree.VisitNativeMigrationUnitWithLease(ctx, lease, parentID, ownerID, func(_ context.Context, object NativeMigrationObject) error {
		observed = append(observed, object)
		return nil
	})
	return unit, observed, err
}

func TestNativeMigrationUnitKeepsCompleteImmediateParentAndStableIdentity(t *testing.T) {
	_, tree, root, _, _ := fencedFixture(t)
	publisher, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	music := nativeMigrationTestDirectory(t, tree, tree.rootID, "music")
	album := nativeMigrationTestDirectory(t, tree, music, "private-album")
	visible := nativeMigrationTestFile(t, tree, publisher, album, nativeMigrationTestSource, "one.mp3", false)
	hidden := nativeMigrationTestFile(t, tree, publisher, album, nativeMigrationTestSource, "hidden.mp3", true)
	expected := map[string]NativeMigrationObject{visible.ObjectID: visible, hidden.ObjectID: hidden}
	for n := range 513 {
		object := nativeMigrationTestFile(t, tree, publisher, album, nativeMigrationTestSource, fmt.Sprintf("track-%d.mp3", n), false)
		expected[object.ObjectID] = object
	}
	nativeMigrationTestDirectory(t, tree, album, "empty-child")
	sibling := nativeMigrationTestDirectory(t, tree, music, "other-album")
	nativeMigrationTestFile(t, tree, publisher, sibling, nativeMigrationTestOther, "unrelated.mp3", false)

	before, observed, err := readNativeMigrationTestPlan(t, tree, album, nativeMigrationTestSource)
	if err != nil || before.ObjectCount != 515 || len(observed) != 515 || !hexID(before.Digest) || before.TreeGeneration <= 0 || before.SourceOwnerID != nativeMigrationTestSource || before.ParentID != album {
		t.Fatal("incomplete unit", err)
	}
	for _, object := range observed {
		if expected[object.ObjectID] != object {
			t.Fatal("the plan omitted or changed an authenticated source identity")
		}
		delete(expected, object.ObjectID)
	}
	again, _, err := readNativeMigrationTestPlan(t, tree, album, nativeMigrationTestSource)
	if err != nil || before != again {
		t.Fatal("read-only plan changed generation or was nondeterministic", err)
	}
	ctx := context.Background()
	facts, revision, err := tree.GetFacts(ctx, hidden.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	facts.Visibility = &VisibilityFact{Hidden: 0, UpdatedAt: "later"}
	if _, err = tree.SetFacts(ctx, facts, revision); err != nil {
		t.Fatal(err)
	}
	again, _, err = readNativeMigrationTestPlan(t, tree, album, nativeMigrationTestSource)
	if err != nil || again.Digest != before.Digest || again.TreeGeneration <= before.TreeGeneration {
		t.Fatal("display-only changes altered the placement proof", err)
	}
	nativeMigrationTestFile(t, tree, publisher, album, nativeMigrationTestSource, "three.mp3", false)
	after, _, err := readNativeMigrationTestPlan(t, tree, album, nativeMigrationTestSource)
	if err != nil || after.ObjectCount != 516 || after.Digest == before.Digest {
		t.Fatal("a changed sibling roster reused the old proof", err)
	}
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	stagingErr := errors.New("migration staging sink rejected object")
	incomplete, err := tree.VisitNativeMigrationUnitWithLease(ctx, lease, album, nativeMigrationTestSource, func(context.Context, NativeMigrationObject) error { return stagingErr })
	if !errors.Is(err, stagingErr) || incomplete != (NativeMigrationUnit{}) {
		t.Fatal("sink failure returned a complete roster proof", err)
	}
}

func TestNativeMigrationUnitRejectsUnsettledOrForeignRoster(t *testing.T) {
	db, tree, root, _, _ := fencedFixture(t)
	publisher, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	music := nativeMigrationTestDirectory(t, tree, tree.rootID, "music")
	check := func(parent, owner string, expected error) int {
		t.Helper()
		unit, observed, err := readNativeMigrationTestPlan(t, tree, parent, owner)
		if !errors.Is(err, expected) || unit != (NativeMigrationUnit{}) {
			t.Fatal("ineligible roster returned a plan", err)
		}
		return len(observed)
	}
	mixed := nativeMigrationTestDirectory(t, tree, music, "mixed")
	nativeMigrationTestFile(t, tree, publisher, mixed, nativeMigrationTestSource, "one.mp3", false)
	check(mixed, nativeMigrationTestOther, ErrConflict)
	nativeMigrationTestFile(t, tree, publisher, mixed, nativeMigrationTestOther, "two.mp3", false)
	check(mixed, nativeMigrationTestSource, ErrConflict)

	pending := nativeMigrationTestDirectory(t, tree, music, "pending")
	check(pending, nativeMigrationTestSource, ErrConflict)
	nativeMigrationTestFile(t, tree, publisher, pending, nativeMigrationTestSource, "settled.mp3", false)
	nativeMigrationTestFile(t, tree, nil, pending, nativeMigrationTestSource, "uploading.mp3", false)
	if observed := check(pending, nativeMigrationTestSource, ErrRevocationPending); observed != 1 {
		t.Fatal("expected one provisional visit without a final proof", observed)
	}

	provider := nativeMigrationTestDirectory(t, tree, music, "provider")
	s3 := fixtureS3Placement()
	s3.ObjectID, s3.Proof.MediaID = strings.Repeat("3", 64), strings.Repeat("3", 64)
	entry := Entry{ParentID: provider, ObjectID: s3.ObjectID, Kind: "audio", Name: "provider.mp3"}
	if err = tree.createImportedS3Fixture(context.Background(), entry, Facts{ObjectID: entry.ObjectID}, s3); err != nil {
		t.Fatal(err)
	}
	check(provider, s3.MemberID, ErrInvalid)

	damaged := nativeMigrationTestDirectory(t, tree, music, "damaged")
	good := nativeMigrationTestFile(t, tree, publisher, damaged, nativeMigrationTestSource, "settled.mp3", false)
	index, err := tree.tree.ObjectIndex(good.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`DELETE FROM sealed_tree_records WHERE object_index=?`, index); err != nil {
		t.Fatal(err)
	}
	check(damaged, nativeMigrationTestSource, ErrInvalid)

	canonicalEmpty := nativeMigrationTestDirectory(t, tree, music, "empty-blob")
	entry = Entry{ParentID: canonicalEmpty, ObjectID: fmt.Sprintf("%064x", 4), Kind: "audio", Name: "zero.mp3"}
	placement := fixturePlacement(t, entry.ObjectID)
	shaEmpty := sha256.Sum256(nil)
	placement.OwnerID, placement.State, placement.Bytes, placement.SHA256 = nativeMigrationTestSource, "active", 0, hex.EncodeToString(shaEmpty[:])
	placement.BlobID, placement.ReadAlias = "", ""
	ctx := context.Background()
	prepared, err := tree.PrepareFileWithFreshLocators(ctx, entry, placement, Facts{ObjectID: entry.ObjectID})
	if err != nil {
		t.Fatal(err)
	}
	if err = tree.PublishPending(ctx, prepared.OperationID, publisher, bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	empty, observed, err := readNativeMigrationTestPlan(t, tree, canonicalEmpty, nativeMigrationTestSource)
	if err != nil || empty.ObjectCount != 1 || len(observed) != 1 || observed[0].Bytes != 0 || observed[0].SHA256 != placement.SHA256 {
		t.Fatal("canonical empty placement refused", err)
	}
}

func TestNativeMigrationUnitRequiresCurrentReadFence(t *testing.T) {
	_, tree, _, _, _ := fencedFixture(t)
	ctx := context.Background()
	music := nativeMigrationTestDirectory(t, tree, tree.rootID, "music")
	parent := nativeMigrationTestDirectory(t, tree, music, "album")
	visit := func(context.Context, NativeMigrationObject) error { return nil }
	if _, err := tree.VisitNativeMigrationUnitWithLease(ctx, nil, parent, nativeMigrationTestSource, visit); !errors.Is(err, ErrFenceRequired) {
		t.Fatal("missing lease accepted", err)
	}
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = tree.VisitNativeMigrationUnitWithLease(cancelled, lease, parent, nativeMigrationTestSource, visit); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled lease read accepted", err)
	}
	lease.Release()
	if _, err = tree.VisitNativeMigrationUnitWithLease(ctx, lease, parent, nativeMigrationTestSource, visit); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("released lease accepted", err)
	}
}
