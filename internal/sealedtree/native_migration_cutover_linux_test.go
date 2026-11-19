//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

func TestNativeMigrationCutoverRollsBackAndPreservesBusinessFacts(t *testing.T) {
	ctx := context.Background()
	db, tree, root, _, _ := fencedFixture(t)
	publisher, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	music := nativeMigrationTestDirectory(t, tree, tree.rootID, "music")
	album := nativeMigrationTestDirectory(t, tree, music, "album")
	track := nativeMigrationTestFile(t, tree, publisher, album, nativeMigrationTestSource, "first.mp3", false)
	hidden := nativeMigrationTestFile(t, tree, publisher, album, nativeMigrationTestSource, "hidden.mp3", true)
	for index := range 127 {
		nativeMigrationTestFile(t, tree, publisher, album, nativeMigrationTestSource, fmt.Sprintf("track-%d.mp3", index), false)
	}
	unit, objects, err := readNativeMigrationTestPlan(t, tree, album, nativeMigrationTestSource)
	if err != nil || unit.ObjectCount != 129 {
		t.Fatal(unit, err)
	}
	lyrics := nativeMigrationTestDirectory(t, tree, tree.rootID, "lyrics")
	lyricID, err := NewBlobID()
	if err != nil {
		t.Fatal(err)
	}
	lyricBytes := []byte("[00:00.00]fixture lyric")
	lyricDigest := sha256.Sum256(lyricBytes)
	lyric := fixturePlacement(t, lyricID)
	lyric.ReadAlias, lyric.BlobID = "", ""
	lyric.Bytes, lyric.SHA256 = int64(len(lyricBytes)), hex.EncodeToString(lyricDigest[:])
	entry := Entry{ObjectID: lyricID, ParentID: lyrics, Name: "first.lrc", Kind: "lyric"}
	prepared, err := tree.PrepareFileWithFreshLocators(ctx, entry, lyric, Facts{ObjectID: lyricID})
	if err != nil {
		t.Fatal(err)
	}
	if err = tree.PublishPending(ctx, prepared.OperationID, publisher, bytes.NewReader(lyricBytes)); err != nil {
		t.Fatal(err)
	}
	facts, rev, err := tree.GetFacts(ctx, track.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	facts.Visibility = &VisibilityFact{Hidden: 0, UpdatedAt: "later"}
	facts.Playback = &PlaybackFact{Preference: 17, PlayScore: 3, CreatedAt: "earlier", UpdatedAt: "later"}
	facts.Lyric = &LyricFact{LyricID: lyricID, LegacyMediaPath: "music/album/first.mp3", LegacyLyricPath: "lyrics/first.lrc", CreatedAt: "earlier", UpdatedAt: "later"}
	rev, err = tree.SetFacts(ctx, facts, rev)
	if err != nil {
		t.Fatal(err)
	}
	oldTrack, err := tree.GetPlacement(ctx, track.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	readFence, err := tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := tree.CaptureCatalogScopeWithLease(ctx, readFence, album, true)
	readFence.Release()
	if err != nil {
		t.Fatal(err)
	}
	admission := NativeMigrationCutover{
		Unit: unit, MasterID: strings.Repeat("3", 32), TargetOwnerID: nativeMigrationTestOther, TargetRelationshipID: strings.Repeat("4", 32),
	}
	newID := func() string {
		t.Helper()
		id, err := NewBlobID()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	publications := make(map[string]NativeMigrationPublication)
	var expectedBytes int64
	sourceTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sourceTx.Rollback()
	for _, object := range objects {
		binding := protocol.OpaqueOwnerBinding{MasterID: admission.MasterID, OwnerID: admission.TargetOwnerID,
			RelationshipID: admission.TargetRelationshipID, Alias: newID(), Blob: newID(),
			Size: object.Bytes, Digest: object.SHA256, Descriptor: object.Descriptor}
		binding.Revision, err = protocol.OpaquePlacementRevisionFromDescriptor(binding.Alias, binding.Blob, binding.Digest, binding.Descriptor, binding.Size)
		if err != nil {
			t.Fatal(err)
		}
		sourceOp, err := tree.completedNativePublicationOperation(ctx, sourceTx, object.ObjectID, object.BlobID)
		if err != nil {
			t.Fatal(err)
		}
		publications[object.ObjectID] = NativeMigrationPublication{SourceOperationID: sourceOp, OperationID: newID(), Binding: binding}
		expectedBytes += object.Bytes
	}
	if err = sourceTx.Commit(); err != nil {
		t.Fatal(err)
	}
	cutover := func(request NativeMigrationCutover, lateFailure error, failReceipt bool) (int, error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		called := 0
		err := tree.WithCoordinatedMutation(ctx, db, func(m *CoordinatedMutation) error {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback()
			moved, err := m.CutoverNativeMigrationUnitTx(ctx, tx, request, func(_ context.Context, object NativeMigrationObject) (NativeMigrationPublication, error) {
				called++
				receipt := publications[object.ObjectID]
				if failReceipt && called == len(objects) {
					receipt.Binding.RelationshipID = strings.Repeat("5", 32)
				}
				return receipt, nil
			})
			if err != nil {
				return err
			}
			if moved != expectedBytes {
				return fmt.Errorf("cutover moved %d bytes, expected %d", moved, expectedBytes)
			}
			if lateFailure != nil {
				return lateFailure
			}
			return tx.Commit()
		})
		return called, err
	}
	assertRolledBack := func() {
		t.Helper()
		lease, err := tree.AcquireReadFence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		err = tree.CheckCatalogScopeWithLease(ctx, lease, album, true, scope)
		lease.Release()
		if err != nil {
			t.Fatalf("rollback changed catalog scope: %v", err)
		}
		for _, object := range objects {
			placement, err := tree.GetPlacement(ctx, object.ObjectID)
			if err != nil || placement.OwnerID != admission.Unit.SourceOwnerID || placement.BlobID != object.BlobID || placement.ReadAlias != object.ReadAlias {
				t.Fatalf("rollback left a moved placement: %v", err)
			}
			var count int
			err = db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_operation_ids WHERE operation_id=?`, publications[object.ObjectID].OperationID).Scan(&count)
			if err != nil || count != 0 {
				t.Fatalf("rollback left a new publication: %v", err)
			}
		}
	}
	if count, err := cutover(admission, nil, true); count != len(objects) || !errors.Is(err, ErrConflict) {
		t.Fatal(count, err)
	}
	assertRolledBack()
	last := objects[len(objects)-1].ObjectID
	original := publications[last]
	wrongSource := original
	wrongSource.SourceOperationID = publications[objects[0].ObjectID].SourceOperationID
	publications[last] = wrongSource
	if count, err := cutover(admission, nil, false); count != len(objects) || !errors.Is(err, ErrConflict) {
		t.Fatal(count, err)
	}
	publications[last] = original
	assertRolledBack()
	stale := admission
	stale.Unit.ObjectCount--
	if count, err := cutover(stale, nil, false); count != len(objects) || !errors.Is(err, ErrConflict) {
		t.Fatal(count, err)
	}
	assertRolledBack()
	settlement := errors.New("simulated capacity settlement failure")
	if count, err := cutover(admission, settlement, false); count != len(objects) || !errors.Is(err, settlement) {
		t.Fatal(count, err)
	}
	assertRolledBack()
	if count, err := cutover(admission, nil, false); count != len(objects) || err != nil {
		t.Fatal(count, err)
	}
	newTrack, err := tree.GetPlacement(ctx, track.ObjectID)
	oldTrack.OwnerID = admission.TargetOwnerID
	oldTrack.BlobID, oldTrack.ReadAlias = publications[track.ObjectID].Binding.Blob, publications[track.ObjectID].Binding.Alias
	if err != nil || !reflect.DeepEqual(oldTrack, newTrack) {
		t.Fatalf("cutover changed fields other than owner and locators: %v", err)
	}
	actualFacts, actualRev, err := tree.GetFacts(ctx, track.ObjectID)
	if err != nil || actualRev != rev || !reflect.DeepEqual(facts, actualFacts) {
		t.Fatalf("cutover changed business facts: %v", err)
	}
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if err = tree.CheckCatalogScopeWithLease(ctx, lease, album, true, scope); err == nil {
		t.Fatal("successful cutover left the pre-cutover catalog proof current")
	}
	if _, err = tree.ReadListingObjectByAliasWithLease(ctx, lease, track.ReadAlias, true); err == nil {
		t.Fatal("retired alias still had live catalog authority")
	}
	if got, err := tree.ReadListingObjectByAliasWithLease(ctx, lease, publications[hidden.ObjectID].Binding.Alias, true); err != nil || got.Entry.ObjectID != hidden.ObjectID {
		t.Fatal("hidden object was lost", err)
	}
	if got, linked, err := tree.ReadLinkedVisibleLyricWithLease(ctx, lease, track.ObjectID); err != nil || got.Entry.ObjectID != track.ObjectID || linked.Entry != entry {
		t.Fatal("linked lyric no longer resolves", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, object := range objects {
		receipt := publications[object.ObjectID]
		if err := tree.verifyCompletedNativePublication(ctx, tx, object.ObjectID, receipt.Binding.Blob, receipt.OperationID); err != nil {
			t.Fatal("new publication is not recoverable", err)
		}
		if _, err := tree.completedNativePublicationOperation(ctx, tx, object.ObjectID, object.BlobID); err != nil {
			t.Fatal("old publication proof was lost", err)
		}
	}
}
