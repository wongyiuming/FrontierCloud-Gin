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
)

func TestS3AndNativeCatalogEntriesHaveAuthenticatedSeparatePlacements(t *testing.T) {
	ctx := context.Background()
	db, s, root, _, _ := fencedFixture(t)
	dir := Entry{ParentID: s.rootID, ObjectID: fmt.Sprintf("%064x", 101), Kind: "directory", Name: "music"}
	if err := s.CreateDirectoryWithFacts(ctx, dir, Facts{ObjectID: dir.ObjectID}); err != nil {
		t.Fatal(err)
	}
	s3 := fixtureS3Placement()
	s3.ObjectID = fmt.Sprintf("%064x", 102)
	s3.Proof.MediaID = s3.ObjectID
	entry := Entry{ParentID: dir.ObjectID, ObjectID: s3.ObjectID, Kind: "audio", Name: "provider-secret.mp3"}
	if _, err := db.Exec(`CREATE TRIGGER s3_insert_fail BEFORE INSERT ON sealed_tree_placements BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.createImportedS3Fixture(ctx, entry, Facts{ObjectID: entry.ObjectID}, s3); err == nil {
		t.Fatal("partial placement accepted")
	}
	var count int
	idx, _ := s.tree.ObjectIndex(entry.ObjectID)
	if err := db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_records WHERE object_index=?`, idx).Scan(&count); err != nil || count != 0 {
		t.Fatal("S3 import did not roll back", err)
	}
	if _, err := db.Exec(`DROP TRIGGER s3_insert_fail`); err != nil {
		t.Fatal(err)
	}
	if err := s.createImportedS3Fixture(ctx, entry, Facts{ObjectID: entry.ObjectID}, s3); err != nil {
		t.Fatal(err)
	}
	hiddenS3 := s3
	hiddenS3.ObjectID = fmt.Sprintf("%064x", 104)
	hiddenS3.Proof.MediaID = hiddenS3.ObjectID
	hiddenS3.Proof.Key = "objects/hidden-provider-key"
	hiddenEntry := Entry{ParentID: dir.ObjectID, ObjectID: hiddenS3.ObjectID, Kind: "audio", Name: "hidden-provider.mp3"}
	if err := s.createImportedS3Fixture(ctx, hiddenEntry, Facts{ObjectID: hiddenEntry.ObjectID, Visibility: &VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}}, hiddenS3); err != nil {
		t.Fatal(err)
	}
	native := Entry{ParentID: dir.ObjectID, ObjectID: fmt.Sprintf("%064x", 103), Kind: "audio", Name: "local.mp3"}
	sum := sha256.Sum256(nil)
	p := fixturePlacement(t, native.ObjectID)
	p.Bytes, p.SHA256, p.BlobID, p.ReadAlias, p.State = 0, hex.EncodeToString(sum[:]), "", "", "active"
	op, err := s.PrepareFileWithFreshLocators(ctx, native, p, Facts{ObjectID: native.ObjectID})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.PublishPending(ctx, op.OperationID, pub, bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Check(ctx); err != nil {
		t.Fatal("tree check rejected valid mixed placements", err)
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	items, next, err := s.ListCatalogPageWithLease(ctx, lease, dir.ObjectID, "", 10, false)
	view, viewErr := s.ReadS3ListingObjectWithLease(ctx, lease, entry.ObjectID, false)
	if viewErr != nil || view.Path != "music/provider-secret.mp3" || view.Placement.Proof.Key != s3.Proof.Key || view.PlacementRevision != 1 {
		t.Fatal("S3 object snapshot", viewErr)
	}
	if _, e := s.ReadS3ListingObjectWithLease(ctx, lease, native.ObjectID, false); e == nil {
		t.Fatal("native object treated as S3")
	}
	if _, e := s.ReadS3ListingObjectWithLease(ctx, lease, hiddenEntry.ObjectID, false); !errors.Is(e, ErrHidden) {
		t.Fatal("hidden S3 became visible", e)
	}
	if _, e := s.ReadS3ListingObjectWithLease(ctx, lease, hiddenEntry.ObjectID, true); e != nil {
		t.Fatal("explicit hidden S3 display rejected", e)
	}
	lease.Release()
	if _, e := s.ReadS3ListingObjectWithLease(ctx, lease, entry.ObjectID, false); e == nil {
		t.Fatal("released lease accepted")
	}
	if err != nil || next != "" || len(items) != 2 {
		t.Fatal("mixed listing", err)
	}
	for _, item := range items {
		if item.Entry.ObjectID == entry.ObjectID {
			if item.Placement != nil || item.S3Placement == nil || item.S3Placement.Proof.Key != s3.Proof.Key {
				t.Fatal("S3 metadata mixed with native")
			}
		} else if item.Entry.ObjectID == native.ObjectID {
			if item.Placement == nil || item.S3Placement != nil {
				t.Fatal("native metadata mixed with S3")
			}
		} else {
			t.Fatal("unexpected item")
		}
	}
	var sealed []byte
	if err = db.QueryRow(`SELECT sealed FROM sealed_tree_placements WHERE object_index=?`, idx).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{s3.Proof.Key, s3.Location.Bucket, s3.Location.Endpoint, entry.Name} {
		if strings.Contains(string(sealed), secret) {
			t.Fatal("placement plaintext leaked")
		}
	}
	if _, err = db.Exec(`INSERT INTO sealed_tree_aliases(alias_index,object_index) VALUES(?,?)`, strings.Repeat("d", 64), idx); err != nil {
		t.Fatal(err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.ListCatalogPageWithLease(ctx, lease, dir.ObjectID, "", 10, false); err == nil {
		t.Fatal("S3 native alias accepted")
	}
	lease.Release()
	if _, err = db.Exec(`DELETE FROM sealed_tree_aliases WHERE object_index=?`, idx); err != nil {
		t.Fatal(err)
	}
	other := strings.Repeat("e", 64)
	if _, err = db.Exec(`INSERT INTO sealed_tree_blob_ids(blob_index) VALUES(?)`, other); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE sealed_tree_placements SET blob_index=? WHERE object_index=?`, other, idx); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Check(ctx); err == nil {
		t.Fatal("tree check accepted substituted S3 slot")
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if _, _, err = s.ListCatalogPageWithLease(ctx, lease, dir.ObjectID, "", 10, false); err == nil {
		t.Fatal("S3 slot substitution accepted")
	}
}
