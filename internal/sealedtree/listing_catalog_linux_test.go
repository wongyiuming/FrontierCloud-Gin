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

func TestCatalogPageBatchesAuthenticatedPlacement(t *testing.T) {
	for _, mode := range []string{"valid", "missing-alias", "missing-blob-reservation", "corrupt-placement"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			db, s, root, _, _ := fencedFixture(t)
			dir := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "dir"}
			file := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("c", 64), Kind: "audio", Name: "song.mp3"}
			if err := s.CreateDirectoryWithFacts(ctx, dir, Facts{ObjectID: dir.ObjectID}); err != nil {
				t.Fatal(err)
			}
			loc := fixturePlacement(t, file.ObjectID)
			empty := sha256.Sum256(nil)
			loc.Bytes, loc.SHA256, loc.BlobID, loc.ReadAlias = 0, hex.EncodeToString(empty[:]), "", ""
			pending, err := s.PrepareFileWithFreshLocators(ctx, file, loc, Facts{ObjectID: file.ObjectID})
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
			index, err := s.tree.ObjectIndex(file.ObjectID)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "missing-alias":
				if _, err = db.Exec(`DELETE FROM sealed_tree_aliases WHERE object_index=?`, index); err != nil {
					t.Fatal(err)
				}
			case "missing-blob-reservation":
				if _, err = db.Exec(`DELETE FROM sealed_tree_blob_ids WHERE blob_index=(SELECT blob_index FROM sealed_tree_placements WHERE object_index=?)`, index); err != nil {
					t.Fatal(err)
				}
			case "corrupt-placement":
				if _, err = db.Exec(`UPDATE sealed_tree_placements SET sealed=zeroblob(length(sealed)) WHERE object_index=?`, index); err != nil {
					t.Fatal(err)
				}
			}
			lease, err := s.AcquireReadFence(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Release()
			items, next, err := s.ListCatalogPageWithLease(ctx, lease, s.rootID, "", 10, false)
			if mode != "valid" {
				if err == nil || len(items) != 0 {
					t.Fatal("tampered page accepted", err)
				}
				return
			}
			if err != nil || len(items) != 2 || next != "" {
				t.Fatal("batch listing", err)
			}
			for _, item := range items {
				switch item.Entry.ObjectID {
				case dir.ObjectID:
					if item.Placement != nil || item.Facts.ObjectID != dir.ObjectID {
						t.Fatal("directory metadata")
					}
				case file.ObjectID:
					if item.Placement == nil || item.Placement.BlobID != pending.BlobID || item.Facts.ObjectID != file.ObjectID || item.PlacementRevision != 1 {
						t.Fatal("file metadata")
					}
				default:
					t.Fatal("unexpected item")
				}
			}
		})
	}
}
