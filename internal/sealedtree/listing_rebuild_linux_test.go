//go:build linux

package sealedtree

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestListingRebuildResumesAndFailsClosed(t *testing.T) {
	ctx := context.Background()
	db, s, root, _, _ := fencedFixture(t)
	for i := 0; i < 4; i++ {
		entry := Entry{ParentID: s.rootID, ObjectID: fmt.Sprintf("%064x", i+100), Kind: "directory", Name: fmt.Sprintf("entry-%d", i)}
		facts := Facts{ObjectID: entry.ObjectID}
		if i == 3 {
			facts.Visibility = &VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}
		}
		if err := s.CreateDirectoryWithFacts(ctx, entry, facts); err != nil {
			t.Fatal(err)
		}
	}
	// Simulate an older encrypted tree with the new, empty index schema provisioned.
	if _, err := db.Exec(`DELETE FROM sealed_tree_listing`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM sealed_tree_listing_meta`); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginListingRebuild(ctx); err != nil {
		t.Fatal(err)
	}
	if done, err := s.ContinueListingRebuild(ctx, 1); err != nil || done {
		t.Fatal("first batch", done, err)
	}
	var before string
	if err := db.QueryRow(`SELECT build_cursor FROM sealed_tree_listing_meta WHERE singleton=1`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER reject_rebuild BEFORE INSERT ON sealed_tree_listing WHEN NEW.entry_count=-1 BEGIN SELECT RAISE(ABORT,'injected'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ContinueListingRebuild(ctx, 1); err == nil {
		t.Fatal("injected index failure ignored")
	}
	var after string
	if err := db.QueryRow(`SELECT build_cursor FROM sealed_tree_listing_meta WHERE singleton=1`).Scan(&after); err != nil || before != after {
		t.Fatal("failed batch advanced checkpoint", err)
	}
	if _, err := db.Exec(`DROP TRIGGER reject_rebuild`); err != nil {
		t.Fatal(err)
	}
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("f", 64), Kind: "directory", Name: "blocked"}
	if err := s.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: entry.ObjectID}); err == nil {
		t.Fatal("writer accepted during rebuild")
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.ListVisibleWithLease(ctx, lease, s.rootID, "", 2); err == nil {
		t.Fatal("listing accepted during rebuild")
	}
	lease.Release()
	// Reopen the store and fence as after a process restart; the checkpoint is durable.
	reopened, err := OpenSQLite(ctx, db, fixture(t), s.rootID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenFence(ctx, reopened, root, root.Name()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		done, e := reopened.ContinueListingRebuild(ctx, 1)
		if e != nil {
			t.Fatal(e)
		}
		if done {
			break
		}
		if i == 9 {
			t.Fatal("rebuild did not finish")
		}
	}
	lease, err = reopened.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	items, next, err := reopened.ListVisibleWithLease(ctx, lease, reopened.rootID, "", 10)
	lease.Release()
	if err != nil || len(items) != 3 || next != "" {
		t.Fatal("wrong visible result after rebuild", len(items), next, err)
	}
	if err = reopened.BeginListingRebuild(ctx); err == nil {
		t.Fatal("existing index overwritten")
	}
}

func TestListingIndexTamperAndAtomicWriter(t *testing.T) {
	ctx := context.Background()
	db, s, _, _, _ := fencedFixture(t)
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "first"}
	if err := s.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: entry.ObjectID}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER reject_listing BEFORE INSERT ON sealed_tree_listing WHEN NEW.entry_count=-1 BEGIN SELECT RAISE(ABORT,'injected'); END`); err != nil {
		t.Fatal(err)
	}
	failed := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("c", 64), Kind: "directory", Name: "must-rollback"}
	if err := s.CreateDirectoryWithFacts(ctx, failed, Facts{ObjectID: failed.ObjectID}); err == nil {
		t.Fatal("writer ignored index failure")
	}
	if _, _, err := s.Get(ctx, failed.ObjectID); err == nil {
		t.Fatal("record persisted despite index failure")
	}
	if _, err := db.Exec(`DROP TRIGGER reject_listing`); err != nil {
		t.Fatal(err)
	}
	group := s.listingGroup(s.rootID, true)
	if _, err := db.Exec(`DELETE FROM sealed_tree_listing WHERE group_tag=? AND entry_count=-1`, group); err != nil {
		t.Fatal(err)
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if items, _, err := s.ListVisibleWithLease(ctx, lease, s.rootID, "", 10); err == nil || len(items) != 0 {
		t.Fatal("missing visible index row accepted", err)
	}
}

func TestVisiblePageRejectsMissingReservationAndUnexpectedRevocation(t *testing.T) {
	for _, mode := range []string{"missing-facts-reservation", "unexpected-revocation"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			db, s, _, _, _ := fencedFixture(t)
			entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "entry"}
			if err := s.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: entry.ObjectID}); err != nil {
				t.Fatal(err)
			}
			index, err := s.tree.ObjectIndex(entry.ObjectID)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "missing-facts-reservation":
				if _, err = db.Exec(`DELETE FROM sealed_tree_encryption_ids WHERE encryption_id=(SELECT encryption_id FROM sealed_tree_facts WHERE object_index=?)`, index); err != nil {
					t.Fatal(err)
				}
			case "unexpected-revocation":
				if _, err = db.Exec(`INSERT INTO sealed_tree_revocations(operation_index,object_index) VALUES(?,?)`, strings.Repeat("e", 64), index); err != nil {
					t.Fatal(err)
				}
			}
			lease, err := s.AcquireReadFence(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Release()
			if items, _, e := s.ListVisibleWithLease(ctx, lease, s.rootID, "", 10); e == nil || len(items) != 0 {
				t.Fatal("inconsistent page accepted", e)
			}
		})
	}
}
