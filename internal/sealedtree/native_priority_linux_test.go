package sealedtree

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestNativePriorityMoveIsAtomicAndFenced(t *testing.T) {
	ctx := context.Background()
	db, tree, _, _, _ := fencedFixture(t)
	if _, err := db.Exec(`CREATE TABLE admin_audit_log(action TEXT,target_count INTEGER,result TEXT,created_at TEXT)`); err != nil {
		t.Fatal(err)
	}
	root := Entry{ParentID: tree.rootID, ObjectID: fmt.Sprintf("%064x", 11), Name: "music", Kind: "directory"}
	if err := tree.CreateDirectoryWithFacts(ctx, root, Facts{ObjectID: root.ObjectID}); err != nil {
		t.Fatal(err)
	}
	names := []string{"A", "b", "c"}
	for i, name := range names {
		entry := Entry{ParentID: root.ObjectID, ObjectID: fmt.Sprintf("%064x", 12+i), Name: name, Kind: "directory"}
		playback := &PlaybackFact{Preference: store.PriorityMaximum, CreatedAt: "2026", UpdatedAt: "2026"}
		if err := tree.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: entry.ObjectID, Playback: playback}); err != nil {
			t.Fatal(err)
		}
	}
	read := func() store.PriorityOrder {
		t.Helper()
		lease, err := tree.AcquireReadFence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer lease.Release()
		order, err := tree.NativePriorityOrderWithLease(ctx, lease, "music", "directory")
		if err != nil {
			t.Fatal(err)
		}
		return order
	}
	before := read()
	move := store.PriorityMove{Path: "music/c", Before: "music/A", Revision: before.Revision}
	if _, err := db.Exec(`CREATE TRIGGER reject_drag BEFORE INSERT ON admin_audit_log BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := tree.MoveNativePriority(ctx, "music", "directory", move); err == nil {
		t.Fatal("drag without atomic audit accepted")
	}
	if got := read(); got.Revision != before.Revision || !slices.Equal(got.Items, before.Items) {
		t.Fatal("failed drag changed the encrypted facts", got)
	}
	if _, err := db.Exec(`DROP TRIGGER reject_drag`); err != nil {
		t.Fatal(err)
	}
	after, err := tree.MoveNativePriority(ctx, "music", "directory", move)
	if err != nil || after.Changed != 2 || len(after.Items) != 3 || after.Items[0].Path != "music/c" ||
		after.Items[1].Path != "music/A" || after.Items[2].Path != "music/b" || after.Revision == before.Revision {
		t.Fatal("drag failed to preserve the requested order", after, err)
	}
	if got := read(); got.Revision != after.Revision || !slices.Equal(got.Items, after.Items) {
		t.Fatal("new order was not persisted", got)
	}
	if _, err := tree.MoveNativePriority(ctx, "music", "directory", move); !errors.Is(err, store.ErrPriorityStale) {
		t.Fatal("outdated revision accepted", err)
	}
	var count, targets int
	if err = db.QueryRow(`SELECT COUNT(*),SUM(target_count) FROM admin_audit_log WHERE action='priority_reorder'`).Scan(&count, &targets); err != nil || count != 1 || targets != 2 {
		t.Fatal("expected one audit event for both changes", count, targets, err)
	}
}
