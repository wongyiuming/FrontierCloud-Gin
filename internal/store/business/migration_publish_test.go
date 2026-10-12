package business_test

import (
	"context"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"testing"
)

func TestPeerMigrationPublicationRollbackAndReplay(t *testing.T) {
	db, raw, repo, rel, h, l, v := peerMigrationFixture(t, false)
	ctx := context.Background()
	if e := repo.RegisterPeerMigration(ctx, rel, h, l, "queued", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e := repo.RegisterPeerMigrationObject(ctx, rel, l, v, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	o := store.MediaObject{ID: v.Object.ObjectID, Path: v.Object.TargetPath, Kind: v.Object.Kind}
	publish := func() error {
		return repo.CompletePeerMediaPublication(ctx, rel, l, v.Object.ID, o, v.Object.Bytes, v.Proof.SHA256, 20*store.GiB, store.NodeAudit{})
	}
	if e := publish(); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("unverified publication", e)
	}
	if e := repo.VerifyPeerMigrationObject(ctx, rel, l, v.Object.ID, v.Object.Bytes, v.Proof.SHA256); e != nil {
		t.Fatal(e)
	}
	trigger := "CREATE TRIGGER block_peer_publication BEFORE UPDATE ON migration_storage_journal BEGIN SELECT RAISE(ABORT,'publication unavailable'); END"
	if db.Backend() == "mysql" {
		trigger = "CREATE TRIGGER block_peer_publication BEFORE UPDATE ON migration_storage_journal FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='publication unavailable'"
	}
	if _, e := raw.Exec(trigger); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { raw.Exec("DROP TRIGGER IF EXISTS block_peer_publication") })
	if e := publish(); e == nil {
		t.Fatal("fault ignored")
	}
	if found, e := db.Media().ObjectByID(ctx, o.ID); e != nil || found != nil {
		t.Fatal("failed commit leaked object", found, e)
	}
	if _, e := db.Media().EnsureObjects(ctx, []store.MediaObject{{Path: o.Path, Kind: o.Kind}}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("ordinary discovery assigned new identity to migration material", e)
	}
	var used, reserved, capacity int64
	check := func(wantUsed, wantReserved int64) {
		t.Helper()
		if e := raw.QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", h.TargetID).Scan(&used, &reserved); e != nil {
			t.Fatal(e)
		}
		if e := raw.QueryRow("SELECT reserved_bytes FROM migration_capacity WHERE task_id=?", h.TaskID).Scan(&capacity); e != nil {
			t.Fatal(e)
		}
		if used != wantUsed || reserved != wantReserved || capacity != wantReserved {
			t.Fatal(used, reserved, capacity)
		}
	}
	check(0, v.Object.Bytes)
	if _, e := raw.Exec("DROP TRIGGER block_peer_publication"); e != nil {
		t.Fatal(e)
	}
	for range 2 {
		if e := publish(); e != nil {
			t.Fatal(e)
		}
		check(v.Object.Bytes, 0)
	}
	// After task scopes are reconciled, ordinary managed deletion must consume
	// the migration ledger without requiring a fabricated upload reservation.
	if _, e := raw.Exec("DELETE FROM migration_scopes WHERE task_id=?", h.TaskID); e != nil {
		t.Fatal(e)
	}
	operation := store.DeleteOperation{ID: hashPath(t.Name() + "delete")[:32], State: "pending", Items: []store.DeleteItem{{Slot: "0", Path: o.Path, OwnedID: o.ID, Bytes: v.Object.Bytes}}}
	if e := db.Pool().PrepareOwnedDelete(ctx, rel, operation, store.NodeAudit{}); e != nil {
		t.Fatal("migrated object cannot use ordinary deletion", e)
	}
	if e := db.Pool().CommitOwnedDelete(ctx, operation.ID, 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	check(0, 0)
	t.Cleanup(func() { raw.Exec("DELETE FROM media_delete_operations WHERE operation_id=?", operation.ID) })
	o.Path += ".different"
	if e := publish(); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("replay path changed", e)
	}
}
