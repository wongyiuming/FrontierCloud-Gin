//go:build linux

package business_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
)

func TestMasterUploadRequiresHeldOwnerFenceWhenMarked(t *testing.T) {
	ctx := context.Background()
	db := database(t)
	raw := db.(interface{ Database() *sql.DB }).Database()
	if _, err := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: strings.Repeat("1", 32), Role: "Standalone", PrivateKey: "fixture", CreatedAt: 123}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: "https://master.test", Allocation: 2 * store.GiB, PhysicalFree: 10 * store.GiB}, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	reservation, err := db.Pool().ReserveUpload(ctx, "music/fixture/track.mp3", "primary", 10, 10*store.GiB, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	object := store.MediaObject{ID: reservation.MediaID, Path: reservation.Path, Kind: reservation.Kind}
	dir := t.TempDir()
	if err = os.Mkdir(filepath.Join(dir, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fence, err := ownerfence.Create(root, dir, ownerFixtureCodec{})
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Nodes().(*business.Repository)
	if err = repo.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return fence.Acquire(c, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err = repo.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	other := business.New(raw, db.Backend())
	complete := func(c context.Context, target *business.Repository) error {
		return target.CompleteMasterUpload(c, reservation.ID, object, 10, `"digest"`, 9*store.GiB, store.AdminAudit{})
	}
	if err = complete(ctx, repo); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("configured store accepted no token", err)
	}
	if err = complete(ctx, other); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("independent store bypassed marker", err)
	}
	var escaped context.Context
	if err = repo.WithOwnerControlExclusive(ctx, func(held context.Context) error {
		escaped = held
		if e := complete(held, other); !errors.Is(e, store.ErrNodeState) {
			return errors.New("wrong repository token accepted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = complete(escaped, repo); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("expired token accepted", err)
	}
	if _, err = raw.ExecContext(ctx, `INSERT INTO sealed_tree_meta(singleton,version,verifier,salt,root_encryption_id,root_sealed,write_fence) VALUES(1,1,?,?,?, ?,0)`, strings.Repeat("a", 64), []byte{1}, strings.Repeat("b", 64), []byte{1}); err != nil {
		t.Fatal(err)
	}
	if err = repo.WithOwnerControlExclusive(ctx, func(held context.Context) error { return complete(held, repo) }); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("legacy upload accepted under durable tree marker", err)
	}
	if _, err = raw.ExecContext(ctx, `DELETE FROM sealed_tree_meta WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	if err = repo.WithOwnerControlExclusive(ctx, func(held context.Context) error {
		var original string
		if e := raw.QueryRowContext(held, `SELECT fence_tag FROM sealed_tree_owner_fence WHERE singleton=1`).Scan(&original); e != nil {
			return e
		}
		if _, e := raw.ExecContext(held, `UPDATE sealed_tree_owner_fence SET fence_tag=? WHERE singleton=1`, strings.Repeat("f", 64)); e != nil {
			return e
		}
		defer raw.ExecContext(context.Background(), `UPDATE sealed_tree_owner_fence SET fence_tag=? WHERE singleton=1`, original)
		if e := complete(held, repo); !errors.Is(e, store.ErrNodeState) {
			return errors.New("transaction accepted replaced owner marker")
		}
		return nil
	}); err != nil {
		t.Fatal("marker replacement", err)
	}
	trigger := `CREATE TRIGGER fail_master_owner BEFORE INSERT ON media_objects BEGIN SELECT RAISE(ABORT,'fixture'); END`
	if db.Backend() == "mysql" {
		trigger = `CREATE TRIGGER fail_master_owner BEFORE INSERT ON media_objects FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='fixture'`
	}
	if _, err = raw.ExecContext(ctx, trigger); err != nil {
		t.Fatal(err)
	}
	if err = repo.WithOwnerControlExclusive(ctx, func(held context.Context) error { return complete(held, repo) }); err == nil {
		t.Fatal("injected transaction failure accepted")
	}
	var count int
	if err = raw.QueryRowContext(ctx, `SELECT COUNT(*) FROM media_objects WHERE media_id=?`, object.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed upload partly committed", err)
	}
	if _, err = raw.ExecContext(ctx, `DROP TRIGGER fail_master_owner`); err != nil {
		t.Fatal(err)
	}
	if err = repo.WithOwnerControlExclusive(ctx, func(held context.Context) error { return complete(held, repo) }); err != nil {
		t.Fatal("valid held owner rejected", err)
	}
}
