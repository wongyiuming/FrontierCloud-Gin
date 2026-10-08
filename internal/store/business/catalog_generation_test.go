package business_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestCatalogGenerationSharedHandlesCommitAndReadOnlyRegistration(t *testing.T) {
	db := database(t)
	ctx := context.Background()
	first := db.Media().(interface{ CatalogGeneration() uint64 })
	second := db.Pool().(interface{ CatalogGeneration() uint64 })
	before := first.CatalogGeneration()
	name := "music/" + t.Name() + "/track.mp3"
	object := store.MediaObject{Path: name, Kind: "audio"}
	if _, err := db.Media().EnsureObjects(ctx, []store.MediaObject{object}); err != nil {
		t.Fatal(err)
	}
	if first.CatalogGeneration() <= before || first.CatalogGeneration() != second.CatalogGeneration() {
		t.Fatal("domain handles have isolated generations")
	}
	before = first.CatalogGeneration()
	if _, err := db.Media().EnsureObjects(ctx, []store.MediaObject{object}); err != nil {
		t.Fatal(err)
	}
	if first.CatalogGeneration() != before {
		t.Fatal("read-only object lookup invalidated warm catalog")
	}
	if err := db.Media().SetHidden(ctx, []string{name}, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	if first.CatalogGeneration() <= before {
		t.Fatal("committed visibility omitted invalidation")
	}
}

func TestCatalogGenerationDoesNotPublishRolledBackAudit(t *testing.T) {
	db := database(t)
	ctx := context.Background()
	repo := db.Media()
	g := repo.(interface{ CatalogGeneration() uint64 })
	conn := db.(interface{ Database() *sql.DB }).Database()
	query := "CREATE TRIGGER reject_cache_audit BEFORE INSERT ON admin_audit_log BEGIN SELECT RAISE(ABORT,'audit unavailable'); END"
	if db.Backend() == "mysql" {
		query = "CREATE TRIGGER reject_cache_audit BEFORE INSERT ON admin_audit_log FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='audit unavailable'"
	}
	if _, err := conn.Exec(query); err != nil {
		t.Fatal(err)
	}
	defer conn.Exec("DROP TRIGGER reject_cache_audit")
	before := g.CatalogGeneration()
	if err := repo.SetHidden(ctx, []string{"music/cache-rollback"}, true, store.AdminAudit{}); err == nil {
		t.Fatal("unaudited mutation committed")
	}
	if g.CatalogGeneration() != before {
		t.Fatal("rollback published cache generation")
	}
	hidden, err := repo.HiddenPaths(ctx)
	if err != nil || hidden["music/cache-rollback"] {
		t.Fatal("rolled-back visibility survived", hidden, err)
	}
}
