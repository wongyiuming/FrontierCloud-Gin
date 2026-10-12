package business_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestResourceMigrationUnitCommitIsAtomicVerifiedAndIdempotent(t *testing.T) {
	f := migrationDatabase(t)
	ctx := context.Background()
	p := f.plan(t, hashPath(t.Name())[:32])
	if _, e := f.repo.StartMigration(ctx, p, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	l, e := f.repo.ClaimMigration(ctx, p.ID, strings.Repeat("e", 32), time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	w, e := f.repo.MigrationWork(ctx, p.ID)
	if e != nil || len(w.Units) != 1 {
		t.Fatal(w, e)
	}
	unit := w.Units[0].ID
	if e = f.repo.PrepareMigrationPublication(ctx, l, unit); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("unverified unit admitted publication", e)
	}
	for _, o := range w.Objects {
		if e = f.repo.VerifyMigrationObject(ctx, l, o.Object.ID, o.Object.Bytes, strings.Repeat("0", 64)); !errors.Is(e, store.ErrMigrationState) {
			t.Fatal("wrong disk hash accepted", e)
		}
		if e = f.repo.VerifyMigrationObject(ctx, l, o.Object.ID, o.Object.Bytes, o.SourceSHA); e != nil {
			t.Fatal(e)
		}
	}
	if e = f.repo.PrepareMigrationPublication(ctx, l, unit); e != nil {
		t.Fatal(e)
	}
	if e = f.repo.PublishMigrationObject(ctx, l, w.Objects[0].Object.ID); e != nil {
		t.Fatal(e)
	}
	if e = f.repo.CommitMigrationUnit(ctx, l, unit, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("partially published unit committed", e)
	}
	for _, o := range w.Objects {
		if e = f.repo.PublishMigrationObject(ctx, l, o.Object.ID); e != nil {
			t.Fatal(e)
		}
	}
	for _, o := range f.objects {
		g, e := f.db.Pool().Resource(ctx, o.MediaID)
		if e != nil || g.MemberID != f.source {
			t.Fatal("publication became business authority", g, e)
		}
	}
	// Inject a database failure after ownership updates have begun. Both
	// backends must roll those changes and capacity/task facts back together.
	trigger := "CREATE TRIGGER block_migration_cutover BEFORE UPDATE ON migration_units BEGIN SELECT RAISE(ABORT,'cutover unavailable'); END"
	if f.db.Backend() == "mysql" {
		trigger = "CREATE TRIGGER block_migration_cutover BEFORE UPDATE ON migration_units FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='cutover unavailable'"
	}
	if _, e = f.raw.Exec(trigger); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.raw.Exec("DROP TRIGGER IF EXISTS block_migration_cutover") })
	if e = f.repo.CommitMigrationUnit(ctx, l, unit, store.NodeAudit{}); e == nil {
		t.Fatal("injected cutover fault ignored")
	}
	for _, o := range f.objects {
		g, e := f.db.Pool().Resource(ctx, o.MediaID)
		if e != nil || g.MemberID != f.source {
			t.Fatal("failed transaction moved authority", g, e)
		}
	}
	var reserved int64
	f.raw.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", f.target).Scan(&reserved)
	if reserved != p.Catalog.TotalBytes {
		t.Fatal("failed cutover lost reservation", reserved)
	}
	if _, e = f.raw.Exec("DROP TRIGGER block_migration_cutover"); e != nil {
		t.Fatal(e)
	}
	before := f.db.Pool().(interface{ CatalogGeneration() uint64 }).CatalogGeneration()
	if e = f.repo.CommitMigrationUnit(ctx, l, unit, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e = f.repo.CommitMigrationUnit(ctx, l, unit, store.NodeAudit{}); e != nil {
		t.Fatal("ambiguous success retry", e)
	}
	if f.db.Pool().(interface{ CatalogGeneration() uint64 }).CatalogGeneration() <= before {
		t.Fatal("placement cache not invalidated")
	}
	for _, o := range f.objects {
		g, e := f.db.Pool().Resource(ctx, o.MediaID)
		if e != nil || g.MemberID != f.target || g.ID != o.MediaID || g.ObjectID != o.MediaID {
			t.Fatal("logical identity/target placement", g, e)
		}
	}
	g, e := f.db.Pool().Resource(ctx, f.objects[0].MediaID)
	if e != nil || g.Preference != 77 {
		t.Fatal("priority lost", g, e)
	}
	w, e = f.repo.MigrationWork(ctx, p.ID)
	if e != nil || w.Task.CommittedBytes != p.Catalog.TotalBytes || w.Units[0].State != "cleanup_pending" || w.Units[0].CleanupAfter <= time.Now().Unix() {
		t.Fatal("source cleanup dependency lost", w, e)
	}
	var sourceUsed, targetUsed int64
	f.raw.QueryRow("SELECT used_bytes FROM cluster_storage_members WHERE member_id=?", f.source).Scan(&sourceUsed)
	f.raw.QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", f.target).Scan(&targetUsed, &reserved)
	if sourceUsed != 0 || targetUsed != p.Catalog.TotalBytes || reserved != 0 {
		t.Fatal("cutover capacity mismatch", sourceUsed, targetUsed, reserved)
	}
	if _, e = f.repo.ControlMigration(ctx, p.ID, "cancel", store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	for _, o := range f.objects {
		g, e := f.db.Pool().Resource(ctx, o.MediaID)
		if e != nil || g.MemberID != f.target {
			t.Fatal("cancel reversed committed ownership", g, e)
		}
	}
	if e = f.db.Nodes().RevokeRelationship(ctx, f.rel, false, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("cleanup pending source retired", e)
	}
}

func TestResourceMigrationChangedSourceOrPausedRunnerCannotCommit(t *testing.T) {
	f := migrationDatabase(t)
	ctx := context.Background()
	p := f.plan(t, hashPath(t.Name())[:32])
	if _, e := f.repo.StartMigration(ctx, p, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	l, e := f.repo.ClaimMigration(ctx, p.ID, strings.Repeat("e", 32), time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	w, e := f.repo.MigrationWork(ctx, p.ID)
	if e != nil {
		t.Fatal(e)
	}
	for _, o := range w.Objects {
		if e = f.repo.VerifyMigrationObject(ctx, l, o.Object.ID, o.Object.Bytes, o.SourceSHA); e != nil {
			t.Fatal(e)
		}
	}
	if e = f.repo.PrepareMigrationPublication(ctx, l, w.Units[0].ID); e != nil {
		t.Fatal(e)
	}
	for _, o := range w.Objects {
		if e = f.repo.PublishMigrationObject(ctx, l, o.Object.ID); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = f.raw.Exec("UPDATE global_media_objects SET etag='changed' WHERE media_id=?", f.objects[0].MediaID); e != nil {
		t.Fatal(e)
	}
	if e = f.repo.CommitMigrationUnit(ctx, l, w.Units[0].ID, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("changed source committed", e)
	}
	if _, e = f.repo.ControlMigration(ctx, p.ID, "pause", store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e = f.repo.CommitMigrationUnit(ctx, l, w.Units[0].ID, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationLease) {
		t.Fatal("paused runner committed", e)
	}
}
