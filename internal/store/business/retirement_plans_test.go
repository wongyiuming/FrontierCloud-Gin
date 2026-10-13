package business_test

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"strings"
	"testing"
)

func TestPeerRetirementReconcilesPagedPlanHistoryWithoutBlockingPreviewCaches(t *testing.T) {
	f := migrationDatabase(t)
	ctx := context.Background()
	plans := f.repo.(store.MigrationPlanRepository)
	retire := f.db.Pool().(store.RetirementRepository)
	id, orphan := hashPath(t.Name())[:32], hashPath(t.Name() + "orphan")[:32]
	t.Cleanup(func() {
		for _, table := range []string{"migration_plan_bindings", "migration_plan_paths", "migration_plan_headers"} {
			f.raw.Exec("DELETE FROM "+table+" WHERE plan_id IN (?,?)", id, orphan)
		}
	})
	expect := func(code string, want bool) {
		t.Helper()
		ledger, e := retire.RetirementLedger(ctx, f.rel, f.source)
		if e != nil {
			t.Fatal(e)
		}
		found := false
		for _, b := range ledger.Blockers {
			if b.Code == code {
				found = true
				if b.Count < 1 || len(b.SampleIDs) > 8 {
					t.Fatal(b)
				}
			}
		}
		if found != want {
			t.Fatal(code, want, ledger.Blockers)
		}
	}
	p, e := plans.BuildMigrationPlan(ctx, id, f.source, f.target)
	if e != nil {
		t.Fatal(e)
	}
	expect("migration_plan_history_mismatch", false)
	expect("migration_plan_header_orphans", false)
	objects, e := plans.MigrationPlanPage(ctx, id, "")
	if e != nil || len(objects) != 3 {
		t.Fatal(objects, e)
	}
	for _, o := range objects {
		metadata, e := store.MigrationDigest(store.MediaObject{ID: o.ObjectID, Path: o.Path, Kind: o.Kind, Encryption: o.Encryption})
		if e != nil {
			t.Fatal(e)
		}
		item := store.ExpectedPhysicalItem{ObjectID: o.ObjectID, Path: "media/" + o.Path, MetadataSHA256: metadata, ExpectedBytes: &o.Bytes}
		if e = plans.ObserveMigrationPlanNative(ctx, id, o.Resource, item); e != nil {
			t.Fatal(e)
		}
		if e = plans.ObserveMigrationPlanProof(ctx, id, store.MigrationDiskProof{ID: o.ID, Version: o.Version, Bytes: o.Bytes, SHA256: strings.Trim(o.ETag, `"`)}); e != nil {
			t.Fatal(e)
		}
	}
	p.TargetAbsent = true
	p.TargetFree = 20 * store.GiB
	p, e = plans.SealMigrationPlan(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	expect("migration_plan_header_orphans", false)
	if _, e = f.repo.StartMigration(ctx, p, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	expect("migration_plan_history_mismatch", false)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, e := f.raw.Exec(query, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec("UPDATE migration_plan_headers SET state='ready' WHERE plan_id=?", id)
	expect("migration_plan_header_orphans", true)
	expect("migration_plan_history_mismatch", true)
	exec("UPDATE migration_plan_headers SET state='admitted' WHERE plan_id=?", id)
	exec("UPDATE migration_plan_bindings SET native_seen=0 WHERE plan_id=? AND logical_id=?", id, objects[0].ID)
	expect("migration_plan_history_mismatch", true)
	exec("UPDATE migration_plan_bindings SET native_seen=1 WHERE plan_id=? AND logical_id=?", id, objects[0].ID)
	exec("UPDATE migration_plan_bindings SET source_sha256=? WHERE plan_id=? AND logical_id=?", strings.Repeat("0", 64), id, objects[0].ID)
	expect("migration_plan_history_mismatch", true)
	exec("UPDATE migration_plan_bindings SET source_sha256=? WHERE plan_id=? AND logical_id=?", strings.Trim(objects[0].ETag, `"`), id, objects[0].ID)
	exec("UPDATE migration_plan_headers SET object_count=object_count+1 WHERE plan_id=?", id)
	expect("migration_plan_history_mismatch", true)
	exec("UPDATE migration_plan_headers SET object_count=object_count-1 WHERE plan_id=?", id)
	exec("UPDATE migration_objects SET source_version=? WHERE task_id=? AND logical_id=?", strings.Repeat("0", 64), id, objects[0].ID)
	expect("migration_plan_history_mismatch", true)
	exec("UPDATE migration_objects SET source_version=? WHERE task_id=? AND logical_id=?", objects[0].Version, id, objects[0].ID)
	exec("UPDATE migration_plan_headers SET plan_id=? WHERE plan_id=?", orphan, id)
	expect("migration_plan_header_orphans", true)
	expect("migration_plan_binding_orphans", true)
	expect("migration_plan_path_orphans", true)
	expect("migration_plan_history_mismatch", true)
	exec("UPDATE migration_plan_headers SET plan_id=? WHERE plan_id=?", id, orphan)
	expect("migration_plan_history_mismatch", false)
	// A terminal label is insufficient until object checkpoints reconcile. These
	// fixture SQL changes exercise the independent ledger, not task authorization.
	exec("UPDATE migration_tasks SET state='cancelled' WHERE task_id=?", id)
	expect("migration_plan_history_mismatch", true)
	exec("UPDATE migration_objects SET state='cancelled' WHERE task_id=?", id)
	exec("UPDATE migration_units SET state='cancelled' WHERE task_id=?", id)
	expect("migration_plan_history_mismatch", false)
	var retained int
	if e = f.raw.QueryRow("SELECT COUNT(*) FROM migration_plan_bindings WHERE plan_id=?", id).Scan(&retained); e != nil || retained != 3 {
		t.Fatal("retirement check removed audit bindings", retained, e)
	}
}
