package business_test

import (
	"context"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"strings"
	"testing"
)

func TestResourceMigrationPagedPlanRechecksMetadataBeforeAdmission(t *testing.T) {
	f := migrationDatabase(t)
	ctx := context.Background()
	plans := f.repo.(store.MigrationPlanRepository)
	id := hashPath(t.Name())[:32]
	t.Cleanup(func() {
		for _, table := range []string{"migration_plan_bindings", "migration_plan_paths", "migration_plan_headers"} {
			f.raw.Exec("DELETE FROM "+table+" WHERE plan_id=?", id)
		}
	})
	p, e := plans.BuildMigrationPlan(ctx, id, f.source, f.target)
	if e != nil {
		t.Fatal(e)
	}
	objects, e := plans.MigrationPlanPage(ctx, id, "")
	if e != nil {
		t.Fatal(e)
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
		if e = plans.ObserveMigrationPlanNative(ctx, id, o.Resource, item); !errors.Is(e, store.ErrMigrationState) {
			t.Fatal("duplicate native page accepted", e)
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
	if _, e = f.raw.Exec("UPDATE global_media_objects SET etag='changed-after-review' WHERE media_id=?", objects[0].ID); e != nil {
		t.Fatal(e)
	}
	if _, e = f.repo.StartMigration(ctx, p, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("changed source metadata admitted", e)
	}
	var tasks, reserved int64
	if e = f.raw.QueryRow("SELECT COUNT(*) FROM migration_tasks WHERE task_id=?", id).Scan(&tasks); e != nil {
		t.Fatal(e)
	}
	if e = f.raw.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", f.target).Scan(&reserved); e != nil {
		t.Fatal(e)
	}
	if tasks != 0 || reserved != 0 {
		t.Fatal("stale plan wrote authority facts", tasks, reserved)
	}
}
