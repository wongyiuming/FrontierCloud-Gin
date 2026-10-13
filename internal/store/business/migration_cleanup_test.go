package business_test

import (
	"context"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"strings"
	"testing"
	"time"
)

func TestResourceMigrationCleanupRequiresFreshTargetOwnerGraceAndReadDrain(t *testing.T) {
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
	o := w.Objects[0]
	proof := store.MigrationCleanupProof{MigrationDiskProof: store.MigrationDiskProof{ID: o.Object.ID, Version: o.Object.Version, Bytes: o.Object.Bytes, SHA256: o.SourceSHA}, VerifiedAt: time.Now().Unix()}
	checkBlocked := func() {
		t.Helper()
		if _, e := f.repo.AuthorizeMigrationCleanup(ctx, l, o.Object.ID, proof); !errors.Is(e, store.ErrMigrationState) {
			t.Fatal("unsafe cleanup authorized", e)
		}
	}
	checkBlocked()
	for _, c := range w.Objects {
		if e = f.repo.VerifyMigrationObject(ctx, l, c.Object.ID, c.Object.Bytes, c.SourceSHA); e != nil {
			t.Fatal(e)
		}
	}
	unit := w.Units[0].ID
	if e = f.repo.PrepareMigrationPublication(ctx, l, unit); e != nil {
		t.Fatal(e)
	}
	for _, c := range w.Objects {
		if e = f.repo.PublishMigrationObject(ctx, l, c.Object.ID); e != nil {
			t.Fatal(e)
		}
	}
	if e = f.repo.CommitMigrationUnit(ctx, l, unit, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	checkBlocked() // The one-hour capability grace has not elapsed.
	now := time.Now().Unix()
	if _, e = f.raw.Exec("UPDATE migration_units SET committed_at=?,cleanup_after=? WHERE task_id=?", now-3601, now-1, p.ID); e != nil {
		t.Fatal(e)
	}
	proof.VerifiedAt = now - 31
	checkBlocked()
	proof.VerifiedAt = now
	if _, e = f.raw.Exec("INSERT INTO migration_read_leases(lease_id,member_id,logical_id,object_id,source_version,expires_at) VALUES (?,?,?,?,?,?)", strings.Repeat("d", 32), f.source, "different-logical-alias", o.Object.ObjectID, o.Object.Version, now+60); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.raw.Exec("DELETE FROM migration_read_leases WHERE lease_id=?", strings.Repeat("d", 32)) })
	checkBlocked()
	if _, e = f.raw.Exec("UPDATE migration_read_leases SET expires_at=? WHERE lease_id=?", now-1, strings.Repeat("d", 32)); e != nil {
		t.Fatal(e)
	}
	grant, e := f.repo.AuthorizeMigrationCleanup(ctx, l, o.Object.ID, proof)
	if e != nil || grant.Object.ID != o.Object.ID || grant.SourceID != f.source || grant.TargetID != f.target || grant.SHA256 != o.SourceSHA {
		t.Fatal(grant, e)
	}
	wrong := proof
	wrong.SHA256 = strings.Repeat("0", 64)
	if _, e = f.repo.AuthorizeMigrationCleanup(ctx, l, o.Object.ID, wrong); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("wrong target disk proof", e)
	}
	if _, e = f.raw.Exec("UPDATE global_media_objects SET storage_member_id=? WHERE media_id=?", f.source, o.Object.ID); e != nil {
		t.Fatal(e)
	}
	checkBlocked()
	var state string
	f.raw.QueryRow("SELECT state FROM migration_objects WHERE task_id=? AND logical_id=?", p.ID, o.Object.ID).Scan(&state)
	if state != "cleanup_pending" {
		t.Fatal("authorization altered cleanup facts", state)
	}
}
