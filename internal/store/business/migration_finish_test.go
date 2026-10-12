package business_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestResourceMigrationUnitCleanupRequiresBothBoundReceiptsAndRetainsDrain(t *testing.T) {
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
	u := w.Units[0]
	if _, e = f.repo.MigrationUnitFinishGrant(ctx, l, u.ID); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("unfinished unit admitted", e)
	}
	for _, cp := range w.Objects {
		if e = f.repo.VerifyMigrationObject(ctx, l, cp.Object.ID, cp.Object.Bytes, cp.SourceSHA); e != nil {
			t.Fatal(e)
		}
	}
	if e = f.repo.PrepareMigrationPublication(ctx, l, u.ID); e != nil {
		t.Fatal(e)
	}
	for _, cp := range w.Objects {
		if e = f.repo.PublishMigrationObject(ctx, l, cp.Object.ID); e != nil {
			t.Fatal(e)
		}
	}
	if e = f.repo.CommitMigrationUnit(ctx, l, u.ID, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	now := time.Now().Unix()
	if _, e = f.raw.Exec("UPDATE migration_units SET committed_at=?,cleanup_after=? WHERE task_id=?", now-3601, now-1, p.ID); e != nil {
		t.Fatal(e)
	}
	for _, cp := range w.Objects {
		receipt := store.MigrationSourceReceipt{TaskID: p.ID, SourceID: f.source, TargetID: f.target, PlanSHA: w.Task.PlanSHA, Proof: store.MigrationDiskProof{ID: cp.Object.ID, Version: cp.Object.Version, Bytes: cp.Object.Bytes, SHA256: cp.SourceSHA}, ManagedCopyDeleted: true}
		if e = f.repo.RecordMigrationSourceDeletion(ctx, l, receipt, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
	}
	g, e := f.repo.MigrationUnitFinishGrant(ctx, l, u.ID)
	if e != nil {
		t.Fatal(e)
	}
	source := store.MigrationUnitFinishReceipt{Grant: g, MemberID: f.source, Complete: true}
	target := store.MigrationUnitFinishReceipt{Grant: g, MemberID: f.target, Complete: true}
	wrong := target
	wrong.Complete = false
	if e = f.repo.CompleteMigrationUnitCleanup(ctx, l, source, wrong, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("one-sided completion released unit", e)
	}
	wrong = target
	wrong.Grant.ObjectsSHA = strings.Repeat("0", 64)
	if e = f.repo.CompleteMigrationUnitCleanup(ctx, l, source, wrong, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("wrong roster receipt accepted", e)
	}
	for range 2 {
		if e = f.repo.CompleteMigrationUnitCleanup(ctx, l, source, target, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
	}
	var scopes, drains, audits int
	if e = f.raw.QueryRow("SELECT COUNT(*) FROM migration_scopes WHERE task_id=?", p.ID).Scan(&scopes); e != nil || scopes != 0 {
		t.Fatal(scopes, e)
	}
	if e = f.raw.QueryRow("SELECT COUNT(*) FROM migration_drains WHERE owner_id=?", p.ID).Scan(&drains); e != nil || drains != 1 {
		t.Fatal("implicit drain release", drains, e)
	}
	if e = f.raw.QueryRow("SELECT COUNT(*) FROM node_audit WHERE action='resource-migration-unit-cleaned' AND detail LIKE ?", "%"+p.ID+"%").Scan(&audits); e != nil || audits != 1 {
		t.Fatal("completion replay repeated audit", audits, e)
	}
	if e = f.repo.ReleaseMigrationDrain(ctx, p.ID, f.source, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("unit receipt completed whole task", e)
	}
}
