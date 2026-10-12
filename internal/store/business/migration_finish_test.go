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
	taskGrant, e := f.repo.MigrationTaskFinishGrant(ctx, l)
	if e != nil {
		t.Fatal(e)
	}
	sourceTask := store.MigrationTaskFinishReceipt{Grant: taskGrant, MemberID: f.source, Complete: true}
	targetTask := store.MigrationTaskFinishReceipt{Grant: taskGrant, MemberID: f.target, Complete: true}
	wrongTask := targetTask
	wrongTask.Complete = false
	if e = f.repo.CompleteMigrationTask(ctx, l, sourceTask, wrongTask, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("one-sided task completion", e)
	}
	wrongTask = targetTask
	wrongTask.Grant.UnitsSHA = strings.Repeat("0", 64)
	if e = f.repo.CompleteMigrationTask(ctx, l, sourceTask, wrongTask, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("wrong task roster", e)
	}
	if e = f.repo.CompleteMigrationTask(ctx, l, sourceTask, targetTask, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	task, e := f.repo.MigrationTask(ctx, p.ID)
	if e != nil || task.State != "completed" {
		t.Fatal(task, e)
	}
	var capacity int
	if e = f.raw.QueryRow("SELECT COUNT(*) FROM migration_capacity WHERE task_id=?", p.ID).Scan(&capacity); e != nil || capacity != 0 {
		t.Fatal("zero reservation tombstone not retired", capacity, e)
	}
	if e = f.raw.QueryRow("SELECT COUNT(*) FROM migration_drains WHERE owner_id=?", p.ID).Scan(&drains); e != nil || drains != 1 {
		t.Fatal("task completion released drain", drains, e)
	}
	if e = f.repo.ReleaseMigrationDrain(ctx, p.ID, f.target, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("wrong source confirmation", e)
	}
	for range 2 {
		if e = f.repo.ReleaseMigrationDrain(ctx, p.ID, f.source, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
	}
}

func TestResourceMigrationUnitCancellationKeepsSourceAndRefundsOnce(t *testing.T) {
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
	if _, e = f.repo.MigrationUnitCancelGrant(ctx, l, u.ID); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("cancel before control", e)
	}
	if _, e = f.repo.ControlMigration(ctx, p.ID, "cancel", store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e = f.repo.MigrationUnitCancelGrant(ctx, l, u.ID); !errors.Is(e, store.ErrMigrationLease) {
		t.Fatal("old runner not fenced", e)
	}
	l, e = f.repo.ClaimMigration(ctx, p.ID, strings.Repeat("f", 32), time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	g, e := f.repo.MigrationUnitCancelGrant(ctx, l, u.ID)
	if e != nil {
		t.Fatal(e)
	}
	source := store.MigrationUnitFinishReceipt{Grant: g, MemberID: f.source, Complete: true}
	target := store.MigrationUnitFinishReceipt{Grant: g, MemberID: f.target, Complete: true}
	wrong := target
	wrong.Grant.Unit.State = "cleanup_pending"
	if e = f.repo.CompleteMigrationUnitCancellation(ctx, l, source, wrong, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("wrong receipt", e)
	}
	for range 2 {
		if e = f.repo.CompleteMigrationUnitCancellation(ctx, l, source, target, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
	}
	var reserved, drains, scopes int64
	if e = f.raw.QueryRow("SELECT reserved_bytes FROM migration_capacity WHERE task_id=?", p.ID).Scan(&reserved); e != nil {
		t.Fatal(e)
	}
	if e = f.raw.QueryRow("SELECT COUNT(*) FROM migration_drains WHERE owner_id=?", p.ID).Scan(&drains); e != nil {
		t.Fatal(e)
	}
	if e = f.raw.QueryRow("SELECT COUNT(*) FROM migration_scopes WHERE task_id=? AND resource_kind=? AND parent_path=?", p.ID, u.Resource, u.Parent).Scan(&scopes); e != nil {
		t.Fatal(e)
	}
	if reserved != w.Task.TotalBytes-u.Bytes || drains != 1 || scopes != 0 {
		t.Fatal(reserved, drains, scopes)
	}
	after, e := f.repo.MigrationWork(ctx, p.ID)
	if e != nil {
		t.Fatal(e)
	}
	if after.Task.State != "cancelling" || after.Task.CommittedBytes != 0 {
		t.Fatal(after.Task)
	}
	for _, cp := range after.Objects {
		if cp.UnitID != u.ID {
			continue
		}
		if cp.State != "cancelled" {
			t.Fatal(cp.State)
		}
		var owner string
		if e = f.raw.QueryRow("SELECT storage_member_id FROM global_media_objects WHERE media_id=?", cp.Object.ID).Scan(&owner); e != nil {
			t.Fatal(e)
		}
		if owner != f.source {
			t.Fatal("source authority changed", owner)
		}
	}
	// A committed unit cannot be given a cancellation grant even in cancelling.
	if _, e = f.raw.Exec("UPDATE migration_units SET committed_at=1,state='cleanup_pending' WHERE task_id=? AND unit_id=?", p.ID, u.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = f.repo.MigrationUnitCancelGrant(ctx, l, u.ID); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("committed unit reversal", e)
	}
	if _, e = f.repo.MigrationTaskCancelGrant(ctx, l); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("unfinished task finalized", e)
	}
	if _, e = f.raw.Exec("UPDATE migration_units SET committed_at=0,state='cancelled' WHERE task_id=? AND unit_id=?", p.ID, u.ID); e != nil {
		t.Fatal(e)
	}
	for _, unit := range w.Units {
		if unit.ID == u.ID {
			continue
		}
		grant, e := f.repo.MigrationUnitCancelGrant(ctx, l, unit.ID)
		if e != nil {
			t.Fatal(e)
		}
		if e = f.repo.CompleteMigrationUnitCancellation(ctx, l, store.MigrationUnitFinishReceipt{Grant: grant, MemberID: f.source, Complete: true}, store.MigrationUnitFinishReceipt{Grant: grant, MemberID: f.target, Complete: true}, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
	}
	final, e := f.repo.MigrationTaskCancelGrant(ctx, l)
	if e != nil || final.Outcome != "cancelled" {
		t.Fatal(final, e)
	}
	finalSource := store.MigrationTaskFinishReceipt{Grant: final, MemberID: f.source, Complete: true}
	finalTarget := store.MigrationTaskFinishReceipt{Grant: final, MemberID: f.target, Complete: true}
	wrongFinal := finalTarget
	wrongFinal.Grant.Outcome = "completed"
	if e = f.repo.CompleteMigrationTaskCancellation(ctx, l, finalSource, wrongFinal, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("wrong terminal outcome", e)
	}
	if e = f.repo.CompleteMigrationTaskCancellation(ctx, l, finalSource, finalTarget, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	terminal, e := f.repo.MigrationTask(ctx, p.ID)
	if e != nil || terminal.State != "cancelled" || terminal.CommittedBytes != 0 {
		t.Fatal(terminal, e)
	}
	if e = f.raw.QueryRow("SELECT COUNT(*) FROM migration_drains WHERE owner_id=?", p.ID).Scan(&drains); e != nil || drains != 1 {
		t.Fatal("cancel released drain implicitly", drains, e)
	}
	if e = f.repo.ReleaseMigrationDrain(ctx, p.ID, f.source, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
}

func TestResourceMigrationCommittedCancellationStillRequiresCleanupReceipts(t *testing.T) {
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
	for _, cp := range w.Objects {
		if e = f.repo.VerifyMigrationObject(ctx, l, cp.Object.ID, cp.Object.Bytes, cp.SourceSHA); e != nil {
			t.Fatal(e)
		}
	}
	for _, unit := range w.Units {
		if e = f.repo.PrepareMigrationPublication(ctx, l, unit.ID); e != nil {
			t.Fatal(e)
		}
		for _, cp := range w.Objects {
			if cp.UnitID == unit.ID {
				if e = f.repo.PublishMigrationObject(ctx, l, cp.Object.ID); e != nil {
					t.Fatal(e)
				}
			}
		}
		if e = f.repo.CommitMigrationUnit(ctx, l, unit.ID, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = f.repo.ControlMigration(ctx, p.ID, "cancel", store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if id, e := f.repo.NextMigrationRun(ctx); e != nil || id != "" {
		t.Fatal("cancel grace scheduled early", id, e)
	}
	now := time.Now().Unix()
	if _, e = f.raw.Exec("UPDATE migration_units SET committed_at=?,cleanup_after=? WHERE task_id=?", now-3601, now-1, p.ID); e != nil {
		t.Fatal(e)
	}
	if id, e := f.repo.NextMigrationRun(ctx); e != nil || id != p.ID {
		t.Fatal("due cancel cleanup not selected", id, e)
	}
	l, e = f.repo.ClaimMigration(ctx, p.ID, strings.Repeat("f", 32), time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	for _, cp := range w.Objects {
		proof := store.MigrationCleanupProof{MigrationDiskProof: store.MigrationDiskProof{ID: cp.Object.ID, Version: cp.Object.Version, Bytes: cp.Object.Bytes, SHA256: cp.SourceSHA}, VerifiedAt: time.Now().Unix()}
		if _, e = f.repo.AuthorizeMigrationCleanup(ctx, l, cp.Object.ID, proof); e != nil {
			t.Fatal(e)
		}
		receipt := store.MigrationSourceReceipt{TaskID: p.ID, SourceID: f.source, TargetID: f.target, PlanSHA: w.Task.PlanSHA, Proof: proof.MigrationDiskProof, ManagedCopyDeleted: true}
		if e = f.repo.RecordMigrationSourceDeletion(ctx, l, receipt, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
		if _, e = f.repo.AuthorizeMigrationAnchorRetirement(ctx, l, cp.Object.ID, proof); e != nil {
			t.Fatal(e)
		}
	}
	for _, unit := range w.Units {
		g, e := f.repo.MigrationUnitFinishGrant(ctx, l, unit.ID)
		if e != nil {
			t.Fatal(e)
		}
		if e = f.repo.CompleteMigrationUnitCleanup(ctx, l, store.MigrationUnitFinishReceipt{Grant: g, MemberID: f.source, Complete: true}, store.MigrationUnitFinishReceipt{Grant: g, MemberID: f.target, Complete: true}, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
	}
	g, e := f.repo.MigrationTaskCancelGrant(ctx, l)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.repo.CompleteMigrationTaskCancellation(ctx, l, store.MigrationTaskFinishReceipt{Grant: g, MemberID: f.source, Complete: true}, store.MigrationTaskFinishReceipt{Grant: g, MemberID: f.target, Complete: true}, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	terminal, e := f.repo.MigrationTask(ctx, p.ID)
	if e != nil || terminal.State != "cancelled" || terminal.CommittedBytes != terminal.TotalBytes {
		t.Fatal(terminal, e)
	}
	for _, cp := range w.Objects {
		var owner string
		if e = f.raw.QueryRow("SELECT storage_member_id FROM global_media_objects WHERE media_id=?", cp.Object.ID).Scan(&owner); e != nil || owner != f.target {
			t.Fatal("cancel reversed committed owner", owner, e)
		}
	}
}
