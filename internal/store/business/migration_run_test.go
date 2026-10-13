package business_test

import (
	"context"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"strings"
	"testing"
	"time"
)

func TestResourceMigrationRunnerSchedulingFailureAndEpochFence(t *testing.T) {
	f := migrationDatabase(t)
	ctx := context.Background()
	plan := f.plan(t, strings.Repeat("f", 32))
	if _, e := f.repo.StartMigration(ctx, plan, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if id, e := f.repo.NextMigrationRun(ctx); e != nil || id != plan.ID {
		t.Fatal(id, e)
	}
	l, e := f.repo.ClaimMigration(ctx, plan.ID, strings.Repeat("a", 32), time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if id, e := f.repo.NextMigrationRun(ctx); e != nil || id != "" {
		t.Fatal("active runner scheduled twice", id, e)
	}
	if e = f.repo.MigrationRunState(ctx, l, "copying", f.objects[0].MediaID, "", store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e = f.repo.ControlMigration(ctx, plan.ID, "pause", store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e = f.repo.ControlMigration(ctx, plan.ID, "resume", store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e = f.repo.ValidateMigrationLease(ctx, l); !errors.Is(e, store.ErrMigrationLease) {
		t.Fatal("pause/resume restored old executor", e)
	}
	next, e := f.repo.ClaimMigration(ctx, plan.ID, strings.Repeat("b", 32), time.Minute)
	if e != nil || next.Epoch <= l.Epoch {
		t.Fatal(next, e)
	}
	if e = f.repo.MigrationRunState(ctx, next, "failed", f.objects[0].MediaID, "peer_transport", store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	task, e := f.repo.MigrationTask(ctx, plan.ID)
	if e != nil || task.State != "failed" || task.ErrorCode != "peer_transport" {
		t.Fatal(task, e)
	}
	if id, e := f.repo.NextMigrationRun(ctx); e != nil || id != "" {
		t.Fatal("failed task retried without operator control", id, e)
	}
	if _, e = f.repo.ControlMigration(ctx, plan.ID, "retry", store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if id, e := f.repo.NextMigrationRun(ctx); e != nil || id != plan.ID {
		t.Fatal(id, e)
	}
}
