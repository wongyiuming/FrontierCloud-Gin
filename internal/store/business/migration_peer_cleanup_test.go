package business_test

import (
	"context"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"testing"
	"time"
)

func TestPeerMigrationCleanupGrantIsSourceOnlyBoundAndDoesNotRefund(t *testing.T) {
	_, raw, repo, rel, h, l, v := peerMigrationFixture(t, true)
	ctx := context.Background()
	if e := repo.RegisterPeerMigration(ctx, rel, h, l, "queued", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e := repo.RegisterPeerMigrationObject(ctx, rel, l, v, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	now := time.Now().Unix()
	g := store.MigrationCleanupGrant{TaskID: h.TaskID, MasterID: h.MasterID, SourceID: h.SourceID, TargetID: h.TargetID, PlanSHA: h.PlanSHA, UnitID: hashPath(v.Object.Resource + ":" + v.Object.Parent), UnitVersion: hashPath("unit-source-version"), Object: v.Object, SHA256: v.Proof.SHA256, CommittedAt: now - 3601, CleanupAfter: now - 1, TargetVerifiedAt: now}
	wrong := g
	wrong.CleanupAfter = now + 1
	if e := repo.PreparePeerMigrationCleanup(ctx, rel, l, wrong, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("early source cleanup", e)
	}
	wrong = g
	wrong.Object.Version = "wrong"
	if e := repo.PreparePeerMigrationCleanup(ctx, rel, l, wrong, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("wrong object cleanup", e)
	}
	for range 2 {
		if e := repo.PreparePeerMigrationCleanup(ctx, rel, l, g, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
	}
	if e := repo.FailPeerMigrationCleanup(ctx, rel, l, g.Object.ID, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if failed, e := repo.PeerMigrationCleanupFailed(ctx, rel, l, g.Object.ID); e != nil || !failed {
		t.Fatal("peer failure checkpoint missing", failed, e)
	}
	if e := repo.PreparePeerMigrationCleanup(ctx, rel, l, g, store.NodeAudit{}); e != nil {
		t.Fatal("explicit retry grant rejected", e)
	}
	if failed, e := repo.PeerMigrationCleanupFailed(ctx, rel, l, g.Object.ID); e != nil || failed {
		t.Fatal("failure checkpoint not cleared by retry", failed, e)
	}
	var phase string
	var used int64
	if e := raw.QueryRow("SELECT state FROM migration_storage_journal WHERE task_id=? AND logical_id=?", h.TaskID, v.Object.ID).Scan(&phase); e != nil || phase != "deleting" {
		t.Fatal(phase, e)
	}
	if e := raw.QueryRow("SELECT used_bytes FROM cluster_storage_members WHERE member_id=?", h.SourceID).Scan(&used); e != nil || used != v.Object.Bytes {
		t.Fatal("authorization refunded source before physical deletion", used, e)
	}
	if _, e := repo.AuthorizePeerMigration(ctx, rel, l, v.Object.ID, "read"); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("new migration read admitted after cleanup authorization", e)
	}
	wrong = g
	wrong.CommittedAt--
	if e := repo.PreparePeerMigrationCleanup(ctx, rel, l, wrong, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("cleanup timestamps changed on replay", e)
	}
}
