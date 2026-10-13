package business_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestPeerMigrationAnchorGrantRequiresPublishedTargetAndSourceReceipt(t *testing.T) {
	_, _, repo, rel, h, l, v := peerMigrationFixture(t, false)
	ctx := context.Background()
	if e := repo.RegisterPeerMigration(ctx, rel, h, l, "queued", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e := repo.RegisterPeerMigrationObject(ctx, rel, l, v, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	now := time.Now().Unix()
	g := store.MigrationCleanupGrant{SourceCopyDeleted: true, TaskID: h.TaskID, MasterID: h.MasterID, SourceID: h.SourceID, TargetID: h.TargetID, PlanSHA: h.PlanSHA, UnitID: hashPath(v.Object.Resource + ":" + v.Object.Parent), UnitVersion: hashPath("anchor-unit"), Object: v.Object, SHA256: v.Proof.SHA256, CommittedAt: now - 3601, CleanupAfter: now - 1, TargetVerifiedAt: now}
	if e := repo.ValidatePeerAnchorRetirement(ctx, rel, l, g, true); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("unpublished target anchor admitted", e)
	}
	if e := repo.VerifyPeerMigrationObject(ctx, rel, l, v.Object.ID, v.Object.Bytes, v.Proof.SHA256); e != nil {
		t.Fatal(e)
	}
	if e := repo.CompletePeerMediaPublication(ctx, rel, l, v.Object.ID, store.MediaObject{ID: v.Object.ObjectID, Path: v.Object.TargetPath, Kind: v.Object.Kind}, v.Object.Bytes, v.Proof.SHA256, 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	wrong := g
	wrong.SourceCopyDeleted = false
	if e := repo.ValidatePeerAnchorRetirement(ctx, rel, l, wrong, true); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("missing source deletion receipt admitted", e)
	}
	wrong = g
	wrong.TargetVerifiedAt = now - 31
	if e := repo.ValidatePeerAnchorRetirement(ctx, rel, l, wrong, true); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("stale initial grant admitted", e)
	}
	if e := repo.ValidatePeerAnchorRetirement(ctx, rel, l, g, true); e != nil {
		t.Fatal(e)
	}
}
