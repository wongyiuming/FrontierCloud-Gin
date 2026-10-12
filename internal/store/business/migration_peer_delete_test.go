package business_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestPeerMigrationMediaDeleteJournalAndQuotaCommitTogether(t *testing.T) {
	db, raw, repo, rel, h, l, v := peerMigrationFixture(t, true)
	ctx := context.Background()
	if e := repo.RegisterPeerMigration(ctx, rel, h, l, "queued", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e := repo.RegisterPeerMigrationObject(ctx, rel, l, v, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	now := time.Now().Unix()
	g := store.MigrationCleanupGrant{TaskID: h.TaskID, MasterID: h.MasterID, SourceID: h.SourceID, TargetID: h.TargetID, PlanSHA: h.PlanSHA, UnitID: hashPath(v.Object.Resource + ":" + v.Object.Parent), UnitVersion: hashPath("delete-unit"), Object: v.Object, SHA256: v.Proof.SHA256, CommittedAt: now - 3601, CleanupAfter: now - 1, TargetVerifiedAt: now}
	op := store.DeleteOperation{ID: strings.Repeat("f", 32), State: "pending", Items: []store.DeleteItem{{Path: v.Object.Path, Slot: "0", OwnedID: v.Object.ObjectID, Bytes: v.Object.Bytes, MigrationTask: l.TaskID, MigrationLogical: v.Object.ID}}}
	if e := db.Pool().PrepareOwnedDelete(ctx, rel, op, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("ordinary delete bypassed migration", e)
	}
	if e := repo.PreparePeerMediaDelete(ctx, rel, l, op, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("missing cleanup grant accepted", e)
	}
	if e := repo.PreparePeerMigrationCleanup(ctx, rel, l, g, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e := repo.PreparePeerMediaDelete(ctx, rel, l, op, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	for range 2 {
		if e := db.Pool().CommitOwnedDelete(ctx, op.ID, 20*store.GiB, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
	}
	var phase string
	var used int64
	if e := raw.QueryRow("SELECT state FROM migration_storage_journal WHERE task_id=? AND logical_id=?", l.TaskID, v.Object.ID).Scan(&phase); e != nil || phase != "deleted" {
		t.Fatal(phase, e)
	}
	if e := raw.QueryRow("SELECT used_bytes FROM cluster_storage_members WHERE member_id=?", h.SourceID).Scan(&used); e != nil || used != 0 {
		t.Fatal("source refund", used, e)
	}
	var detail string
	if e := raw.QueryRow("SELECT detail FROM node_audit WHERE action='storage-delete-committed'").Scan(&detail); e != nil {
		t.Fatal(e)
	}
	var audit map[string]any
	if e := json.Unmarshal([]byte(detail), &audit); e != nil || audit["task_id"] != l.TaskID || audit["logical_id"] != v.Object.ID {
		t.Fatal("committed audit lost task binding", detail, e)
	}
	if e := db.Media().ForgetDelete(ctx, op.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := repo.AuthorizePeerMigration(ctx, rel, l, v.Object.ID, "cleanup"); e != nil {
		t.Fatal("deleted receipt missing", e)
	}
}

func TestPeerMigrationPublishedShadowDeletionAdmissionCommitAndRecovery(t *testing.T) {
	db, raw, repo, rel, h, l, v := peerMigrationFixture(t, false)
	ctx := context.Background()
	if e := repo.RegisterPeerMigration(ctx, rel, h, l, "queued", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e := repo.RegisterPeerMigrationObject(ctx, rel, l, v, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e := repo.VerifyPeerMigrationObject(ctx, rel, l, v.Object.ID, v.Object.Bytes, v.Proof.SHA256); e != nil {
		t.Fatal(e)
	}
	if e := repo.CompletePeerMediaPublication(ctx, rel, l, v.Object.ID, store.MediaObject{ID: v.Object.ObjectID, Path: v.Object.TargetPath, Kind: v.Object.Kind}, v.Object.Bytes, v.Proof.SHA256, 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	l.Epoch++
	if e := repo.RegisterPeerMigration(ctx, rel, h, l, "cancelling", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	var unit string
	if e := raw.QueryRow("SELECT unit_id FROM migration_storage_journal WHERE task_id=?", h.TaskID).Scan(&unit); e != nil {
		t.Fatal(e)
	}
	sha, e := store.MigrationUnitObjectsSHA([]store.MigrationPeerObject{v})
	if e != nil {
		t.Fatal(e)
	}
	g := store.MigrationShadowGrant{Unit: store.MigrationUnitFinishGrant{Header: h, Unit: store.MigrationUnit{ID: unit, Resource: v.Object.Resource, Parent: v.Object.Parent, State: "cancelled", ObjectCount: 1, Bytes: v.Object.Bytes}, UnitVersion: hashPath("shadow-unit"), ObjectsSHA: sha}, Object: v.Object, SourceProof: store.MigrationCleanupProof{MigrationDiskProof: v.Proof, VerifiedAt: time.Now().Unix()}}
	op := store.DeleteOperation{ID: hashPath(t.Name() + "delete")[:32], State: "pending", Items: []store.DeleteItem{{Path: v.Object.TargetPath, Slot: "0", OwnedID: v.Object.ObjectID, Bytes: v.Object.Bytes, MigrationTask: l.TaskID, MigrationLogical: v.Object.ID}}}
	t.Cleanup(func() { raw.Exec("DELETE FROM media_delete_operations WHERE operation_id=?", op.ID) })
	if e := repo.PreparePeerMediaDelete(ctx, rel, l, op, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("no source proof admitted deletion", e)
	}
	for _, alter := range []func(*store.MigrationShadowGrant){func(g *store.MigrationShadowGrant) { g.SourceProof.VerifiedAt -= 31 }, func(g *store.MigrationShadowGrant) { g.Unit.Unit.CommittedAt = 1 }, func(g *store.MigrationShadowGrant) { g.Unit.ObjectsSHA = strings.Repeat("0", 64) }, func(g *store.MigrationShadowGrant) { g.Object.Path = "music/elsewhere.mp3" }} {
		wrong := g
		alter(&wrong)
		if e := repo.PreparePeerMigrationShadowDeletion(ctx, rel, l, wrong, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
			t.Fatal("wrong shadow grant", e)
		}
	}
	reads := db.Nodes().(store.MigrationReadRepository)
	read, e := reads.AcquireMigrationRead(ctx, rel, v.Object.ID, v.Object.ObjectID, "media")
	if e != nil {
		t.Fatal(e)
	}
	if e = repo.PreparePeerMigrationShadowDeletion(ctx, rel, l, g, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("live target read crossed deletion", e)
	}
	if e = reads.ReleaseMigrationRead(ctx, read); e != nil {
		t.Fatal(e)
	}
	for range 2 {
		if e = repo.PreparePeerMigrationShadowDeletion(ctx, rel, l, g, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
	}
	if e = repo.FailPeerMigrationShadowCleanup(ctx, rel, l, v.Object.ID, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if failed, e := repo.PeerMigrationShadowCleanupFailed(ctx, rel, l, v.Object.ID); e != nil || !failed {
		t.Fatal("shadow failure not durable", failed, e)
	}
	old := g
	old.SourceProof.VerifiedAt -= 31
	if e = repo.PreparePeerMigrationShadowDeletion(ctx, rel, l, old, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("stale proof cleared failed shadow", e)
	}
	if e = repo.PreparePeerMigrationShadowDeletion(ctx, rel, l, g, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if failed, e := repo.PeerMigrationShadowCleanupFailed(ctx, rel, l, v.Object.ID); e != nil || failed {
		t.Fatal("fresh retry kept failure", failed, e)
	}
	if _, e = reads.AcquireMigrationRead(ctx, rel, v.Object.ID, v.Object.ObjectID, "media"); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("new target read after delete fence", e)
	}
	if e = db.Pool().PrepareOwnedDelete(ctx, rel, op, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("ordinary delete bypass", e)
	}
	if e = repo.PreparePeerMediaDelete(ctx, rel, l, op, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	check := func(want int64, phase string) {
		t.Helper()
		var used, reserved int64
		var actual string
		if e := raw.QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", h.TargetID).Scan(&used, &reserved); e != nil {
			t.Fatal(e)
		}
		if e := raw.QueryRow("SELECT state FROM migration_storage_journal WHERE task_id=? AND logical_id=?", h.TaskID, v.Object.ID).Scan(&actual); e != nil {
			t.Fatal(e)
		}
		if used != want || reserved != 0 || actual != phase {
			t.Fatal(used, reserved, actual)
		}
	}
	check(v.Object.Bytes, "deleting")
	trigger := "CREATE TRIGGER block_shadow_refund BEFORE UPDATE ON cluster_storage_members BEGIN SELECT RAISE(ABORT,'refund unavailable'); END"
	if db.Backend() == "mysql" {
		trigger = "CREATE TRIGGER block_shadow_refund BEFORE UPDATE ON cluster_storage_members FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='refund unavailable'"
	}
	if _, e = raw.Exec(trigger); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { raw.Exec("DROP TRIGGER IF EXISTS block_shadow_refund") })
	if e = db.Pool().CommitOwnedDelete(ctx, op.ID, 20*store.GiB, store.NodeAudit{}); e == nil {
		t.Fatal("refund fault ignored")
	}
	check(v.Object.Bytes, "deleting")
	if found, e := db.Media().ObjectByID(ctx, v.Object.ObjectID); e != nil || found == nil {
		t.Fatal("failed refund removed metadata", found, e)
	}
	if _, e = raw.Exec("DROP TRIGGER block_shadow_refund"); e != nil {
		t.Fatal(e)
	}
	// Prepared managed transactions recover without reviving an expired actor.
	if _, e = raw.Exec("UPDATE migration_runners SET expires_at=0 WHERE task_id=?", h.TaskID); e != nil {
		t.Fatal(e)
	}
	for range 2 {
		if e = db.Pool().CommitOwnedDelete(ctx, op.ID, 20*store.GiB, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
	}
	check(0, "deleted")
	if found, e := db.Media().ObjectByID(ctx, v.Object.ObjectID); e != nil || found != nil {
		t.Fatal("deleted shadow retained metadata", found, e)
	}
	if e = db.Media().ForgetDelete(ctx, op.ID); e != nil {
		t.Fatal(e)
	}

	l.Epoch++
	if e = repo.RegisterPeerMigration(ctx, rel, h, l, "cancelling", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e = repo.FailPeerMigrationShadowCleanup(ctx, rel, l, v.Object.ID, store.NodeAudit{}); e != nil {
		t.Fatal("post-delete private failure", e)
	}
	if failed, e := repo.PeerMigrationShadowCleanupFailed(ctx, rel, l, v.Object.ID); e != nil || !failed {
		t.Fatal(failed, e)
	}
	if e = repo.PreparePeerMigrationShadowDeletion(ctx, rel, l, g, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	for range 2 {
		receipt, e := repo.CompletePeerMigrationUnitCancellation(ctx, rel, l, g.Unit, store.NodeAudit{})
		if e != nil || !receipt.Complete {
			t.Fatal("deleted-shadow unit refund replay", receipt, e)
		}
	}
}
