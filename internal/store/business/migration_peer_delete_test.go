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
