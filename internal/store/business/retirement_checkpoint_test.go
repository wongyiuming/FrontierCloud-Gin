package business_test

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"strings"
	"testing"
	"time"
)

func TestPeerRetirementMigrationRequiresBoundTerminalHistory(t *testing.T) {
	db, raw, peer, rel, h, l, v := peerMigrationFixture(t, false)
	ctx := context.Background()
	repo := db.Pool().(store.RetirementMigrationRepository)
	read := func() (store.MigrationPeerObject, error) {
		return repo.RetirementMigration(ctx, rel, h.TargetID, h.MasterID, h.TaskID, v.Object.ID)
	}
	if e := peer.RegisterPeerMigration(ctx, rel, h, l, "cancelling", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e := peer.RegisterPeerMigrationObject(ctx, rel, l, v, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e := read(); e == nil {
		t.Fatal("active task admitted")
	}
	if e := peer.CompletePeerMigrationAbort(ctx, rel, l, v.Object.ID, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	objectsSHA, e := store.MigrationUnitObjectsSHA([]store.MigrationPeerObject{v})
	if e != nil {
		t.Fatal(e)
	}
	unit := store.MigrationUnitFinishGrant{Header: h, Unit: store.MigrationUnit{ID: hashPath(v.Object.Resource + ":" + v.Object.Parent), Resource: v.Object.Resource, Parent: v.Object.Parent, State: "cancelled", ObjectCount: 1, Bytes: 7}, UnitVersion: hashPath("retained-checkpoint"), ObjectsSHA: objectsSHA}
	if _, e = peer.CompletePeerMigrationUnitCancellation(ctx, rel, l, unit, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	unitsSHA, e := store.MigrationTaskUnitsSHA([]store.MigrationUnitFinishGrant{unit})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = peer.CompletePeerMigrationTaskCancellation(ctx, rel, l, store.MigrationTaskFinishGrant{Outcome: "cancelled", Header: h, UnitCount: 1, UnitsSHA: unitsSHA}, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	result, e := read()
	if e != nil || result.Header != h || result.State != "aborted" || result.Object.ID != v.Object.ID {
		t.Fatal(result, e)
	}
	if _, e = repo.RetirementMigration(ctx, rel, h.SourceID, h.MasterID, h.TaskID, v.Object.ID); e == nil {
		t.Fatal("foreign node admitted")
	}
	var original string
	if e = raw.QueryRow("SELECT binding_json FROM migration_peer_bindings WHERE task_id=? AND logical_id=?", h.TaskID, v.Object.ID).Scan(&original); e != nil {
		t.Fatal(e)
	}
	execute := func(query string, args ...any) {
		t.Helper()
		if _, e := raw.Exec(query, args...); e != nil {
			t.Fatal(e)
		}
	}
	execute("UPDATE migration_peer_bindings SET binding_json=? WHERE task_id=?", strings.Repeat("x", 32<<10), h.TaskID)
	if _, e = read(); e == nil {
		t.Fatal("oversized archived binding admitted")
	}
	execute("UPDATE migration_peer_bindings SET binding_json=? WHERE task_id=?", original, h.TaskID)
	execute("UPDATE migration_peer_bindings SET binding_sha256=? WHERE task_id=?", strings.Repeat("1", 64), h.TaskID)
	if _, e = read(); e == nil {
		t.Fatal("corrupt binding digest admitted")
	}
	digest, e := store.MigrationDigest(v.Object)
	if e != nil {
		t.Fatal(e)
	}
	execute("UPDATE migration_peer_bindings SET binding_sha256=? WHERE task_id=?", digest, h.TaskID)
	execute("UPDATE migration_runners SET expires_at=? WHERE task_id=?", time.Now().Unix()+60, h.TaskID)
	if _, e = read(); e == nil {
		t.Fatal("live runner admitted")
	}
	execute("UPDATE migration_runners SET expires_at=0 WHERE task_id=?", h.TaskID)
	if _, e = read(); e != nil {
		t.Fatal(e)
	}
	execute("UPDATE migration_storage_journal SET physical_path=? WHERE task_id=?", "elsewhere/unknown.mp3", h.TaskID)
	if _, e = read(); e == nil {
		t.Fatal("changed physical binding admitted")
	}
}
