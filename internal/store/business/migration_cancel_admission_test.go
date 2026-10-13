package business_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestPeerMigrationCancellationDoesNotRequireOrRefundUnadmittedCapacity(t *testing.T) {
	_, raw, repo, rel, h, lease, object := peerMigrationFixture(t, false)
	ctx := context.Background()
	// This is a disposable native repository fixture. Existing reservations
	// belong to unrelated work and must not be refunded by this cancellation.
	if _, e := raw.Exec("UPDATE cluster_storage_members SET allocated_bytes=0,writable=0,reserved_bytes=13 WHERE member_id=?", h.TargetID); e != nil {
		t.Fatal(e)
	}
	if e := repo.RegisterPeerMigration(ctx, rel, h, lease, "queued", 0, store.NodeAudit{}); !errors.Is(e, store.ErrStorageCapacity) {
		t.Fatal("copy admitted without capacity", e)
	}
	for range 2 {
		if e := repo.RegisterPeerMigration(ctx, rel, h, lease, "cancelling", 0, store.NodeAudit{}); e != nil {
			t.Fatal("cancellation required copy capacity", e)
		}
	}
	var reserved, memberReserved int64
	if e := raw.QueryRow("SELECT reserved_bytes FROM migration_capacity WHERE task_id=?", h.TaskID).Scan(&reserved); e != nil || reserved != 0 {
		t.Fatal("cancel-only reservation", reserved, e)
	}
	if e := raw.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", h.TargetID).Scan(&memberReserved); e != nil || memberReserved != 13 {
		t.Fatal("other reservations changed", memberReserved, e)
	}
	if _, e := raw.Exec("UPDATE migration_tasks SET error_code='' WHERE task_id=?", h.TaskID); e != nil {
		t.Fatal(e)
	}
	lease.Epoch++
	if e := repo.RegisterPeerMigration(ctx, rel, h, lease, "queued", 20*store.GiB, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("new epoch revived cancel-only admission", e)
	}
	if e := repo.FencePeerMigration(ctx, rel, h.TaskID, lease.Epoch, "paused", store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("pause reopened cancellation", e)
	}
	if e := repo.RegisterPeerMigration(ctx, rel, h, lease, "cancelling", 0, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e := repo.RegisterPeerMigrationObject(ctx, rel, lease, object, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	for _, operation := range []string{"begin", "append", "verify", "publish"} {
		if _, e := repo.AuthorizePeerMigration(ctx, rel, lease, object.Object.ID, operation); !errors.Is(e, store.ErrMigrationState) {
			t.Fatal("cancel-only copy authorized", operation, e)
		}
	}
	if _, e := repo.AuthorizePeerMigration(ctx, rel, lease, object.Object.ID, "abort"); e != nil {
		t.Fatal(e)
	}
	// Native filesystem Abort is tested through the authenticated runner test;
	// this repository test independently checks the capacity receipt semantics.
	if e := repo.CompletePeerMigrationAbort(ctx, rel, lease, object.Object.ID, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	objectsSHA, e := store.MigrationUnitObjectsSHA([]store.MigrationPeerObject{object})
	if e != nil {
		t.Fatal(e)
	}
	grant := store.MigrationUnitFinishGrant{Header: h, Unit: store.MigrationUnit{ID: hashPath(object.Object.Resource + ":" + object.Object.Parent), Resource: object.Object.Resource, Parent: object.Object.Parent, State: "cancelled", ObjectCount: 1, Bytes: h.Bytes}, UnitVersion: strings.Repeat("3", 64), ObjectsSHA: objectsSHA}
	for range 2 {
		if _, e = repo.CompletePeerMigrationUnitCancellation(ctx, rel, lease, grant, store.NodeAudit{}); e != nil {
			t.Fatal("cancellation refunded nonexistent capacity", e)
		}
	}
	if e = raw.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", h.TargetID).Scan(&memberReserved); e != nil || memberReserved != 13 {
		t.Fatal("refunded unrelated work", memberReserved, e)
	}
	unitsSHA, e := store.MigrationTaskUnitsSHA([]store.MigrationUnitFinishGrant{grant})
	if e != nil {
		t.Fatal(e)
	}
	finish := store.MigrationTaskFinishGrant{Header: h, Outcome: "cancelled", UnitCount: 1, UnitsSHA: unitsSHA}
	for range 2 {
		if _, e = repo.CompletePeerMigrationTaskCancellation(ctx, rel, lease, finish, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
	}
}
