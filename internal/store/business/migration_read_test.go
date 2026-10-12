package business_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestPeerMigrationActualReadLeaseBlocksCleanupAndCannotRevive(t *testing.T) {
	db, raw, repo, rel, h, l, v := peerMigrationFixture(t, true)
	reads := db.Nodes().(store.MigrationReadRepository)
	ctx := context.Background()
	// An admitted read predates registration and uses a different logical alias.
	id, e := reads.AcquireMigrationRead(ctx, rel, hashPath("read-alias"), v.Object.ObjectID, "media")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { reads.ReleaseMigrationRead(ctx, id) })
	if e = repo.RegisterPeerMigration(ctx, rel, h, l, "queued", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e = repo.RegisterPeerMigrationObject(ctx, rel, l, v, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	now := time.Now().Unix()
	g := store.MigrationCleanupGrant{TaskID: h.TaskID, MasterID: h.MasterID, SourceID: h.SourceID, TargetID: h.TargetID, PlanSHA: h.PlanSHA, UnitID: hashPath(v.Object.Resource + ":" + v.Object.Parent), UnitVersion: hashPath("read-lease-unit"), Object: v.Object, SHA256: v.Proof.SHA256, CommittedAt: now - 3601, CleanupAfter: now - 1, TargetVerifiedAt: now}
	if e = reads.RenewMigrationRead(ctx, rel, id); e != nil {
		t.Fatal(e)
	}
	if e = repo.PreparePeerMigrationCleanup(ctx, rel, l, g, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("live read did not block", e)
	}
	if _, e = raw.Exec("UPDATE migration_read_leases SET expires_at=? WHERE lease_id=?", now-1, id); e != nil {
		t.Fatal(e)
	}
	if e = reads.RenewMigrationRead(ctx, rel, id); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("expired read revived", e)
	}
	if e = repo.PreparePeerMigrationCleanup(ctx, rel, l, g, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e = reads.AcquireMigrationRead(ctx, rel, v.Object.ID, v.Object.ObjectID, "media"); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("read admitted after cleanup", e)
	}
	if e = reads.ReleaseMigrationRead(ctx, id); e != nil {
		t.Fatal(e)
	}
	if e = reads.ReleaseMigrationRead(ctx, id); e != nil {
		t.Fatal("repeat close", e)
	}
}

func TestPeerMigrationConcurrentReadAdmissionAndCleanup(t *testing.T) {
	db, _, repo, rel, h, l, v := peerMigrationFixture(t, true)
	reads := db.Nodes().(store.MigrationReadRepository)
	ctx := context.Background()
	if e := repo.RegisterPeerMigration(ctx, rel, h, l, "queued", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e := repo.RegisterPeerMigrationObject(ctx, rel, l, v, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	now := time.Now().Unix()
	g := store.MigrationCleanupGrant{TaskID: h.TaskID, MasterID: h.MasterID, SourceID: h.SourceID, TargetID: h.TargetID, PlanSHA: h.PlanSHA, UnitID: hashPath(v.Object.Resource + ":" + v.Object.Parent), UnitVersion: hashPath("concurrent-read-unit"), Object: v.Object, SHA256: v.Proof.SHA256, CommittedAt: now - 3601, CleanupAfter: now - 1, TargetVerifiedAt: now}
	start := make(chan struct{})
	var wg sync.WaitGroup
	var readID string
	var readErr, cleanupErr error
	wg.Go(func() {
		<-start
		readID, readErr = reads.AcquireMigrationRead(ctx, rel, v.Object.ID, v.Object.ObjectID, "media")
	})
	wg.Go(func() { <-start; cleanupErr = repo.PreparePeerMigrationCleanup(ctx, rel, l, g, store.NodeAudit{}) })
	close(start)
	wg.Wait()
	if readErr == nil {
		defer reads.ReleaseMigrationRead(ctx, readID)
		if !errors.Is(cleanupErr, store.ErrMigrationState) {
			t.Fatal("cleanup crossed concurrent read admission", cleanupErr)
		}
	} else if cleanupErr != nil || !errors.Is(readErr, store.ErrMigrationState) {
		t.Fatal("neither side obtained a safe boundary", readErr, cleanupErr)
	}
}
