package business_test

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
	"strings"
	"testing"
	"time"
)

func TestPeerRetirementFencePersistsAndRejectsPreviouslyAdmittedMutations(t *testing.T) {
	db, raw, peer, rel, h, l, v := peerMigrationFixture(t, false)
	ctx := context.Background()
	repo := db.Pool().(store.RetirementFenceRepository)
	relation, e := db.Nodes().Relationship(ctx, rel)
	if e != nil {
		t.Fatal(e)
	}
	// Authentication can precede the fence; the later durable mutation must
	// still reject even when a handler retained its original active relation.
	if _, e = db.Nodes().ReserveNodeNonce(ctx, rel, strings.Repeat("1", 32), relation.Credential, time.Now().Unix(), false, false); e != nil {
		t.Fatal(e)
	}
	fenced, e := repo.BeginRetirement(ctx, rel, h.TargetID, store.NodeAudit{Actor: "test"})
	if e != nil || fenced.CompletedAt != 0 {
		t.Fatal(fenced, e)
	}
	reconstructed := business.New(raw, db.Backend())
	again, e := reconstructed.BeginRetirement(ctx, rel, h.TargetID, store.NodeAudit{})
	if e != nil || again != fenced {
		t.Fatal("fence lost on repository reconstruction", again, e)
	}
	owned := db.Pool().(store.OwnedStorageRepository)
	if e = owned.ReserveOwnedUpload(ctx, strings.Repeat("2", 32), rel, store.MediaObject{ID: v.Object.ObjectID, Path: v.Object.Path, Kind: v.Object.Kind}, 7, 20*store.GiB, store.NodeAudit{}); e == nil {
		t.Fatal("previous authentication authorized new write")
	}
	if e = peer.RegisterPeerMigration(ctx, rel, h, l, "queued", 20*store.GiB, store.NodeAudit{}); e == nil {
		t.Fatal("retiring target admitted migration")
	}
	if e = db.Backups().BeginBackup(ctx, rel, 100, store.NodeAudit{}); e == nil {
		t.Fatal("retiring target admitted backup")
	}
	if e = db.Nodes().RevokeRelationship(ctx, rel, true, store.NodeAudit{}); e == nil {
		t.Fatal("old admitted revoke bypassed the durable fence")
	}
	if _, e = db.Nodes().ReserveNodeNonce(ctx, rel, strings.Repeat("3", 32), relation.Credential, time.Now().Unix(), false, false); e == nil {
		t.Fatal("ordinary credential survived fence")
	}
	if _, e = repo.ReserveRetirementNonce(ctx, rel, strings.Repeat("3", 32), relation.Credential, time.Now().Unix(), false); e != nil {
		t.Fatal("receipt authentication blocked", e)
	}
	if _, e = repo.ReserveRetirementNonce(ctx, rel, strings.Repeat("3", 32), relation.Credential, time.Now().Unix(), false); e == nil {
		t.Fatal("receipt nonce replay accepted")
	}
	if _, e = raw.Exec("UPDATE cluster_storage_members SET reserved_bytes=1 WHERE member_id=?", h.TargetID); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.CompleteRetirement(ctx, rel, h.TargetID, store.NodeAudit{}); e == nil {
		t.Fatal("final ledger not rechecked")
	}
	if _, e = raw.Exec("UPDATE cluster_storage_members SET reserved_bytes=0 WHERE member_id=?", h.TargetID); e != nil {
		t.Fatal(e)
	}
	complete, e := repo.CompleteRetirement(ctx, rel, h.TargetID, store.NodeAudit{})
	if e != nil || complete.CompletedAt < complete.FencedAt {
		t.Fatal(complete, e)
	}
	again, e = reconstructed.CompleteRetirement(ctx, rel, h.TargetID, store.NodeAudit{})
	if e != nil || again != complete {
		t.Fatal("lost ack changed tombstone", again, e)
	}
	if e = db.Nodes().RevokeRelationship(ctx, rel, true, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	again, e = reconstructed.RetirementFence(ctx, rel, h.TargetID)
	if e != nil || again != complete {
		t.Fatal("old notification erased receipt", again, e)
	}
	if _, e = db.Nodes().ReserveNodeNonce(ctx, rel, strings.Repeat("4", 32), relation.Credential, time.Now().Unix(), false, false); e == nil {
		t.Fatal("retired credential authorized ordinary request")
	}
	var audits int
	if e = raw.QueryRow("SELECT COUNT(*) FROM node_audit WHERE relationship_id=? AND action='retirement-completed'", rel).Scan(&audits); e != nil || audits != 1 {
		t.Fatal("replay duplicated audit", audits, e)
	}
}
