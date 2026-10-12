package business_test

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"strings"
	"testing"
	"time"
)

func TestPeerRetirementLedgerReportsIndependentBlockersWithoutMutation(t *testing.T) {
	db, raw, peer, rel, h, l, v := peerMigrationFixture(t, true)
	ctx := context.Background()
	repo := db.Pool().(store.RetirementRepository)
	ledger, e := repo.RetirementLedger(ctx, rel, h.SourceID)
	if e != nil {
		t.Fatal(e)
	}
	if ledger.DatabaseClear || !ledger.RequiresPhysicalVerification {
		t.Fatal("managed node reported clear", ledger)
	}
	codes := map[string]bool{}
	for _, b := range ledger.Blockers {
		codes[b.Code] = true
		if b.Count < 1 || len(b.SampleIDs) > 8 || b.NextStep == "" {
			t.Fatal(b)
		}
	}
	if !codes["managed_media"] || !codes["storage_accounting"] {
		t.Fatal("missing resource blockers", ledger)
	}
	if e = peer.RegisterPeerMigration(ctx, rel, h, l, "queued", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e = peer.RegisterPeerMigrationObject(ctx, rel, l, v, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	lease := hashPath(t.Name() + "lease")[:32]
	if _, e = raw.Exec("INSERT INTO migration_read_leases(lease_id,member_id,logical_id,object_id,source_version,expires_at) VALUES (?,?,?,?,?,?)", lease, h.SourceID, v.Object.ID, v.Object.ObjectID, v.Object.Version, time.Now().Unix()+30); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { raw.Exec("DELETE FROM migration_read_leases WHERE lease_id=?", lease) })
	ledger, e = repo.RetirementLedger(ctx, rel, h.SourceID)
	if e != nil {
		t.Fatal(e)
	}
	codes = map[string]bool{}
	for _, b := range ledger.Blockers {
		codes[b.Code] = true
	}
	for _, code := range []string{"migration_tasks", "migration_scopes", "migration_journals", "active_read_leases"} {
		if !codes[code] {
			t.Fatal("missing lifecycle blocker", code, ledger)
		}
	}
	if _, e = repo.RetirementLedger(ctx, rel, strings.Repeat("e", 32)); e == nil {
		t.Fatal("foreign node inspected")
	}
	var used, reserved int64
	if e = raw.QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", h.SourceID).Scan(&used, &reserved); e != nil || used != 7 || reserved != 0 {
		t.Fatal("ledger changed quota", used, reserved, e)
	}
}
func TestPeerRetirementLedgerEmptySQLStillRequiresPhysicalVerification(t *testing.T) {
	db, raw, _, rel, h, _, _ := peerMigrationFixture(t, false)
	ledger, e := db.Pool().(store.RetirementRepository).RetirementLedger(context.Background(), rel, h.TargetID)
	if e != nil {
		t.Fatal(e)
	}
	if !ledger.DatabaseClear || !ledger.RequiresPhysicalVerification {
		t.Fatal("empty ledger claimed retirement permission", ledger)
	}
	// A cold recovery manifest is independent of a zero media quota.
	if _, e = raw.Exec("INSERT INTO cluster_business_backups(master_id,generation,checksum,size_bytes,chunk_count,state,created_at,updated_at) VALUES (?,919191,?,7,1,'ready',1,1)", h.MasterID, strings.Repeat("9", 64)); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		raw.Exec("DELETE FROM cluster_business_backups WHERE master_id=? AND generation=919191", h.MasterID)
	})
	ledger, e = db.Pool().(store.RetirementRepository).RetirementLedger(context.Background(), rel, h.TargetID)
	if e != nil || ledger.DatabaseClear {
		t.Fatal("backup omitted", ledger, e)
	}
	found := false
	for _, b := range ledger.Blockers {
		if b.Code == "backup_generations" {
			found = true
		}
	}
	if !found {
		t.Fatal(ledger)
	}
}

func TestPeerRetirementLedgerMasterResourcesAndOfflineMember(t *testing.T) {
	f := migrationDatabase(t)
	ctx := context.Background()
	repo := f.db.Pool().(store.RetirementRepository)
	ledger, e := repo.RetirementLedger(ctx, f.rel, f.source)
	if e != nil {
		t.Fatal(e)
	}
	codes := map[string]bool{}
	for _, b := range ledger.Blockers {
		codes[b.Code] = true
	}
	if ledger.Role != "Master" || ledger.DatabaseClear || !codes["managed_media"] || !codes["storage_accounting"] {
		t.Fatal("Master omitted authoritative resources", ledger)
	}
	if _, e = f.raw.Exec("UPDATE cluster_storage_members SET health='offline' WHERE member_id=?", f.source); e != nil {
		t.Fatal(e)
	}
	ledger, e = repo.RetirementLedger(ctx, f.rel, f.source)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, b := range ledger.Blockers {
		if b.Code == "node_offline" {
			found = true
		}
	}
	if !found {
		t.Fatal("offline member reported reconciled", ledger)
	}
	identity, e := f.db.Nodes().ReadIdentity(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = repo.RetirementLedger(ctx, f.rel, identity.ID); e == nil {
		t.Fatal("Master Local admitted for retirement")
	}
}
