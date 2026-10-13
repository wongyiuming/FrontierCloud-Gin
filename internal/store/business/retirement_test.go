package business_test

import (
	"context"
	"encoding/json"
	"fmt"
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

func retirementCode(ledger store.RetirementLedger, code string) int64 {
	for _, b := range ledger.Blockers {
		if b.Code == code {
			return b.Count
		}
	}
	return 0
}
func TestPeerRetirementLedgerWorkerAndMasterMutationReferences(t *testing.T) {
	f := migrationDatabase(t)
	ctx := context.Background()
	repo := f.db.Pool().(store.RetirementRepository)
	ids := []string{}
	insert := func(member, media any, state string, expiry int64) string {
		id := hashPath(t.Name() + fmt.Sprint(len(ids)))[:32]
		ids = append(ids, id)
		if _, e := f.raw.Exec("INSERT INTO cluster_worker_jobs(job_id,idempotency_key,job_type,media_id,member_id,payload,result,state,lease_expires_at,attempts,created_at,updated_at) VALUES (?,?, 'fixture',?,?, '{}','{}',?,?,0,1,1)", id, id, media, member, state, expiry); e != nil {
			t.Fatal(e)
		}
		return id
	}
	t.Cleanup(func() {
		for _, id := range ids {
			f.raw.Exec("DELETE FROM cluster_worker_jobs WHERE job_id=?", id)
		}
	})
	first := insert(f.source, nil, "queued", 0)
	insert(f.target, nil, "queued", 0)
	insert(nil, f.objects[0].MediaID, "failed", 0)
	insert(nil, nil, "running", time.Now().Unix()+30)
	insert(nil, strings.Repeat("e", 64), "queued", 0)
	insert(f.target, f.objects[0].MediaID, "queued", 0)
	insert(f.source, nil, "complete", time.Now().Unix()+30)
	insert(f.source, nil, "complete", 0)
	ledger, e := repo.RetirementLedger(ctx, f.rel, f.source)
	if e != nil || retirementCode(ledger, "worker_jobs") != 6 {
		t.Fatal("missing worker reference or live completed lease", ledger, e)
	}
	if _, e = f.raw.Exec("UPDATE cluster_worker_jobs SET state='complete' WHERE job_id=?", first); e != nil {
		t.Fatal(e)
	}
	ledger, e = repo.RetirementLedger(ctx, f.rel, f.source)
	if e != nil || retirementCode(ledger, "worker_jobs") != 5 {
		t.Fatal("terminal worker count", ledger, e)
	}
	op, e := f.db.Pool().PrepareGlobalRename(ctx, f.base, f.base+"Moved", store.AdminAudit{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.raw.Exec("DELETE FROM media_delete_operations WHERE operation_id=?", op.ID) })
	ledger, e = repo.RetirementLedger(ctx, f.rel, f.source)
	if e != nil || retirementCode(ledger, "file_transactions") != 1 {
		t.Fatal("Master mutation omitted", ledger, e)
	}
	unrelated, e := repo.RetirementLedger(ctx, strings.Repeat("c", 32), f.target)
	if e != nil || retirementCode(unrelated, "file_transactions") != 0 || retirementCode(unrelated, "unverified_file_transactions") != 0 {
		t.Fatal("valid unrelated mutation blocked member", unrelated, e)
	}
	// Corrupt only this isolated fixture's manifest; uncertainty must block all
	// affected retirement checks rather than hiding the unresolved transaction.
	if _, e = f.raw.Exec("UPDATE media_delete_operations SET manifest='{}' WHERE operation_id=?", op.ID); e != nil {
		t.Fatal(e)
	}
	unrelated, e = repo.RetirementLedger(ctx, strings.Repeat("c", 32), f.target)
	if e != nil || retirementCode(unrelated, "unverified_file_transactions") != 1 {
		t.Fatal("ambiguous mutation cleared", unrelated, e)
	}
	large, _ := json.Marshal(map[string]string{"oversized": strings.Repeat("x", 100000)})
	if _, e = f.raw.Exec("UPDATE media_delete_operations SET manifest=? WHERE operation_id=?", string(large), op.ID); e != nil {
		t.Fatal(e)
	}
	ledger, e = repo.RetirementLedger(ctx, f.rel, f.source)
	if e != nil || retirementCode(ledger, "unverified_file_transactions") != 1 {
		t.Fatal("oversized mutation ignored", ledger, e)
	}
	for i := 0; i < 10; i++ {
		id := hashPath(t.Name() + "mutation" + fmt.Sprint(i))[:32]
		if _, e = f.raw.Exec("INSERT INTO media_delete_operations(operation_id,state,manifest,created_at) VALUES (?,'rename_cleanup','{}','2026-10-12 01:02:03.000000')", id); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { f.raw.Exec("DELETE FROM media_delete_operations WHERE operation_id=?", id) })
	}
	ledger, e = repo.RetirementLedger(ctx, f.rel, f.source)
	if e != nil || retirementCode(ledger, "unverified_file_transactions") != 11 {
		t.Fatal("unexamined rows silently cleared", ledger, e)
	}
	var state string
	if e = f.raw.QueryRow("SELECT state FROM media_delete_operations WHERE operation_id=?", op.ID).Scan(&state); e != nil || state != "rename_pending" {
		t.Fatal("ledger changed transaction", state, e)
	}
}
func TestPeerRetirementLedgerOrphanBindingsAndTerminalTaskIncompleteJournal(t *testing.T) {
	db, raw, peer, rel, h, l, v := peerMigrationFixture(t, true)
	ctx := context.Background()
	repo := db.Pool().(store.RetirementRepository)
	if e := peer.RegisterPeerMigration(ctx, rel, h, l, "queued", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e := raw.Exec("INSERT INTO migration_peer_bindings(task_id,logical_id,binding_sha256,binding_json) VALUES (?,?,?,'{}')", h.TaskID, v.Object.ID, strings.Repeat("f", 64)); e != nil {
		t.Fatal(e)
	}
	ledger, e := repo.RetirementLedger(ctx, rel, h.SourceID)
	if e != nil || retirementCode(ledger, "migration_binding_orphans") != 1 {
		t.Fatal("orphan binding omitted", ledger, e)
	}
	if _, e = raw.Exec("DELETE FROM migration_peer_bindings WHERE task_id=?", h.TaskID); e != nil {
		t.Fatal(e)
	}
	if e = peer.RegisterPeerMigrationObject(ctx, rel, l, v, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e = raw.Exec("UPDATE migration_tasks SET state='completed' WHERE task_id=?", h.TaskID); e != nil {
		t.Fatal(e)
	}
	ledger, e = repo.RetirementLedger(ctx, rel, h.SourceID)
	if e != nil || retirementCode(ledger, "migration_journals") != 1 {
		t.Fatal("terminal task hid incomplete journal", ledger, e)
	}
}
