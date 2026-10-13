package business_test

import (
	"context"
	"fmt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"strings"
	"testing"
	"time"
)

func TestPeerRetirementLedgerTerminalCancellationRequiresCompleteRosterAndRole(t *testing.T) {
	for _, source := range []bool{true, false} {
		t.Run(fmt.Sprint(source), func(t *testing.T) {
			db, raw, peer, rel, h, l, v := peerMigrationFixture(t, source)
			ctx := context.Background()
			if e := peer.RegisterPeerMigration(ctx, rel, h, l, "cancelling", 20*store.GiB, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			if e := peer.RegisterPeerMigrationObject(ctx, rel, l, v, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			if !source {
				if e := peer.CompletePeerMigrationAbort(ctx, rel, l, v.Object.ID, store.NodeAudit{}); e != nil {
					t.Fatal(e)
				}
			}
			objectsSHA, e := store.MigrationUnitObjectsSHA([]store.MigrationPeerObject{v})
			if e != nil {
				t.Fatal(e)
			}
			unit := store.MigrationUnitFinishGrant{Header: h, Unit: store.MigrationUnit{ID: hashPath(v.Object.Resource + ":" + v.Object.Parent), Resource: v.Object.Resource, Parent: v.Object.Parent, State: "cancelled", ObjectCount: 1, Bytes: 7}, UnitVersion: hashPath("terminal-cancel-unit"), ObjectsSHA: objectsSHA}
			if _, e = peer.CompletePeerMigrationUnitCancellation(ctx, rel, l, unit, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			unitsSHA, e := store.MigrationTaskUnitsSHA([]store.MigrationUnitFinishGrant{unit})
			if e != nil {
				t.Fatal(e)
			}
			grant := store.MigrationTaskFinishGrant{Outcome: "cancelled", Header: h, UnitCount: 1, UnitsSHA: unitsSHA}
			if _, e = peer.CompletePeerMigrationTaskCancellation(ctx, rel, l, grant, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			member := h.TargetID
			if source {
				member = h.SourceID
			}
			repo := db.Pool().(store.RetirementRepository)
			inspect := func() store.RetirementLedger {
				ledger, e := repo.RetirementLedger(ctx, rel, member)
				if e != nil {
					t.Fatal(e)
				}
				return ledger
			}
			baseline := inspect()
			for _, code := range []string{"migration_journals", "migration_terminal_rosters", "migration_unit_receipts", "migration_runner_leases"} {
				if retirementCode(baseline, code) != 0 {
					t.Fatal("valid history blocked", code, baseline)
				}
			}
			if source && retirementCode(baseline, "managed_media") == 0 {
				t.Fatal("cancelled source ownership disappeared", baseline)
			}
			execute := func(sql string, args ...any) {
				if _, e := raw.Exec(sql, args...); e != nil {
					t.Fatal(e)
				}
			}
			var bindingJSON, bindingSHA string
			if e = raw.QueryRow("SELECT binding_json,binding_sha256 FROM migration_peer_bindings WHERE task_id=? AND logical_id=?", h.TaskID, v.Object.ID).Scan(&bindingJSON, &bindingSHA); e != nil {
				t.Fatal(e)
			}
			for _, fault := range []struct {
				name, change, restore, code string
				args, undo                  []any
			}{
				{"missing-binding", "DELETE FROM migration_peer_bindings WHERE task_id=? AND logical_id=?", "INSERT INTO migration_peer_bindings(task_id,logical_id,binding_sha256,binding_json) VALUES (?,?,?,?)", "migration_journals", []any{h.TaskID, v.Object.ID}, []any{h.TaskID, v.Object.ID, bindingSHA, bindingJSON}},
				{"missing-unit", "UPDATE migration_storage_journal SET unit_id=? WHERE task_id=?", "UPDATE migration_storage_journal SET unit_id=? WHERE task_id=?", "migration_journals", []any{strings.Repeat("f", 64), h.TaskID}, []any{unit.Unit.ID, h.TaskID}},
				{"unit-state", "UPDATE migration_units SET state='pending' WHERE task_id=?", "UPDATE migration_units SET state='cancelled' WHERE task_id=?", "migration_unit_receipts", []any{h.TaskID}, []any{h.TaskID}},
				{"unit-count", "UPDATE migration_units SET object_count=2 WHERE task_id=?", "UPDATE migration_units SET object_count=1 WHERE task_id=?", "migration_terminal_rosters", []any{h.TaskID}, []any{h.TaskID}},
				{"task-bytes", "UPDATE migration_tasks SET total_bytes=8 WHERE task_id=?", "UPDATE migration_tasks SET total_bytes=7 WHERE task_id=?", "migration_terminal_rosters", []any{h.TaskID}, []any{h.TaskID}},
				{"wrong-role", "UPDATE migration_storage_journal SET state='published' WHERE task_id=?", "UPDATE migration_storage_journal SET state=? WHERE task_id=?", "migration_journals", []any{h.TaskID}, []any{map[bool]string{true: "receiving", false: "aborted"}[source], h.TaskID}},
				{"wrong-master", "UPDATE migration_storage_journal SET master_id=? WHERE task_id=?", "UPDATE migration_storage_journal SET master_id=? WHERE task_id=?", "migration_journals", []any{strings.Repeat("f", 32), h.TaskID}, []any{h.MasterID, h.TaskID}},
				{"active-runner", "UPDATE migration_runners SET expires_at=? WHERE task_id=?", "UPDATE migration_runners SET expires_at=0 WHERE task_id=?", "migration_runner_leases", []any{time.Now().Unix() + 60, h.TaskID}, []any{h.TaskID}},
			} {
				t.Run(fault.name, func(t *testing.T) {
					execute(fault.change, fault.args...)
					defer execute(fault.restore, fault.undo...)
					if ledger := inspect(); retirementCode(ledger, fault.code) != 1 {
						t.Fatal("missing blocker", fault, ledger)
					}
				})
			}
			// Inject only scalar receipt states in this isolated database to cover
			// historical committed units inside a partially cancelled task.
			now := time.Now().Unix()
			execute("UPDATE migration_units SET state='cleaned',committed_at=?,cleanup_after=? WHERE task_id=?", now-3601, now-1, h.TaskID)
			phase := "published"
			if source {
				phase = "deleted"
			}
			execute("UPDATE migration_storage_journal SET state=? WHERE task_id=?", phase, h.TaskID)
			if ledger := inspect(); retirementCode(ledger, "migration_journals") != 0 || retirementCode(ledger, "migration_unit_receipts") != 0 {
				t.Fatal("cleaned historical unit", ledger)
			}
			if !source {
				execute("UPDATE migration_storage_journal SET state='deleted' WHERE task_id=?", h.TaskID)
				if ledger := inspect(); retirementCode(ledger, "migration_journals") != 0 {
					t.Fatal("later managed deletion blocked", ledger)
				}
			}
			execute("UPDATE migration_units SET cleanup_after=? WHERE task_id=?", now+60, h.TaskID)
			if ledger := inspect(); retirementCode(ledger, "migration_unit_receipts") != 1 {
				t.Fatal("future grace ignored", ledger)
			}

		})
	}
}
