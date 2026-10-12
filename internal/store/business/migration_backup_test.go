package business_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestMigrationFactsBlockSnapshotsWithoutDiscardingJournals(t *testing.T) {
	db := database(t)
	ctx := context.Background()
	n, e := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: strings.Repeat("a", 32), Role: "Standalone", PrivateKey: "private-fixture"})
	if e != nil {
		t.Fatal(e)
	}
	raw := db.(interface{ Database() *sql.DB }).Database()
	if _, e = raw.Exec("UPDATE node_identity SET `role`='Master' WHERE singleton=1"); e != nil {
		t.Fatal(e)
	}
	id := strings.Repeat("e", 32)
	t.Cleanup(func() {
		for _, table := range []string{"migration_tasks", "migration_capacity", "migration_scopes", "migration_storage_journal"} {
			raw.Exec("DELETE FROM "+table+" WHERE task_id=?", id)
		}
		raw.Exec("UPDATE node_identity SET `role`=? WHERE singleton=1", n.Role)
	})
	for _, fixture := range []struct {
		table, sql string
		args       []any
	}{
		{"migration_tasks", "INSERT INTO migration_tasks(task_id,master_id,source_id,target_id,source_relationship,target_relationship,plan_sha256,plan,state,object_count,total_bytes,created_at,updated_at) VALUES (?,?,?,?,?,?,?,'{}','paused',1,7,1,1)", []any{id, n.ID, "source", "target", "source-rel", "target-rel", strings.Repeat("a", 64)}},
		{"migration_capacity", "INSERT INTO migration_capacity(task_id,member_id,reserved_bytes,updated_at) VALUES (?,'target',7,1)", []any{id}},
		{"migration_scopes", "INSERT INTO migration_scopes(scope_id,task_id,member_id,resource_kind,parent_path,created_at) VALUES ('scope',?,'source','media','music/locked',1)", []any{id}},
		{"migration_storage_journal", "INSERT INTO migration_storage_journal(task_id,logical_id,unit_id,master_id,source_id,target_id,resource_kind,object_id,physical_path,source_version,expected_bytes,state,updated_at) VALUES (?,'logical','unit','master','source','target','media','object','music/locked/a.mp3','version',7,'verified',1)", []any{id}},
	} {
		if _, e = raw.Exec(fixture.sql, fixture.args...); e != nil {
			t.Fatal(e)
		}
		snapshot, e := db.Maintenance().InspectMaintenance(ctx)
		if e != nil || snapshot.LogicalIdle {
			t.Fatal("migration fact disappeared from freeze check", fixture.table, snapshot, e)
		}
		emitted := false
		e = db.Backups().ExportBusinessSnapshot(ctx, func(string, map[string]any) error { emitted = true; return nil })
		if !errors.Is(e, store.ErrBackupBusy) || emitted {
			t.Fatal("snapshot bypassed migration journal", fixture.table, e, emitted)
		}
		var count int
		if e = raw.QueryRow("SELECT COUNT(*) FROM "+fixture.table+" WHERE task_id=?", id).Scan(&count); e != nil || count != 1 {
			t.Fatal("inspection discarded state", count, e)
		}
		if _, e = raw.Exec("DELETE FROM "+fixture.table+" WHERE task_id=?", id); e != nil {
			t.Fatal(e)
		}
	}
}
