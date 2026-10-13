package business_test

import (
	"context"
	"fmt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestResourceMigrationAdminRevisionFencesAndBoundedStatus(t *testing.T) {
	f := migrationDatabase(t)
	ctx := context.Background()
	admin := f.db.Pool().(store.MigrationAdminRepository)
	plan := f.plan(t, hashPath(t.Name())[:32])
	task, e := f.repo.StartMigration(ctx, plan, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	status, e := admin.MigrationStatus(ctx, task.ID, "")
	if e != nil || status.RetirementReady || !status.Complete || len(status.Objects) != 3 || len(status.ObjectStages) != 1 || status.ObjectStages[0].Count != 3 {
		t.Fatal("status", status, e)
	}
	if _, e = f.raw.Exec("UPDATE migration_tasks SET master_id=? WHERE task_id=?", f.other, task.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = admin.MigrationStatus(ctx, task.ID, ""); e == nil {
		t.Fatal("foreign Master task exposed")
	}
	foreignPage, e := admin.MigrationTasksPage(ctx, 0, "")
	if e != nil {
		t.Fatal(e)
	}
	for _, foreign := range foreignPage.Tasks {
		if foreign.ID == task.ID {
			t.Fatal("foreign Master task listed")
		}
	}
	if _, e = f.raw.Exec("UPDATE migration_tasks SET master_id=? WHERE task_id=?", task.MasterID, task.ID); e != nil {
		t.Fatal(e)
	}
	var reservation int64
	if e = f.raw.QueryRow("SELECT reserved_bytes FROM migration_capacity WHERE task_id=?", task.ID).Scan(&reservation); e != nil {
		t.Fatal(e)
	}
	paused, e := admin.ControlMigrationRevision(ctx, task.ID, "pause", task.Revision, store.NodeAudit{Actor: "fixture-admin-control"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = admin.ControlMigrationRevision(ctx, task.ID, "resume", task.Revision, store.NodeAudit{}); e == nil {
		t.Fatal("stale control revision accepted")
	}
	again, e := admin.ControlMigrationRevision(ctx, task.ID, "pause", paused.Revision, store.NodeAudit{})
	if e != nil || again.Revision != paused.Revision {
		t.Fatal("duplicate pause replay", again, e)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, action := range []string{"resume", "cancel"} {
		wg.Go(func() {
			_, e := admin.ControlMigrationRevision(ctx, task.ID, action, paused.Revision, store.NodeAudit{})
			results <- e
		})
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal("concurrent stale action applied", success)
	}
	var retained int64
	if e = f.raw.QueryRow("SELECT reserved_bytes FROM migration_capacity WHERE task_id=?", task.ID).Scan(&retained); e != nil || retained != reservation {
		t.Fatal("control refunded pending cleanup", retained, reservation, e)
	}
	// Isolated extra checkpoint rows exercise keyset pages without a full plan
	// decode. They are fixture rows, not claims of validated byte transfer.
	for i := 0; i < 35; i++ {
		id := hashPath(t.Name() + fmt.Sprint(i))
		unit := status.Objects[0].UnitID
		if _, e = f.raw.Exec("INSERT INTO migration_objects(task_id,unit_id,logical_id,resource_kind,source_object,target_object,source_version,physical_path,expected_bytes,verified_bytes,state,updated_at) VALUES (?, ?, ?, 'media', ?, ?, ?, ?,1,0,'pending',1)", task.ID, unit, id, id, id, strings.Repeat("e", 64), fmt.Sprintf("music/fixture/%d.mp3", i)); e != nil {
			t.Fatal(e)
		}
	}
	after := ""
	seen := map[string]bool{}
	for {
		value, e := admin.MigrationStatus(ctx, task.ID, after)
		if e != nil {
			t.Fatal(e)
		}
		if len(value.Objects) > 16 || value.RetirementReady {
			t.Fatal("unbounded status", value)
		}
		for _, object := range value.Objects {
			if seen[object.ID] || object.ID <= after {
				t.Fatal("duplicate cursor")
			}
			seen[object.ID] = true
		}
		if value.Complete {
			break
		}
		if value.Next == after {
			t.Fatal("stalled cursor")
		}
		after = value.Next
	}
	if len(seen) != 38 {
		t.Fatal("omitted status objects", len(seen))
	}
	ids := []string{}
	t.Cleanup(func() {
		for _, id := range ids {
			f.raw.Exec("DELETE FROM migration_tasks WHERE task_id=?", id)
		}
	})
	for i := 0; i < 35; i++ {
		id := hashPath(t.Name() + "task" + fmt.Sprint(i))[:32]
		ids = append(ids, id)
		if _, e = f.raw.Exec("INSERT INTO migration_tasks(task_id,master_id,source_id,target_id,plan_sha256,source_relationship,target_relationship,plan,state,revision,object_count,total_bytes,created_at,updated_at) VALUES (?,?,?,?,?, ?,?,'{}','failed',1,0,0,?,1)", id, task.MasterID, f.source, f.target, strings.Repeat("e", 64), f.rel, strings.Repeat("c", 32), time.Now().Unix()); e != nil {
			t.Fatal(e)
		}
	}
	cursor := ""
	stamp := int64(0)
	tasks := map[string]bool{}
	for {
		page, e := admin.MigrationTasksPage(ctx, stamp, cursor)
		if e != nil {
			t.Fatal(e)
		}
		if len(page.Tasks) > 16 {
			t.Fatal("unbounded task page")
		}
		for _, task := range page.Tasks {
			if tasks[task.ID] {
				t.Fatal("repeated task cursor")
			}
			tasks[task.ID] = true
		}
		if page.Complete {
			break
		}
		cursor = page.NextID
		stamp = page.NextTime
	}
	if len(tasks) != 36 {
		t.Fatal("failed/historical tasks omitted", len(tasks))
	}
	if _, e = admin.MigrationStatus(ctx, task.ID, "bad-cursor"); e == nil {
		t.Fatal("invalid object cursor")
	}
}
