package business_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestResourceMigrationPagedConflictsCountDistinctImmediateParents(t *testing.T) {
	f := migrationDatabase(t)
	ctx := context.Background()
	var sourceBytes int64
	insert := func(name, owner, state string) {
		t.Helper()
		id := hashPath(name)
		if _, e := f.raw.Exec("INSERT INTO global_media_objects(media_id,storage_member_id,object_id,object_kind,media_path,path_locator,size_bytes,etag,state,created_at,updated_at) VALUES (?,?,?,'audio',?,?,1,?,?,?,?)", id, owner, id, name, id, hashPath("x"), state, time.Now().Unix(), time.Now().Unix()); e != nil {
			t.Fatal(e)
		}
		if owner == f.source {
			sourceBytes++
		}
	}
	for i := range 70 {
		parent := fmt.Sprintf("%s_group%02d", f.base, i)
		insert(parent+"/a.mp3", f.source, "active")
		insert(parent+"/z.mp3", f.other, "pending_delete")
		// Descendant rows sort between immediate children; they must neither
		// lose the ancestor's pending facts nor count as its direct children.
		insert(parent+"/nested/b.mp3", f.other, "active")
	}
	for i := range 70 {
		insert(fmt.Sprintf("%s_group00/m%02d.mp3", f.base, i), f.source, "active")
	}
	insert(f.base+"_Independent/a.mp3", f.source, "active")
	insert(f.base+"_Independent/nested/z.mp3", f.other, "active")
	insert(f.base+"_Case/a.mp3", f.source, "active")
	insert(f.base+"_case/z.mp3", f.other, "active")
	if _, e := f.raw.Exec("UPDATE cluster_storage_members SET used_bytes=used_bytes+? WHERE member_id=?", sourceBytes, f.source); e != nil {
		t.Fatal(e)
	}
	plans := f.repo.(store.MigrationPlanRepository)
	id := hashPath(t.Name())[:32]
	t.Cleanup(func() {
		for _, table := range []string{"migration_plan_bindings", "migration_plan_paths", "migration_plan_headers"} {
			f.raw.Exec("DELETE FROM "+table+" WHERE plan_id=?", id)
		}
	})
	p, e := plans.BuildMigrationPlan(ctx, id, f.source, f.target)
	if e != nil {
		t.Fatal(e)
	}
	if p.Catalog.TotalBlockers() != 70 || len(p.Catalog.Blockers) != 64 {
		t.Fatal("lost conflicts, duplicate parents, or unbounded samples", p.Catalog.TotalBlockers(), p.Catalog.Blockers)
	}
	seen := map[string]bool{}
	for _, blocker := range p.Catalog.Blockers {
		if blocker.Code != "split_directory_ownership" || seen[blocker.Resource] {
			t.Fatal(blocker)
		}
		seen[blocker.Resource] = true
	}
}
