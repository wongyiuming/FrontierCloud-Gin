package business_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestPriorityOrderAtomicStaleRollbackAndLegacyValues(t *testing.T) {
	db := database(t)
	repo := db.Media()
	ctx := context.Background()
	scope := store.PriorityScope{Path: "music/" + t.Name(), Kind: "media"}
	for _, name := range []string{"a", "b", "c", "d"} {
		scope.Objects = append(scope.Objects, store.MediaObject{Path: scope.Path + "/" + name + ".mp3", Kind: "audio"})
	}
	for i, value := range []int{100, 100, 101, 99} {
		if _, e := repo.SetPreference(ctx, scope.Objects[i], value, store.AdminAudit{}); e != nil {
			t.Fatal(e)
		}
	}
	initial, e := repo.PriorityOrder(ctx, scope)
	if e != nil {
		t.Fatal(e)
	}
	if initial.Items[0].Path != scope.Objects[2].Path || initial.Items[3].Preference != 99 {
		t.Fatal("legacy values changed", initial)
	}
	move := store.PriorityMove{Revision: initial.Revision, Path: scope.Objects[2].Path, Before: scope.Objects[1].Path, After: scope.Objects[0].Path}
	result, e := repo.MovePriority(ctx, scope, move, store.AdminAudit{Action: "priority_reorder", RequestID: "drag"})
	if e != nil {
		t.Fatal(e)
	}
	for i, index := range []int{0, 2, 1, 3} {
		if result.Items[i].Path != scope.Objects[index].Path {
			t.Fatal("incorrect target", result)
		}
	}
	if result.Items[3].Preference != 99 {
		t.Fatal("99 neighbour changed", result)
	}
	if _, e = repo.MovePriority(ctx, scope, move, store.AdminAudit{}); !errors.Is(e, store.ErrPriorityStale) {
		t.Fatal("stale accepted", e)
	}
	for _, value := range []int{-7, 0, 100, 500, 500000} {
		if _, e = repo.SetPreference(ctx, scope.Objects[0], value, store.AdminAudit{}); e != nil {
			t.Fatal(value, e)
		}
	}
	for _, value := range []int{-8, 500001} {
		if _, e = repo.SetPreference(ctx, scope.Objects[0], value, store.AdminAudit{}); e == nil {
			t.Fatal("invalid extended bound", value)
		}
	}
	current, e := repo.PriorityOrder(ctx, scope)
	if e != nil {
		t.Fatal(e)
	}
	move = store.PriorityMove{Revision: current.Revision, Path: scope.Objects[3].Path, Before: current.Items[0].Path}
	raw := db.(interface{ Database() *sql.DB }).Database()
	trigger := "CREATE TRIGGER reject_priority_audit BEFORE INSERT ON admin_audit_log BEGIN SELECT RAISE(ABORT,'audit unavailable'); END"
	if db.Backend() == "mysql" {
		trigger = "CREATE TRIGGER reject_priority_audit BEFORE INSERT ON admin_audit_log FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='audit unavailable'"
	}
	if _, e = raw.Exec(trigger); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { raw.Exec("DROP TRIGGER IF EXISTS reject_priority_audit") })
	if _, e = repo.MovePriority(ctx, scope, move, store.AdminAudit{Action: "priority_reorder"}); e == nil {
		t.Fatal("audit failure ignored")
	}
	rolled, e := repo.PriorityOrder(ctx, scope)
	if e != nil || rolled.Revision != current.Revision {
		t.Fatal("partial preferences committed", rolled, e)
	}
}

func TestPriorityCollisionAuditKeepsCompleteLargeBatch(t *testing.T) {
	db := database(t)
	repo := db.Media()
	ctx := context.Background()
	scope := store.PriorityScope{Path: "music/" + t.Name(), Kind: "directory"}
	for i := 0; i < 400; i++ {
		o := store.MediaObject{Path: fmt.Sprintf("%s/%04d", scope.Path, i), Kind: "directory"}
		scope.Objects = append(scope.Objects, o)
		if _, err := repo.SetPreference(ctx, o, 100, store.AdminAudit{}); err != nil {
			t.Fatal(err)
		}
	}
	moved := store.MediaObject{Path: scope.Path + "/zz", Kind: "directory"}
	scope.Objects = append(scope.Objects, moved)
	if _, err := repo.SetPreference(ctx, moved, 100, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	order, err := repo.PriorityOrder(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	result, err := repo.MovePriority(ctx, scope, store.PriorityMove{Revision: order.Revision, Path: moved.Path, After: scope.Objects[199].Path, Before: scope.Objects[200].Path}, store.AdminAudit{Action: "priority_reorder", RequestID: "large-drag"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed < 200 {
		t.Fatal("fixture did not expand collision window", result.Changed)
	}
	raw := db.(interface{ Database() *sql.DB }).Database()
	rows, err := raw.Query("SELECT source_summary,detail FROM admin_audit_log WHERE request_id='large-drag'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	batches := 0
	for rows.Next() {
		var source, detail string
		if err = rows.Scan(&source, &detail); err != nil {
			t.Fatal(err)
		}
		var paths []string
		var facts map[string]any
		if json.Unmarshal([]byte(source), &paths) != nil || json.Unmarshal([]byte(detail), &facts) != nil {
			t.Fatal("truncated audit JSON")
		}
		if facts["changed_total"] != float64(result.Changed) {
			t.Fatal("missing total", facts)
		}
		for _, p := range paths {
			seen[p] = true
		}
		batches++
	}
	if rows.Err() != nil || batches < 2 || len(seen) != result.Changed {
		t.Fatal("missing evidence", rows.Err(), batches, len(seen), result.Changed)
	}
}

func TestPriorityConcurrentAdminMovesHaveOneWinner(t *testing.T) {
	db := database(t)
	repo := db.Media()
	ctx := context.Background()
	if _, e := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: strings.Repeat("b", 32), Role: "Standalone", PrivateKey: "priority-test"}); e != nil {
		t.Fatal(e)
	}
	scope := store.PriorityScope{Path: "music/" + t.Name(), Kind: "directory"}
	for _, name := range []string{"a", "b", "c"} {
		scope.Objects = append(scope.Objects, store.MediaObject{Path: scope.Path + "/" + name, Kind: "directory"})
	}
	initial, e := repo.PriorityOrder(ctx, scope)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, index := range []int{1, 2} {
		wg.Go(func() {
			_, e := repo.MovePriority(ctx, scope, store.PriorityMove{Revision: initial.Revision, Path: scope.Objects[index].Path, Before: scope.Objects[0].Path}, store.AdminAudit{Action: "priority_reorder"})
			results <- e
		})
	}
	wg.Wait()
	close(results)
	success, stale := 0, 0
	for e := range results {
		if e == nil {
			success++
		} else if errors.Is(e, store.ErrPriorityStale) {
			stale++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || stale != 1 {
		t.Fatal(success, stale)
	}
}
