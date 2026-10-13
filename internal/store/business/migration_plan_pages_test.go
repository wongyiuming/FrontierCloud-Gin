package business_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Repository proofs below are isolated fixture facts. Authenticated native-byte
// acquisition is exercised separately by the HTTP runner and fleet suites.
func TestResourceMigrationPagedPlanAdmissionCommitAndManifestIntegrity(t *testing.T) {
	f := migrationDatabase(t)
	ctx := context.Background()
	began, previous := time.Now(), time.Now()
	heartbeatBoundary := func() {}
	phase := func(name string) {
		now := time.Now()
		t.Logf("phase=%s elapsed=%s total=%s", name, now.Sub(previous), now.Sub(began))
		heartbeatBoundary()
		previous = time.Now()
	}
	plans := f.repo.(store.MigrationPlanRepository)
	pages := f.repo.(store.MigrationPagingRepository)
	id := hashPath(t.Name())[:32]
	t.Cleanup(func() {
		for _, table := range []string{"migration_plan_bindings", "migration_plan_paths", "migration_plan_headers"} {
			f.raw.Exec("DELETE FROM "+table+" WHERE plan_id=?", id)
		}
	})
	additional := 65
	if os.Getenv("FRONTIERCLOUD_TEST_LARGE_MIGRATION") == "1" {
		additional = 10005
	}
	// Real nodes retry transient SQLite writer contention on later heartbeats.
	// Measure those retries and require recovery inside the 120-second health
	// window; other errors and sustained contention still fail this test.
	live, stop := context.WithCancel(ctx)
	joined := make(chan struct{})
	boundaries := make(chan chan struct{})
	var heartbeats, busyRetries int
	var maximumWait, maximumGap time.Duration
	go func() {
		defer close(joined)
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		last := map[string]time.Time{f.rel: time.Now(), strings.Repeat("c", 32): time.Now()}
		for {
			var acknowledged chan struct{}
			select {
			case <-live.Done():
				return
			case acknowledged = <-boundaries:
			case <-ticker.C:
			}
			for _, relationship := range []string{f.rel, strings.Repeat("c", 32)} {
				for {
					started := time.Now()
					err := f.db.Nodes().RecordHeartbeat(live, relationship, true, 1, map[string]any{"capabilities": []string{store.MigrationCapability}, "storage": map[string]any{"physical_free_bytes": 20 * store.GiB}}, time.Now().Unix())
					maximumWait = max(maximumWait, time.Since(started))
					maximumGap = max(maximumGap, time.Since(last[relationship]))
					heartbeats++
					if live.Err() != nil {
						return
					}
					if time.Since(last[relationship]) >= 90*time.Second {
						t.Errorf("heartbeat exceeded recovery budget: %s", time.Since(last[relationship]))
						return
					}
					if err == nil {
						last[relationship] = time.Now()
						break
					}
					var sqliteCode interface{ Code() int }
					if f.db.Backend() != "sqlite" || !errors.As(err, &sqliteCode) || sqliteCode.Code()&255 != 5 || time.Since(last[relationship]) >= 90*time.Second {
						t.Errorf("heartbeat at %s (maximum success gap %s): %v", time.Since(began), maximumGap, err)
						return
					}
					busyRetries++
					timer := time.NewTimer(250 * time.Millisecond)
					select {
					case <-live.Done():
						timer.Stop()
						return
					case <-timer.C:
					}
				}
			}
			if acknowledged != nil {
				close(acknowledged)
			}
		}
	}()
	// Independent operator actions yield to control traffic between phases.
	// The background heartbeats still compete with each real transaction,
	// including the injected rollback; no lock budget is increased for race.
	heartbeatBoundary = func() {
		ack := make(chan struct{})
		select {
		case boundaries <- ack:
		case <-joined:
			t.Fatal("heartbeat worker stopped")
		}
		select {
		case <-ack:
		case <-joined:
			t.Fatal("heartbeat boundary failed")
		}
	}
	defer func() {
		stop()
		<-joined
		t.Logf("heartbeat attempts=%d recoverable_busy=%d longest_SQL_wait=%s largest_success_gap=%s", heartbeats, busyRetries, maximumWait, maximumGap)
	}()

	parent := f.base + "/" + strings.Repeat("long", 155)
	tx, e := f.raw.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	statement, e := tx.PrepareContext(ctx, "INSERT INTO global_media_objects(media_id,storage_member_id,object_id,object_kind,media_path,path_locator,size_bytes,etag,state,created_at,updated_at) VALUES (?,?,?,'audio',?,?,1,?,'active',?,?)")
	if e != nil {
		tx.Rollback()
		t.Fatal(e)
	}
	for i := range additional {
		name := fmt.Sprintf("%s/t%05d.mp3", parent, i)
		logical := hashPath(name)
		if _, e = statement.ExecContext(ctx, logical, f.source, logical, name, hashPath(name), `"`+hashPath("x")+`"`, time.Now().Unix(), time.Now().Unix()); e != nil {
			statement.Close()
			tx.Rollback()
			t.Fatal(e)
		}
	}
	statement.Close()
	if _, e = tx.ExecContext(ctx, "UPDATE cluster_storage_members SET used_bytes=used_bytes+? WHERE member_id=?", additional, f.source); e != nil {
		tx.Rollback()
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	phase("seed")
	p, e := plans.BuildMigrationPlan(ctx, id, f.source, f.target)
	if e != nil || len(p.Catalog.Blockers) != 0 {
		t.Fatal("paged catalog", p.Catalog.Blockers, e)
	}
	if p.ObjectCount != int64(additional+3) || len(p.Catalog.Objects) != 0 || p.UnitCount != 2 {
		t.Fatal("header retained full roster or lost unit", p.ObjectCount, p.UnitCount, len(p.Catalog.Objects))
	}
	phase("catalog")
	var count, serializedBytes int64
	after := ""
	for {
		page, e := plans.MigrationPlanPage(ctx, id, after)
		if e != nil || len(page) > store.MigrationPageObjects {
			t.Fatal("page", e, len(page))
		}
		for _, o := range page {
			if o.ID <= after {
				t.Fatal("unstable object cursor")
			}
			after = o.ID
			count++
			raw, _ := json.Marshal(o)
			serializedBytes += int64(len(raw))
			metadata, e := store.MigrationDigest(store.MediaObject{ID: o.ObjectID, Path: o.Path, Kind: o.Kind, Encryption: o.Encryption})
			if e != nil {
				t.Fatal(e)
			}
			item := store.ExpectedPhysicalItem{ObjectID: o.ObjectID, Path: "media/" + o.Path, MetadataSHA256: metadata, ExpectedBytes: &o.Bytes}
			if e = plans.ObserveMigrationPlanNative(ctx, id, o.Resource, item); e != nil {
				t.Fatal("native roster", e)
			}
			if e = plans.ObserveMigrationPlanProof(ctx, id, store.MigrationDiskProof{ID: o.ID, Version: o.Version, Bytes: o.Bytes, SHA256: strings.Trim(o.ETag, `"`)}); e != nil {
				t.Fatal("content fact", e)
			}
		}
		if len(page) < store.MigrationPageObjects {
			break
		}
	}
	phase("native-and-content-fixture-proofs")
	if count != p.ObjectCount {
		t.Fatal("truncated catalog", count, p.ObjectCount)
	}
	if additional > 10000 && serializedBytes <= store.MaxMigrationPlanBytes {
		t.Fatal("fixture must exceed old JSON limit", serializedBytes)
	}
	conflict, e := plans.MigrationPlanPathConflict(ctx, id, "media", parent+"/foreign.mp3", false)
	if e != nil || !conflict {
		t.Fatal("immediate-parent native conflict missing", e)
	}
	conflict, e = plans.MigrationPlanPathConflict(ctx, id, "media", parent+"/child/new.mp3", false)
	if e != nil || conflict {
		t.Fatal("independent nested unit blocked", e)
	}
	for _, table := range []string{"migration_tasks", "migration_capacity", "migration_scopes", "migration_drains"} {
		var total int
		if e = f.raw.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&total); e != nil || total != 0 {
			t.Fatal("plan changed business admission", table, total, e)
		}
	}
	p.TargetAbsent = true
	p.TargetFree = 20 * store.GiB
	p, e = plans.SealMigrationPlan(ctx, p)
	if e != nil {
		t.Fatal("seal", e)
	}
	phase("seal")
	// A failed admission must leave no capacity, drain or partially created task.
	trigger := "CREATE TRIGGER reject_paged_admission BEFORE UPDATE ON migration_plan_headers WHEN NEW.state='admitted' BEGIN SELECT RAISE(ABORT,'admission unavailable'); END"
	if f.db.Backend() == "mysql" {
		trigger = "CREATE TRIGGER reject_paged_admission BEFORE UPDATE ON migration_plan_headers FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='admission unavailable'"
	}
	if _, e = f.raw.Exec(trigger); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.raw.Exec("DROP TRIGGER IF EXISTS reject_paged_admission") })
	if _, e = f.repo.StartMigration(ctx, p, store.NodeAudit{}); e == nil {
		t.Fatal("admission fault ignored")
	}
	phase("admission-rollback")
	if _, e = f.raw.Exec("DROP TRIGGER reject_paged_admission"); e != nil {
		t.Fatal(e)
	}
	var reserved int64
	f.raw.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", f.target).Scan(&reserved)
	if reserved != 0 {
		t.Fatal("rolled-back admission reserved", reserved)
	}
	task, e := f.repo.StartMigration(ctx, p, store.NodeAudit{})
	if e != nil {
		t.Fatal("start", e)
	}
	phase("admission")
	replay, e := f.repo.StartMigration(ctx, p, store.NodeAudit{})
	if e != nil || replay.ID != task.ID {
		t.Fatal("start replay", e)
	}
	if _, e = plans.BuildMigrationPlan(ctx, id, f.source, f.target); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("admitted immutable plan replaced", e)
	}
	header, e := pages.MigrationHeader(ctx, id)
	if e != nil || header.Task.ObjectCount != count || len(header.Objects) != 0 || len(header.Plan.Catalog.Objects) != 0 {
		t.Fatal("unbounded header", e)
	}
	lease, e := f.repo.ClaimMigration(ctx, id, strings.Repeat("e", 32), time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	// These are target receipt checkpoints for the transaction test. The
	// end-to-end runner tests perform real native writes before these methods.
	if _, e = f.raw.Exec("UPDATE migration_objects SET state='published',target_sha256=source_sha256,verified_bytes=expected_bytes WHERE task_id=?", id); e != nil {
		t.Fatal(e)
	}
	if _, e = f.raw.Exec("UPDATE migration_units SET state='publishing' WHERE task_id=?", id); e != nil {
		t.Fatal(e)
	}
	units, e := pages.MigrationUnitPage(ctx, id, "")
	if e != nil || len(units) != 2 {
		t.Fatal("unit page", e)
	}
	for _, u := range units {
		lease, e = f.repo.RenewMigration(ctx, lease, time.Minute)
		if e != nil {
			t.Fatal(e)
		}
		if e = f.repo.CommitMigrationUnit(ctx, lease, u.ID, store.NodeAudit{}); e != nil {
			t.Fatal("atomic paged unit commit", u.ObjectCount, e)
		}
		phase(fmt.Sprintf("commit-%d-objects", u.ObjectCount))
		if e = f.repo.CommitMigrationUnit(ctx, lease, u.ID, store.NodeAudit{}); e != nil {
			t.Fatal("commit replay", e)
		}
	}
	var targetObjects int64
	if e = f.raw.QueryRow("SELECT COUNT(*) FROM global_media_objects WHERE storage_member_id=?", f.target).Scan(&targetObjects); e != nil || targetObjects != count {
		t.Fatal("whole unit ownership", targetObjects, count, e)
	}
	f.raw.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", f.target).Scan(&reserved)
	if reserved != 0 {
		t.Fatal("capacity did not reconcile", reserved)
	}
	page, e := pages.MigrationObjectPage(ctx, id, "", "")
	if e != nil || len(page) != 64 {
		t.Fatal("execution page", len(page), e)
	}
	logical := page[0].Object.ID
	if _, e = f.raw.Exec("UPDATE migration_plan_bindings SET object_sha256=? WHERE plan_id=? AND logical_id=?", strings.Repeat("0", 64), id, logical); e != nil {
		t.Fatal(e)
	}
	if _, e = pages.MigrationObject(ctx, id, logical); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("corrupted immutable object binding accepted", e)
	}
	stop()
	<-joined
	for _, relationship := range []string{f.rel, strings.Repeat("c", 32)} {
		if err := f.db.Nodes().RecordHeartbeat(ctx, relationship, true, 1, map[string]any{"capabilities": []string{store.MigrationCapability}, "storage": map[string]any{"physical_free_bytes": 20 * store.GiB}}, time.Now().Unix()); err != nil {
			t.Fatal("final heartbeat did not recover", err)
		}
	}
	t.Log("both final heartbeats succeeded after all writer transactions")
	t.Logf("paged objects=%d immutable JSON bytes=%d page limit=%d", count, serializedBytes, store.MigrationPageObjects)
}
