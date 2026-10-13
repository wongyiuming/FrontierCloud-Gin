package business_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
)

// This regression counts actual SQL statements and immutable rows decoded by
// repository shadow authorization. It supplies isolated receipt/proof fixtures;
// physical deletion and source-byte verification remain native HTTP tests.
type migrationScaleSQL struct{ queries, bindings atomic.Int64 }
type migrationScaleConnector struct {
	underlying driver.Driver
	dsn        string
	count      *migrationScaleSQL
}

func (c migrationScaleConnector) Driver() driver.Driver { return c.underlying }
func (c migrationScaleConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, e := c.underlying.Open(c.dsn)
	if e != nil {
		return nil, e
	}
	return &migrationScaleConn{Conn: conn, count: c.count}, nil
}

type migrationScaleConn struct {
	driver.Conn
	count *migrationScaleSQL
}

func (c *migrationScaleConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.count.queries.Add(1)
	rows, e := c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
	if e != nil {
		return nil, e
	}
	return &migrationScaleRows{Rows: rows, count: c.count, bindings: strings.Contains(query, "object_json") || strings.Contains(query, "binding_json")}, nil
}
func (c *migrationScaleConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.count.queries.Add(1)
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args)
}

type migrationScaleRows struct {
	driver.Rows
	count    *migrationScaleSQL
	bindings bool
}

func (r *migrationScaleRows) Next(values []driver.Value) error {
	e := r.Rows.Next(values)
	if e == nil && r.bindings {
		r.count.bindings.Add(1)
	}
	return e
}
func migrationScaleRepository(t *testing.T, raw *sql.DB) (*business.Repository, *migrationScaleSQL) {
	t.Helper()
	var seq int
	var name, file string
	if e := raw.QueryRow("PRAGMA database_list").Scan(&seq, &name, &file); e != nil || name != "main" || file == "" {
		t.Fatal("isolated SQLite path", name, e)
	}
	uriPath := filepath.ToSlash(file)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath}
	u.RawQuery = url.Values{"mode": {"rw"}, "_busy_timeout": {"5000"}, "_synchronous": {"NORMAL"}}.Encode()
	count := &migrationScaleSQL{}
	db := sql.OpenDB(migrationScaleConnector{underlying: raw.Driver(), dsn: u.String(), count: count})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return business.New(db, "sqlite"), count
}

func TestResourceMigrationPublishedShadowGrantScaling(t *testing.T) {
	if os.Getenv("FRONTIERCLOUD_TEST_SHADOW_SCALE") != "1" {
		t.Skip("explicit SQLite bounded SQL-growth and fault-recovery regression")
	}
	var smallQueries int64
	for _, size := range []int{128, 1024} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			f := migrationDatabase(t)
			if f.db.Backend() != "sqlite" {
				t.Skip("SQL instrumentation uses the isolated SQLite driver")
			}
			ctx := context.Background()
			for i := 3; i < size; i++ {
				name := fmt.Sprintf("%s/extra%04d.mp3", f.base, i)
				id := hashPath(name)
				if _, e := f.raw.Exec("INSERT INTO global_media_objects(media_id,storage_member_id,object_id,object_kind,media_path,path_locator,size_bytes,etag,state,created_at,updated_at) VALUES (?,?,?,'audio',?,?,1,?,'active',?,?)", id, f.source, id, name, id, hashPath("x"), time.Now().Unix(), time.Now().Unix()); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := f.raw.Exec("UPDATE cluster_storage_members SET used_bytes=used_bytes+? WHERE member_id=?", size-3, f.source); e != nil {
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
			var sample []store.MigrationPeerObject
			after := ""
			for {
				page, e := plans.MigrationPlanPage(ctx, id, after)
				if e != nil {
					t.Fatal(e)
				}
				for _, o := range page {
					metadata, e := store.MigrationNativeMetadataSHA(o, f.source)
					if e != nil {
						t.Fatal(e)
					}
					if e = plans.ObserveMigrationPlanNative(ctx, id, o.Resource, store.ExpectedPhysicalItem{ObjectID: o.ObjectID, Path: "media/" + o.Path, ExpectedBytes: &o.Bytes, MetadataSHA256: metadata}); e != nil {
						t.Fatal(e)
					}
					proof := store.MigrationDiskProof{ID: o.ID, Version: o.Version, Bytes: o.Bytes, SHA256: strings.Trim(o.ETag, `"`)}
					if e = plans.ObserveMigrationPlanProof(ctx, id, proof); e != nil {
						t.Fatal(e)
					}
					if len(sample) < 8 {
						sample = append(sample, store.MigrationPeerObject{Object: o, Proof: proof})
					}
					after = o.ID
				}
				if len(page) < store.MigrationPageObjects {
					break
				}
			}
			p.TargetAbsent, p.TargetFree = true, 20*store.GiB
			p, e = plans.SealMigrationPlan(ctx, p)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = f.repo.StartMigration(ctx, p, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			if _, e = f.raw.Exec("UPDATE migration_objects SET state='published',target_sha256=source_sha256,verified_bytes=expected_bytes WHERE task_id=?", id); e != nil {
				t.Fatal(e)
			}
			if _, e = f.raw.Exec("UPDATE migration_units SET state='publishing' WHERE task_id=?", id); e != nil {
				t.Fatal(e)
			}
			if _, e = f.repo.ControlMigration(ctx, id, "cancel", store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			lease, e := f.repo.ClaimMigration(ctx, id, strings.Repeat("e", 32), time.Minute)
			if e != nil {
				t.Fatal(e)
			}
			repo, count := migrationScaleRepository(t, f.raw)
			began := time.Now()
			for _, v := range sample {
				g, e := repo.AuthorizeMigrationShadowDeletion(ctx, lease, v.Object.ID, store.MigrationCleanupProof{MigrationDiskProof: v.Proof, VerifiedAt: time.Now().Unix()})
				if e != nil || g.Unit.Unit.ObjectCount != int64(size) {
					t.Fatal("shadow authorization", g.Unit.Unit.ObjectCount, e)
				}
			}
			t.Logf("master unit_objects=%d grants=%d SQL_statements=%d immutable_binding_rows=%d elapsed=%s", size, len(sample), count.queries.Load(), count.bindings.Load(), time.Since(began))
			measured := count.queries.Load()
			if measured > 400 || count.bindings.Load() > int64(len(sample)*2) {
				t.Fatal("per-object authorization scanned sibling bindings", measured, count.bindings.Load())
			}
			if size == 128 {
				smallQueries = measured
			} else if measured > smallQueries+8 {
				t.Fatal("SQL grew with unit size", smallQueries, measured)
			}
			migrationMasterShadowRecovery(t, f, lease, sample)

		})
	}
}

func TestPeerMigrationPublishedShadowGrantScaling(t *testing.T) {
	if os.Getenv("FRONTIERCLOUD_TEST_SHADOW_SCALE") != "1" {
		t.Skip("explicit SQLite bounded SQL-growth and fault-recovery regression")
	}
	var smallQueries int64
	for _, size := range []int{128, 1024} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			db, raw, repo, rel, h, l, template := peerMigrationFixture(t, false)
			if db.Backend() != "sqlite" {
				t.Skip("SQL instrumentation uses the isolated SQLite driver")
			}
			ctx := context.Background()
			h.ObjectCount, h.Bytes = int64(size), int64(size)*template.Object.Bytes
			if e := repo.RegisterPeerMigration(ctx, rel, h, l, "queued", 20*store.GiB, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			var sample []store.MigrationPeerObject
			for i := range size {
				v := template
				v.Object.ID = fmt.Sprintf("%064x", i+1)
				v.Object.ObjectID = v.Object.ID
				v.Object.Path = fmt.Sprintf("%s/extra%04d.mp3", v.Object.Parent, i)
				v.Object.TargetPath = v.Object.Path
				v.Proof.ID = v.Object.ID
				if e := repo.RegisterPeerMigrationObject(ctx, rel, l, v, store.NodeAudit{}); e != nil {
					t.Fatal(e)
				}
				if len(sample) < 8 {
					sample = append(sample, v)
				}
			}
			if _, e := raw.Exec("UPDATE migration_storage_journal SET state='published' WHERE task_id=?", h.TaskID); e != nil {
				t.Fatal(e)
			}
			l.Epoch++
			l.ExpiresAt = time.Now().Unix() + 60
			if e := repo.RegisterPeerMigration(ctx, rel, h, l, "cancelling", 20*store.GiB, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			// Reconstruct the exact sorted immutable transcript from this fixture.
			var sequence store.MigrationSequence
			for i := range size {
				v := template
				v.Object.ID = fmt.Sprintf("%064x", i+1)
				v.Object.ObjectID = v.Object.ID
				v.Object.Path = fmt.Sprintf("%s/extra%04d.mp3", v.Object.Parent, i)
				v.Object.TargetPath = v.Object.Path
				v.Proof.ID = v.Object.ID
				if e := sequence.Add(v.Object.ID, v); e != nil {
					t.Fatal(e)
				}
			}
			unit := store.MigrationUnitFinishGrant{Header: h, Unit: store.MigrationUnit{ID: hashPath(template.Object.Resource + ":" + template.Object.Parent), Resource: template.Object.Resource, Parent: template.Object.Parent, State: "cancelled", ObjectCount: int64(size), Bytes: h.Bytes}, UnitVersion: sequence.Sum(), ObjectsSHA: sequence.Sum()}
			first := store.MigrationShadowGrant{Unit: unit, Object: sample[0].Object, SourceProof: store.MigrationCleanupProof{MigrationDiskProof: sample[0].Proof, VerifiedAt: time.Now().Unix()}}
			// A fault after roster verification must roll the durable seal back.
			if _, e := raw.Exec("CREATE TRIGGER reject_shadow_seal BEFORE UPDATE ON migration_storage_journal WHEN NEW.state='deleting' BEGIN SELECT RAISE(ABORT,'shadow fault'); END"); e != nil {
				t.Fatal(e)
			}
			if e := repo.PreparePeerMigrationShadowDeletion(ctx, rel, l, first, store.NodeAudit{}); e == nil {
				t.Fatal("shadow admission fault ignored")
			}
			if _, e := raw.Exec("DROP TRIGGER reject_shadow_seal"); e != nil {
				t.Fatal(e)
			}
			var seals int
			if e := raw.QueryRow("SELECT COUNT(*) FROM migration_units WHERE task_id=?", h.TaskID).Scan(&seals); e != nil || seals != 0 {
				t.Fatal("partial root survived rollback", seals, e)
			}
			forged := first
			forged.Unit.UnitVersion, forged.Unit.ObjectsSHA = hashPath("forged"), hashPath("forged")
			if e := repo.PreparePeerMigrationShadowDeletion(ctx, rel, l, forged, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
				t.Fatal("unverified root accepted", e)
			}
			admitted, initialCount := migrationScaleRepository(t, raw)
			if e := admitted.PreparePeerMigrationShadowDeletion(ctx, rel, l, first, store.NodeAudit{}); e != nil {
				t.Fatal("first complete roster admission", e)
			}
			if initialCount.bindings.Load() != int64(size+1) {
				t.Fatal("first authorization did not inspect complete roster", initialCount.bindings.Load())
			}
			// A new repository/connection cannot depend on a process cache.
			counted, count := migrationScaleRepository(t, raw)
			began := time.Now()
			for _, v := range sample {
				g := store.MigrationShadowGrant{Unit: unit, Object: v.Object, SourceProof: store.MigrationCleanupProof{MigrationDiskProof: v.Proof, VerifiedAt: time.Now().Unix()}}
				if e := counted.PreparePeerMigrationShadowDeletion(ctx, rel, l, g, store.NodeAudit{}); e != nil {
					t.Fatal(e)
				}
			}
			t.Logf("target unit_objects=%d grants=%d SQL_statements=%d immutable_binding_rows=%d elapsed=%s", size, len(sample), count.queries.Load(), count.bindings.Load(), time.Since(began))
			measured := count.queries.Load()
			if measured > 240 || count.bindings.Load() != int64(len(sample)) {
				t.Fatal("target rescanned sealed sibling roster", measured, count.bindings.Load())
			}
			if size == 128 {
				smallQueries = measured
			} else if measured > smallQueries+8 {
				t.Fatal("target SQL grew with unit size", smallQueries, measured)
			}
			migrationPeerShadowRecovery(t, raw, counted, rel, h, l, unit, sample)

		})
	}
}

func migrationMasterShadowRecovery(t *testing.T, f *migrationFixture, old store.MigrationLease, sample []store.MigrationPeerObject) {
	t.Helper()
	ctx := context.Background()
	reopened, _ := migrationScaleRepository(t, f.raw)
	if e := reopened.ReleaseMigration(ctx, old); e != nil {
		t.Fatal(e)
	}
	lease, e := reopened.ClaimMigration(ctx, old.TaskID, strings.Repeat("f", 32), time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	v := sample[0]
	proof := store.MigrationCleanupProof{MigrationDiskProof: v.Proof, VerifiedAt: time.Now().Unix()}
	if _, e = reopened.AuthorizeMigrationShadowDeletion(ctx, old, v.Object.ID, proof); e == nil {
		t.Fatal("old actor revived after reopening")
	}
	for _, alter := range []func(*store.MigrationCleanupProof){func(p *store.MigrationCleanupProof) { p.VerifiedAt -= 31 }, func(p *store.MigrationCleanupProof) { p.SHA256 = hashPath("wrong-bytes") }, func(p *store.MigrationCleanupProof) { p.Version = hashPath("wrong-version") }} {
		wrong := proof
		alter(&wrong)
		if _, e = reopened.AuthorizeMigrationShadowDeletion(ctx, lease, v.Object.ID, wrong); !errors.Is(e, store.ErrMigrationState) {
			t.Fatal("wrong proof accepted", e)
		}
	}
	for _, change := range []struct {
		column   string
		old, bad any
	}{{"storage_member_id", f.source, f.target}, {"etag", v.Object.ETag, "changed-etag"}} {
		if _, e = f.raw.Exec("UPDATE global_media_objects SET "+change.column+"=? WHERE media_id=?", change.bad, v.Object.ID); e != nil {
			t.Fatal(e)
		}
		if _, e = reopened.MigrationCancellationObjectGrant(ctx, lease, v.Object.ID); e == nil {
			t.Fatal("changed current source authority accepted", change.column)
		}
		if _, e = f.raw.Exec("UPDATE global_media_objects SET "+change.column+"=? WHERE media_id=?", change.old, v.Object.ID); e != nil {
			t.Fatal(e)
		}
	}
	bounded, e := reopened.MigrationCancellationObjectGrant(ctx, lease, v.Object.ID)
	if e != nil {
		t.Fatal(e)
	}
	full, e := reopened.MigrationUnitCancelGrant(ctx, lease, bounded.Unit.ID)
	if e != nil {
		t.Fatal(e)
	}
	a, _ := store.MigrationDigest(bounded)
	b, _ := store.MigrationDigest(full)
	if a != b || full.ObjectsSHA != full.UnitVersion {
		t.Fatal("bounded grant lost admitted sorted roster")
	}
	// Corruption outside the eight inspected objects must still prevent terminal
	// reconciliation, even though other exact objects can be retried safely.
	var sibling, sha string
	if e = f.raw.QueryRow("SELECT logical_id,object_sha256 FROM migration_plan_bindings WHERE plan_id=? ORDER BY logical_id DESC LIMIT 1", lease.TaskID).Scan(&sibling, &sha); e != nil {
		t.Fatal(e)
	}
	if _, e = f.raw.Exec("UPDATE migration_plan_bindings SET object_sha256=? WHERE plan_id=? AND logical_id=?", hashPath("corrupt"), lease.TaskID, sibling); e != nil {
		t.Fatal(e)
	}
	if _, e = reopened.MigrationUnitCancelGrant(ctx, lease, full.Unit.ID); e == nil {
		t.Fatal("terminal whole roster check omitted corrupted sibling")
	}
	if _, e = f.raw.Exec("UPDATE migration_plan_bindings SET object_sha256=? WHERE plan_id=? AND logical_id=?", sha, lease.TaskID, sibling); e != nil {
		t.Fatal(e)
	}
	source := store.MigrationUnitFinishReceipt{Grant: full, MemberID: f.source, Complete: true}
	target := store.MigrationUnitFinishReceipt{Grant: full, MemberID: f.target, Complete: true}
	for range 2 {
		if e = reopened.CompleteMigrationUnitCancellation(ctx, lease, source, target, store.NodeAudit{}); e != nil {
			t.Fatal("terminal cancellation/replay", e)
		}
	}
	if _, e = reopened.AuthorizeMigrationShadowDeletion(ctx, lease, v.Object.ID, proof); e == nil {
		t.Fatal("cancelled unit authorized new deletion")
	}
	var reserved int64
	if e = f.raw.QueryRow("SELECT reserved_bytes FROM cluster_storage_members WHERE member_id=?", f.target).Scan(&reserved); e != nil || reserved != 0 {
		t.Fatal("master cancellation refund", reserved, e)
	}
}

func migrationPeerShadowRecovery(t *testing.T, raw *sql.DB, repo *business.Repository, rel string, h store.MigrationPeerHeader, old store.MigrationLease, unit store.MigrationUnitFinishGrant, sample []store.MigrationPeerObject) {
	t.Helper()
	ctx := context.Background()
	v := sample[0]
	lease := old
	lease.Epoch++
	lease.ExpiresAt = time.Now().Unix() + 60
	if e := repo.RegisterPeerMigration(ctx, rel, h, lease, "cancelling", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	g := store.MigrationShadowGrant{Unit: unit, Object: v.Object, SourceProof: store.MigrationCleanupProof{MigrationDiskProof: v.Proof, VerifiedAt: time.Now().Unix()}}
	if e := repo.PreparePeerMigrationShadowDeletion(ctx, rel, old, g, store.NodeAudit{}); e == nil {
		t.Fatal("superseded peer actor accepted")
	}
	if e := repo.FailPeerMigrationShadowCleanup(ctx, rel, lease, v.Object.ID, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	reopened, _ := migrationScaleRepository(t, raw)
	stale := g
	stale.SourceProof.VerifiedAt -= 31
	if e := reopened.PreparePeerMigrationShadowDeletion(ctx, rel, lease, stale, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("stale proof revived failed deletion", e)
	}
	if failed, e := reopened.PeerMigrationShadowCleanupFailed(ctx, rel, lease, v.Object.ID); e != nil || !failed {
		t.Fatal("lost failure fence after reopen", e)
	}
	for _, alter := range []func(*store.MigrationShadowGrant){func(g *store.MigrationShadowGrant) { g.Unit.ObjectsSHA = hashPath("wrong-root") }, func(g *store.MigrationShadowGrant) { g.Object.Path = "music/changed.mp3" }, func(g *store.MigrationShadowGrant) { g.Unit.Unit.CommittedAt = 1 }, func(g *store.MigrationShadowGrant) { g.SourceProof.SHA256 = hashPath("wrong-proof") }} {
		wrong := g
		alter(&wrong)
		if e := reopened.PreparePeerMigrationShadowDeletion(ctx, rel, lease, wrong, store.NodeAudit{}); e == nil {
			t.Fatal("wrong sealed object grant accepted")
		}
	}
	if e := reopened.PreparePeerMigrationShadowDeletion(ctx, rel, lease, g, store.NodeAudit{}); e != nil {
		t.Fatal("fresh retry", e)
	}
	if failed, e := reopened.PeerMigrationShadowCleanupFailed(ctx, rel, lease, v.Object.ID); e != nil || failed {
		t.Fatal("fresh proof did not clear failure", e)
	}
	if _, e := reopened.CompletePeerMigrationUnitCancellation(ctx, rel, lease, unit, store.NodeAudit{}); e == nil {
		t.Fatal("unprocessed siblings accepted as complete")
	}
	// Only terminal receipt fixtures are supplied here. Native tests exercise
	// physical abort/delete and used-capacity refund before these states exist.
	if _, e := raw.Exec("UPDATE migration_storage_journal SET state='deleted' WHERE task_id=?", h.TaskID); e != nil {
		t.Fatal(e)
	}
	var sibling, sha string
	if e := raw.QueryRow("SELECT logical_id,binding_sha256 FROM migration_peer_bindings WHERE task_id=? ORDER BY logical_id DESC LIMIT 1", h.TaskID).Scan(&sibling, &sha); e != nil {
		t.Fatal(e)
	}
	if _, e := raw.Exec("UPDATE migration_peer_bindings SET binding_sha256=? WHERE task_id=? AND logical_id=?", hashPath("bad-sibling"), h.TaskID, sibling); e != nil {
		t.Fatal(e)
	}
	if _, e := reopened.CompletePeerMigrationUnitCancellation(ctx, rel, lease, unit, store.NodeAudit{}); e == nil {
		t.Fatal("terminal validation skipped sealed sibling")
	}
	if _, e := raw.Exec("UPDATE migration_peer_bindings SET binding_sha256=? WHERE task_id=? AND logical_id=?", sha, h.TaskID, sibling); e != nil {
		t.Fatal(e)
	}
	for range 2 {
		receipt, e := reopened.CompletePeerMigrationUnitCancellation(ctx, rel, lease, unit, store.NodeAudit{})
		if e != nil || !receipt.Complete {
			t.Fatal("recovered terminal receipt/replay", e)
		}
	}
	if e := reopened.PreparePeerMigrationShadowDeletion(ctx, rel, lease, g, store.NodeAudit{}); e == nil {
		t.Fatal("terminal unit admitted new shadow work")
	}
}
