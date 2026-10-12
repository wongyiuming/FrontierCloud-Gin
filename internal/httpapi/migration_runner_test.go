package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourcemigration"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type migrationReadWriter struct {
	*httptest.ResponseRecorder
	started chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (w *migrationReadWriter) Write(b []byte) (int, error) {
	w.once.Do(func() { close(w.started); <-w.resume })
	return w.ResponseRecorder.Write(b)
}

type runnerFaultCaller struct {
	client                    *node.Service
	lost                      bool
	lostCleanup               bool
	lostUnit                  bool
	lostTask                  bool
	lostAbort                 bool
	lostCancelUnit            bool
	lostCancelTask            bool
	lostShadow                bool
	lostUnpublish             bool
	stopPublishing            func() bool
	losePublicationCheckpoint func()
	blockBegin                func() bool
	reads                     map[int64]int
}

func (c *runnerFaultCaller) Call(ctx context.Context, rel store.Relationship, path string, value any) (map[string]any, error) {
	if strings.HasSuffix(path, "/begin") && c.blockBegin != nil && c.blockBegin() {
		return nil, errors.New("injected stop after committed unit")
	}
	if strings.HasSuffix(path, "/read") {
		raw, _ := json.Marshal(value)
		var request migrationdata.Request
		if json.Unmarshal(raw, &request) == nil {
			c.reads[request.Offset]++
		}
	}
	result, e := c.client.Call(ctx, rel, path, value)
	if e == nil && c.losePublicationCheckpoint != nil && strings.HasSuffix(path, "/status") && result["peer_state"] == "published" {
		c.losePublicationCheckpoint()
		c.losePublicationCheckpoint = nil
		return nil, errors.New("injected SQL receipt saved without final byte checkpoint")
	}
	if e == nil && c.stopPublishing != nil && strings.HasSuffix(path, "/status") && result["peer_state"] == "verified" {
		raw, _ := json.Marshal(result["checkpoint"])
		var cp migrationdata.Checkpoint
		if json.Unmarshal(raw, &cp) == nil && cp.State == "publishing" && c.stopPublishing() {
			return nil, errors.New("injected stop after link before SQL receipt")
		}
	}
	if e == nil && c.lostUnpublish && strings.HasSuffix(path, "/unpublish") && result["state"] == "publication_aborted" {
		c.lostUnpublish = false
		return nil, errors.New("injected lost publication abort receipt")
	}
	if e == nil && c.lost && strings.HasSuffix(path, "/append") {
		c.lost = false
		return nil, errors.New("injected lost append acknowledgement")
	}
	if e == nil && c.lostCleanup && strings.HasSuffix(path, "/cleanup") && result["state"] == "source_deleted" {
		c.lostCleanup = false
		return nil, errors.New("injected lost source deletion receipt")
	}
	if e == nil && c.lostUnit && strings.HasSuffix(path, "/finish-unit") {
		c.lostUnit = false
		return nil, errors.New("injected lost unit completion receipt")
	}
	if e == nil && c.lostTask && strings.HasSuffix(path, "/finish-task") {
		c.lostTask = false
		return nil, errors.New("injected lost task completion receipt")
	}
	for _, fault := range []struct {
		flag   *bool
		suffix string
	}{{&c.lostAbort, "/abort"}, {&c.lostCancelUnit, "/cancel-unit"}, {&c.lostCancelTask, "/cancel-task"}} {
		if e == nil && *fault.flag && strings.HasSuffix(path, fault.suffix) {
			*fault.flag = false
			return nil, errors.New("injected lost cancellation acknowledgement")
		}
	}
	if e == nil && c.lostShadow && strings.HasSuffix(path, "/shadow") && result["state"] == "shadow_deleted" {
		c.lostShadow = false
		return nil, errors.New("injected lost target shadow receipt")
	}
	return result, e
}

func TestMasterMigrationRunnerRealBytesRestartAndAtomicUnitRetry(t *testing.T) {
	masterMigrationRunnerFixture(t, false)
}
func TestMasterMigrationCancellationRealPrefixAndLostFinalReceipts(t *testing.T) {
	masterMigrationRunnerFixture(t, true)
}
func TestMasterMigrationPartialCommitCancellationPreservesBothOwners(t *testing.T) {
	masterMigrationRunnerFixture(t, false, "mixed")
}
func TestMasterMigrationShadowGrantRequiresCurrentSourceBytes(t *testing.T) {
	masterMigrationRunnerFixture(t, false, "shadowproof")
}
func TestMasterMigrationPublishedShadowCancellationLostReceipts(t *testing.T) {
	masterMigrationRunnerFixture(t, false, "shadowcleanup")
}
func TestMasterMigrationInterruptedPublicationCancellation(t *testing.T) {
	masterMigrationRunnerFixture(t, false, "unpublish")
}

// This isolated fault restores only the prior publishing state; all immutable
// bindings, prefix proofs and real business bytes/SQL accounting are retained.
func loseMigrationPublicationCheckpoint(t *testing.T, root string) {
	t.Helper()
	entries, e := os.ReadDir(root)
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".migration-data-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		name := filepath.Join(root, entry.Name())
		raw, e := os.ReadFile(name)
		if e != nil {
			t.Fatal(e)
		}
		var record map[string]any
		if e = json.Unmarshal(raw, &record); e != nil {
			t.Fatal(e)
		}
		if record["state"] != "published" {
			continue
		}
		record["state"] = "publishing"
		raw, e = json.Marshal(record)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(name, raw, 0600); e != nil {
			t.Fatal(e)
		}
		return
	}
	t.Fatal("missing actual published checkpoint for fault injection")
}
func TestMasterMigrationAccountedPublicationCheckpointRecovery(t *testing.T) {
	masterMigrationRunnerFixture(t, false, "checkpoint")
}
func masterMigrationRunnerFixture(t *testing.T, cancelTask bool, modes ...string) {
	mixed := len(modes) > 0 && modes[0] == "mixed"
	unpublish := len(modes) > 0 && modes[0] == "unpublish"
	checkpoint := len(modes) > 0 && modes[0] == "checkpoint"
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	_, db, _, _, master := clusterFixture(t, "https://master.test", transport, true)
	_, sourceDB, sourceDir, _, source := clusterFixture(t, "https://source.test", transport, true)
	_, targetDB, targetDir, _, target := clusterFixture(t, "https://target.test", transport, true)
	for _, v := range []struct {
		s          *node.Service
		role, url  string
		allocation int64
	}{{master, "Master", "https://master.test", store.GiB}, {source, "Follower", "https://source.test", 0}, {target, "Follower", "https://target.test", 0}} {
		if _, e := v.s.Promote(ctx, v.role, v.url, v.allocation, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
	}
	pair, e := source.CreatePair(ctx, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	srid, e := master.ImportPair(ctx, pair, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	pair, e = target.CreatePair(ctx, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	trid, e := master.ImportPair(ctx, pair, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{srid, trid} {
		rel, _ := db.Nodes().Relationship(ctx, id)
		cfg := store.ResourceConfiguration{}
		cfg.Storage.Enabled = true
		cfg.Storage.Allocation = 5 * store.GiB
		if e = db.Pool().ConfigureMember(ctx, rel.PeerID, cfg, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
		if id == srid {
			if e = db.Nodes().SetRelationshipMode(ctx, id, "Direct", false, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
		}
		rel, _ = db.Nodes().Relationship(ctx, id)
		if e = master.Tick(ctx, rel); e != nil {
			t.Fatal(e)
		}
	}
	sr, _ := db.Nodes().Relationship(ctx, srid)
	tr, _ := db.Nodes().Relationship(ctx, trid)
	payloads := map[string][]byte{}
	ids := []string{}
	names := []string{"music/RunnerUnit/a.mp3", "music/RunnerUnit/b.mp3"}
	if mixed {
		names = append(names, "music/OtherUnit/c.mp3")
	}
	for i, name := range names {
		payload := bytes.Repeat([]byte{byte(0x51 + i)}, migrationdata.ChunkBytes+31+i)
		copy(payload, []byte("ID3"))
		payloads[name] = payload
		u, e := db.Pool().ReserveUpload(ctx, name, "direct", int64(len(payload)), 10*store.GiB, store.AdminAudit{})
		if e != nil {
			t.Fatal(e)
		}
		receipt, e := master.UploadStorage(ctx, u, bytes.NewReader(payload))
		if e != nil {
			t.Fatal(e)
		}
		object, _ := receipt["object_id"].(string)
		etag, _ := receipt["etag"].(string)
		if _, e = db.Pool().FinalizeUpload(ctx, u.ID, object, u.ExpectedBytes, etag, store.AdminAudit{}); e != nil {
			t.Fatal(e)
		}
		ids = append(ids, u.MediaID)
	}
	// Hold an actual native Go response open before any migration is registered.
	// The follower must already expose its durable physical read dependency.
	first, e := db.Pool().Resource(ctx, ids[0])
	if e != nil {
		t.Fatal(e)
	}
	token, e := master.MediaCapability(ctx, srid, first.MemberID, first.ObjectID, first.ID, strings.Repeat("1", 32), strings.Repeat("2", 32))
	if e != nil {
		t.Fatal(e)
	}
	w := &migrationReadWriter{ResponseRecorder: httptest.NewRecorder(), started: make(chan struct{}), resume: make(chan struct{})}
	req := httptest.NewRequest("GET", "https://source.test/internal/v1/media/"+first.ObjectID, nil)
	req.Header.Set("X-Media-Capability", token)
	done := make(chan struct{})
	go func() { defer close(done); transport.routers["https://source.test"].ServeHTTP(w, req) }()
	var resumeOnce sync.Once
	resume := func() { resumeOnce.Do(func() { close(w.resume) }) }
	defer resume()
	select {
	case <-w.started:
	case <-time.After(10 * time.Second):
		t.Fatal("native read did not start")
	}
	var liveReads int
	if e = sourceDB.Database().QueryRow("SELECT COUNT(*) FROM migration_read_leases WHERE member_id=? AND object_id=? AND expires_at>?", sr.PeerID, first.ObjectID, time.Now().Unix()).Scan(&liveReads); e != nil || liveReads != 1 {
		t.Fatal("stream missing durable read lease", liveReads, e)
	}
	resume()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("native read did not finish")
	}
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), payloads[first.Path]) {
		t.Fatal("native stream bytes", w.Code)
	}
	if e = sourceDB.Database().QueryRow("SELECT COUNT(*) FROM migration_read_leases WHERE member_id=?", sr.PeerID).Scan(&liveReads); e != nil || liveReads != 0 {
		t.Fatal("completed stream retained lease", liveReads, e)
	}
	if e = db.Media().SetHidden(ctx, []string{"music/RunnerUnit/a.mp3"}, true, store.AdminAudit{}); e != nil {
		t.Fatal(e)
	}
	// This isolated fixture explicitly opts into the unfinished capability;
	// production heartbeat still does not advertise full migration support.
	for _, id := range []string{srid, trid} {
		if e = db.Nodes().RecordHeartbeat(ctx, id, true, 1, map[string]any{"capabilities": []string{"storage-v2", store.MigrationCapability}, "storage": map[string]any{"physical_free_bytes": 20 * store.GiB}}, time.Now().Unix()); e != nil {
			t.Fatal(e)
		}
	}
	repo := db.Pool().(store.MigrationRepository)
	catalog, e := repo.MigrationCatalog(ctx, sr.PeerID, tr.PeerID)
	if e != nil || len(catalog.Blockers) != 0 {
		t.Fatal(catalog.Blockers, e)
	}
	plan := store.MigrationPlan{ID: strings.Repeat("e", 32), Catalog: catalog, TargetAbsent: true, TargetFree: 20 * store.GiB, CreatedAt: time.Now().Unix(), ExpiresAt: time.Now().Unix() + 120}
	for _, o := range catalog.Objects {
		sum := sha256.Sum256(payloads[o.Path])
		plan.Proofs = append(plan.Proofs, store.MigrationDiskProof{ID: o.ID, Version: o.Version, Bytes: o.Bytes, SHA256: hex.EncodeToString(sum[:])})
	}
	if _, e = repo.StartMigration(ctx, plan, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	fault := &runnerFaultCaller{client: master, lost: true, reads: map[int64]int{}}
	engine := &resourcemigration.Runner{Repository: repo, Nodes: db.Nodes(), Client: fault}
	if mixed {
		fault.lost = false
		fault.blockBegin = func() bool { task, e := repo.MigrationTask(ctx, plan.ID); return e == nil && task.CommittedBytes > 0 }
		if e = engine.Run(ctx, plan.ID, strings.Repeat("a", 32)); e == nil {
			t.Fatal("partial commit fault ignored")
		}
		before, e := repo.MigrationWork(ctx, plan.ID)
		if e != nil {
			t.Fatal(e)
		}
		if before.Task.CommittedBytes <= 0 || before.Task.CommittedBytes >= before.Task.TotalBytes {
			t.Fatal("fixture not partially committed", before.Task)
		}
		owners := map[string]string{}
		for _, cp := range before.Objects {
			resource, e := db.Pool().Resource(ctx, cp.Object.ID)
			if e != nil {
				t.Fatal(e)
			}
			owners[cp.Object.ID] = resource.MemberID
		}
		if _, e = repo.ControlMigration(ctx, plan.ID, "cancel", store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
		if e = engine.Run(ctx, plan.ID, strings.Repeat("b", 32)); e != nil {
			t.Fatal("uncommitted unit cancel during grace", e)
		}
		if id, e := repo.NextMigrationRun(ctx); e != nil || id != "" {
			t.Fatal("committed cleanup scheduled before grace", id, e)
		}
		// Advance this isolated fixture only; no production grace bypass exists.
		now := time.Now().Unix()
		if _, e = db.Database().Exec("UPDATE migration_units SET committed_at=?,cleanup_after=? WHERE task_id=? AND committed_at>0", now-3601, now-1, plan.ID); e != nil {
			t.Fatal(e)
		}
		if id, e := repo.NextMigrationRun(ctx); e != nil || id != plan.ID {
			t.Fatal("due cancellation cleanup not scheduled", id, e)
		}
		fault.lostCleanup = true
		if e = engine.Run(ctx, plan.ID, strings.Repeat("c", 32)); e == nil {
			t.Fatal("lost committed source cleanup receipt ignored")
		}
		if _, e = repo.ControlMigration(ctx, plan.ID, "retry", store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
		if e = engine.Run(ctx, plan.ID, strings.Repeat("d", 32)); e != nil {
			t.Fatal("mixed cancellation recovery", e)
		}
		final, e := repo.MigrationWork(ctx, plan.ID)
		if e != nil || final.Task.State != "cancelled" || final.Task.CommittedBytes != before.Task.CommittedBytes {
			t.Fatal(final.Task, e)
		}
		for _, cp := range final.Objects {
			resource, e := db.Pool().Resource(ctx, cp.Object.ID)
			if e != nil || resource.MemberID != owners[cp.Object.ID] {
				t.Fatal("cancellation reversed owner", resource, e)
			}
			reader, e := master.ReadGlobalMedia(ctx, resource)
			if e != nil {
				t.Fatal(e)
			}
			got, e := io.ReadAll(reader)
			reader.Close()
			if e != nil || !bytes.Equal(got, payloads[resource.Path]) {
				t.Fatal("mixed business read changed", e)
			}
			expected := "cancelled"
			if resource.MemberID == tr.PeerID {
				expected = "cleaned"
			}
			if cp.State != expected {
				t.Fatal("wrong unit outcome", cp.State, expected)
			}
		}
		for _, entry := range []struct {
			database *sql.DB
			member   string
			used     int64
		}{
			{db.Database(), sr.PeerID, final.Task.TotalBytes - final.Task.CommittedBytes},
			{db.Database(), tr.PeerID, final.Task.CommittedBytes},
			{sourceDB.Database(), sr.PeerID, final.Task.TotalBytes - final.Task.CommittedBytes},
			{targetDB.Database(), tr.PeerID, final.Task.CommittedBytes},
		} {
			var used, reserved int64
			if e = entry.database.QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", entry.member).Scan(&used, &reserved); e != nil || used != entry.used || reserved != 0 {
				t.Fatal("mixed capacity reconciliation", used, reserved, entry.used, e)
			}
		}
		t.Logf("mixed cancellation: committed=%d total=%d, original logical IDs and both source/target owners retained", final.Task.CommittedBytes, final.Task.TotalBytes)
		return
	}
	if e = engine.Run(ctx, plan.ID, strings.Repeat("a", 32)); e == nil {
		t.Fatal("lost acknowledgement ignored")
	}
	task, e := repo.MigrationTask(ctx, plan.ID)
	if e != nil || task.State != "failed" || task.ErrorCode != "peer_transport" {
		t.Fatal(task, e)
	}
	if fault.reads[0] != 1 {
		t.Fatal("unexpected initial copies", fault.reads)
	}
	if cancelTask {
		if _, e = repo.ControlMigration(ctx, plan.ID, "cancel", store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
		fault.lostAbort = true
		fault.lostCancelUnit = true
		fault.lostCancelTask = true
		for attempt := 0; attempt < 4; attempt++ {
			e = engine.Run(ctx, plan.ID, strings.Repeat(string(rune('b'+attempt)), 32))
			if attempt < 3 {
				if e == nil {
					t.Fatal("lost cancellation receipt ignored", attempt)
				}
				current, err := repo.MigrationTask(ctx, plan.ID)
				if err != nil || current.State != "cancelling" || current.ErrorCode != "cancel_cleanup" {
					t.Fatal(current, err)
				}
				if id, err := repo.NextMigrationRun(ctx); err != nil || id != "" {
					t.Fatal("failed cancellation auto retried", id, err)
				}
				if _, e = repo.ControlMigration(ctx, plan.ID, "retry", store.NodeAudit{}); e != nil {
					t.Fatal(e)
				}
			} else if e != nil {
				t.Fatal("final cancellation reconciliation", e)
			}
		}
		current, e := repo.MigrationTask(ctx, plan.ID)
		if e != nil || current.State != "cancelled" || current.CommittedBytes != 0 {
			t.Fatal(current, e)
		}
		for _, database := range []*sql.DB{db.Database(), sourceDB.Database(), targetDB.Database()} {
			var state string
			var scopes, capacity int
			if e = database.QueryRow("SELECT state FROM migration_tasks WHERE task_id=?", plan.ID).Scan(&state); e != nil || state != "cancelled" {
				t.Fatal(state, e)
			}
			if e = database.QueryRow("SELECT COUNT(*) FROM migration_scopes WHERE task_id=?", plan.ID).Scan(&scopes); e != nil {
				t.Fatal(e)
			}
			if e = database.QueryRow("SELECT COUNT(*) FROM migration_capacity WHERE task_id=?", plan.ID).Scan(&capacity); e != nil || scopes != 0 || capacity != 0 {
				t.Fatal(scopes, capacity, e)
			}
		}
		var used, reserved int64
		if e = targetDB.Database().QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", tr.PeerID).Scan(&used, &reserved); e != nil || used != 0 || reserved != 0 {
			t.Fatal(used, reserved, e)
		}
		for _, id := range ids {
			resource, e := db.Pool().Resource(ctx, id)
			if e != nil || resource.MemberID != sr.PeerID {
				t.Fatal("cancel changed owner", resource, e)
			}
			read, e := master.ReadGlobalMedia(ctx, resource)
			if e != nil {
				t.Fatal(e)
			}
			got, e := io.ReadAll(read)
			read.Close()
			if e != nil || !bytes.Equal(got, payloads[resource.Path]) {
				t.Fatal("source business bytes after cancel", e)
			}
		}
		if fault.reads[0] != 1 {
			t.Fatal("cancellation recopied prefix", fault.reads)
		}
		if e = engine.ReleaseDrain(ctx, plan.ID, sr.PeerID, store.NodeAudit{}); e != nil {
			t.Fatal("explicit cancel drain release", e)
		}
		t.Log("durable prefix aborted; lost abort/unit/task receipts recovered under fresh epochs; original source business reads and quota retained")
		return
	}
	if _, e = repo.ControlMigration(ctx, plan.ID, "retry", store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Database().Exec("CREATE TRIGGER block_runner_cutover BEFORE UPDATE ON migration_units WHEN NEW.state='cleanup_pending' BEGIN SELECT RAISE(ABORT,'cutover unavailable'); END"); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Database().Exec("DROP TRIGGER IF EXISTS block_runner_cutover") })
	if unpublish {
		if _, e = targetDB.Database().Exec("CREATE TRIGGER fail_native_publication BEFORE INSERT ON node_audit WHEN NEW.action='peer-migration-media-published' BEGIN SELECT RAISE(ABORT,'publication commit unavailable'); END"); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { targetDB.Database().Exec("DROP TRIGGER IF EXISTS fail_native_publication") })
		fault.stopPublishing = func() bool {
			for _, name := range names {
				if _, e := os.Stat(filepath.Join(targetDir, "media", name)); e == nil {
					return true
				}
			}
			return false
		}
	}
	if checkpoint {
		fault.losePublicationCheckpoint = func() { loseMigrationPublicationCheckpoint(t, filepath.Join(targetDir, "media")) }
	}
	engine = &resourcemigration.Runner{Repository: repo, Nodes: db.Nodes(), Client: fault}
	if e = engine.Run(ctx, plan.ID, strings.Repeat("b", 32)); e == nil {
		t.Fatal("injected unit commit failure ignored")
	} else {
		t.Log("second runner outcome", e)
	}
	for _, id := range ids {
		row, e := db.Pool().Resource(ctx, id)
		if e != nil || row.MemberID != sr.PeerID {
			t.Fatal("partial parent cutover", row, e)
		}
	}
	if fault.reads[0] != 2 {
		t.Fatal("already saved prefix was copied again", fault.reads)
	}
	// The runner orders immutable logical IDs, not fixture filenames. Select
	// the real first published/link-created object for subsequent fault checks.
	var interruptedBytes int64
	if unpublish || checkpoint {
		found := false
		for i, id := range ids {
			row, e := db.Pool().Resource(ctx, id)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = os.Stat(filepath.Join(targetDir, "media", row.Path)); e == nil {
				ids[0], ids[i] = ids[i], ids[0]
				interruptedBytes = int64(len(payloads[row.Path]))
				found = true
				break
			}
		}
		if !found {
			t.Fatal("no actual business link at interrupted publication")
		}
	}
	var targetUsed, targetReserved int64
	targetDB.Database().QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", tr.PeerID).Scan(&targetUsed, &targetReserved)
	if !unpublish && !checkpoint && (targetUsed != catalog.TotalBytes || targetReserved != 0) || unpublish && (targetUsed != 0 || targetReserved != catalog.TotalBytes) || checkpoint && (targetUsed != interruptedBytes || targetReserved != catalog.TotalBytes-targetUsed) {
		t.Fatal("local publication accounting", targetUsed, targetReserved)
	}
	if len(modes) > 0 && (modes[0] == "shadowproof" || modes[0] == "shadowcleanup" || unpublish || checkpoint) {
		if _, e = repo.ControlMigration(ctx, plan.ID, "cancel", store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
		lease, e := repo.ClaimMigration(ctx, plan.ID, strings.Repeat("8", 32), time.Minute)
		if e != nil {
			t.Fatal(e)
		}
		resource, e := db.Pool().Resource(ctx, ids[0])
		if e != nil || resource.MemberID != sr.PeerID {
			t.Fatal(resource, e)
		}
		original := payloads[resource.Path]
		if e = os.WriteFile(filepath.Join(sourceDir, "media", resource.Path), append([]byte("!"), original[1:]...), 0644); e != nil {
			t.Fatal(e)
		}
		if _, e = engine.FreshCancellationSourceProof(ctx, lease, ids[0]); !errors.Is(e, store.ErrMigrationState) {
			t.Fatal("corrupted source accepted for shadow deletion", e)
		}
		if data, e := os.ReadFile(filepath.Join(targetDir, "media", resource.Path)); e != nil || !bytes.Equal(data, original) {
			t.Fatal("unique valid target copy changed", e)
		}
		if e = os.WriteFile(filepath.Join(sourceDir, "media", resource.Path), original, 0644); e != nil {
			t.Fatal(e)
		}
		proof, e := engine.FreshCancellationSourceProof(ctx, lease, ids[0])
		if e != nil {
			t.Fatal(e)
		}
		grant, e := repo.AuthorizeMigrationShadowDeletion(ctx, lease, ids[0], proof)
		if e != nil || grant.Unit.Unit.CommittedAt != 0 || grant.Object.ID != ids[0] || grant.SourceProof.SHA256 != proof.SHA256 {
			t.Fatal(grant, e)
		}
		old := proof
		old.VerifiedAt -= 31
		if _, e = repo.AuthorizeMigrationShadowDeletion(ctx, lease, ids[0], old); !errors.Is(e, store.ErrMigrationState) {
			t.Fatal("stale source proof", e)
		}
		if _, e = repo.ControlMigration(ctx, plan.ID, "cancel", store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
		if _, e = repo.ControlMigration(ctx, plan.ID, "pause", store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
			t.Fatal("cancel converted to paused", e)
		}
		if modes[0] == "shadowcleanup" || unpublish || checkpoint {
			if e = repo.ReleaseMigration(ctx, lease); e != nil {
				t.Fatal(e)
			}
			// A disk scan failure must surface from the durable worker checkpoint,
			// preserve the source owner and require an explicit retry.
			if e = os.WriteFile(filepath.Join(targetDir, "media", resource.Path), append([]byte("!"), original[1:]...), 0644); e != nil {
				t.Fatal(e)
			}
			if e = engine.Run(ctx, plan.ID, strings.Repeat("9", 32)); e == nil {
				t.Fatal("corrupt target shadow silently deleted")
			}
			var failed int
			if e = targetDB.Database().QueryRow("SELECT COUNT(*) FROM migration_objects WHERE task_id=? AND logical_id=? AND state='pending'", plan.ID, ids[0]).Scan(&failed); e != nil || failed != 1 {
				t.Fatal("worker failure not durable", failed, e)
			}
			if e = os.WriteFile(filepath.Join(targetDir, "media", resource.Path), original, 0644); e != nil {
				t.Fatal(e)
			}
			if _, e = repo.ControlMigration(ctx, plan.ID, "retry", store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			fault.lostShadow = !unpublish
			fault.lostUnpublish = unpublish
			fault.lostCancelUnit = true
			fault.lostCancelTask = true
			for attempt := 0; attempt < 4; attempt++ {
				e = engine.Run(ctx, plan.ID, strings.Repeat(string(rune('a'+attempt)), 32))
				if attempt < 3 {
					if e == nil {
						t.Fatal("lost shadow cancellation receipt ignored", attempt)
					}
					current, e := repo.MigrationTask(ctx, plan.ID)
					if e != nil || current.State != "cancelling" || current.ErrorCode != "cancel_cleanup" {
						t.Fatal(current, e)
					}
					if _, e = repo.ControlMigration(ctx, plan.ID, "retry", store.NodeAudit{}); e != nil {
						t.Fatal(e)
					}
				} else if e != nil {
					t.Fatal("shadow cancellation recovery", e)
				}
			}
			current, e := repo.MigrationWork(ctx, plan.ID)
			if e != nil || current.Task.State != "cancelled" || current.Task.CommittedBytes != 0 {
				t.Fatal(current.Task, e)
			}
			for _, cp := range current.Objects {
				row, e := db.Pool().Resource(ctx, cp.Object.ID)
				if e != nil || row.MemberID != sr.PeerID || cp.State != "cancelled" {
					t.Fatal(row, cp.State, e)
				}
				read, e := master.ReadGlobalMedia(ctx, row)
				if e != nil {
					t.Fatal(e)
				}
				got, e := io.ReadAll(read)
				read.Close()
				if e != nil || !bytes.Equal(got, payloads[row.Path]) {
					t.Fatal("original source read after shadow cancellation", e)
				}
				if _, e = os.Stat(filepath.Join(targetDir, "media", row.Path)); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("published target shadow remains", e)
				}
			}
			var used, reserved int64
			if e = targetDB.Database().QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", tr.PeerID).Scan(&used, &reserved); e != nil || used != 0 || reserved != 0 {
				t.Fatal("target double/retained capacity", used, reserved, e)
			}
			entries, e := os.ReadDir(filepath.Join(targetDir, "media"))
			if e != nil {
				t.Fatal(e)
			}
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".part") || strings.HasPrefix(entry.Name(), ".delete-") {
					t.Fatal("private target bytes retained", entry.Name())
				}
			}
			t.Logf("published media shadow cancellation recovered lost deletion/unit/task receipts; source business bytes=%d, target used/reserved=0", catalog.TotalBytes)
			return
		}
		t.Logf("published shadow retained while corrupted source blocked authorization; fresh %d-byte authenticated source SHA bound to uncommitted cancellation unit", proof.Bytes)
		return
	}
	if _, e = db.Database().Exec("DROP TRIGGER block_runner_cutover"); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.ControlMigration(ctx, plan.ID, "retry", store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	readsBefore := fault.reads[0]
	if e = engine.Run(ctx, plan.ID, strings.Repeat("c", 32)); e != nil {
		t.Fatal(e)
	}
	if fault.reads[0] != readsBefore {
		t.Fatal("published objects copied again")
	}
	for _, id := range ids {
		row, e := db.Pool().Resource(ctx, id)
		if e != nil || row.MemberID != tr.PeerID || row.ID != id {
			t.Fatal(row, e)
		}
		reader, e := master.ReadGlobalMedia(ctx, row)
		if e != nil {
			t.Fatal(e)
		}
		got, e := io.ReadAll(reader)
		reader.Close()
		if e != nil || !bytes.Equal(got, payloads[row.Path]) {
			t.Fatal("post-cutover business bytes mismatch", e)
		}
	}
	task, e = repo.MigrationTask(ctx, plan.ID)
	if e != nil || task.State != "cleanup_pending" || task.CommittedBytes != catalog.TotalBytes {
		t.Fatal(task, e)
	}
	hidden, e := db.Media().HiddenPaths(ctx)
	if e != nil || !hidden["music/RunnerUnit/a.mp3"] {
		t.Fatal("hidden state changed", hidden, e)
	}
	cleanupLease, e := repo.ClaimMigration(ctx, plan.ID, strings.Repeat("d", 32), time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	proof, e := engine.FreshTargetProof(ctx, cleanupLease, ids[0])
	if e != nil || proof.Bytes <= 0 || proof.VerifiedAt < time.Now().Unix()-30 {
		t.Fatal("fresh authenticated target proof", proof, e)
	}
	row, e := db.Pool().Resource(ctx, ids[0])
	if e != nil {
		t.Fatal(e)
	}
	file, e := os.OpenFile(filepath.Join(targetDir, "media", row.Path), os.O_WRONLY, 0)
	if e != nil {
		t.Fatal(e)
	}
	_, e = file.WriteAt([]byte("!"), 0)
	file.Close()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = engine.FreshTargetProof(ctx, cleanupLease, ids[0]); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("corrupted target reused old publication proof", e)
	}
	row, e = db.Pool().Resource(ctx, ids[0])
	if e != nil || row.MemberID != tr.PeerID {
		t.Fatal("failed recheck reversed committed authority", row, e)
	}
	// Advance only this isolated fixture's grace; production still waits an hour.
	if e = os.WriteFile(filepath.Join(targetDir, "media", row.Path), payloads[row.Path], 0644); e != nil {
		t.Fatal(e)
	}
	if e = repo.ReleaseMigration(ctx, cleanupLease); e != nil {
		t.Fatal(e)
	}
	if e = engine.Run(ctx, plan.ID, strings.Repeat("7", 32)); e != nil {
		t.Fatal("premature cleanup run", e)
	}
	if _, e = os.Stat(filepath.Join(sourceDir, "media", row.Path)); e != nil {
		t.Fatal("source deleted during grace", e)
	}
	if id, e := repo.NextMigrationRun(ctx); e != nil || id != "" {
		t.Fatal("grace task scheduled early", id, e)
	}
	now := time.Now().Unix()
	if _, e = db.Database().Exec("UPDATE migration_units SET committed_at=?,cleanup_after=? WHERE task_id=?", now-3601, now-1, plan.ID); e != nil {
		t.Fatal(e)
	}
	reads := sourceDB.Nodes().(store.MigrationReadRepository)
	readID, e := reads.AcquireMigrationRead(ctx, srid, strings.Repeat("9", 64), row.ObjectID, "media")
	if e != nil {
		t.Fatal(e)
	}
	if e = engine.Run(ctx, plan.ID, strings.Repeat("8", 32)); e == nil {
		t.Fatal("source live read crossed cleanup")
	}
	if _, e = os.Stat(filepath.Join(sourceDir, "media", row.Path)); e != nil {
		t.Fatal("live read source removed", e)
	}
	if e = reads.ReleaseMigrationRead(ctx, readID); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.ControlMigration(ctx, plan.ID, "retry", store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(sourceDir, "media", row.Path), append([]byte("!"), payloads[row.Path][1:]...), 0644); e != nil {
		t.Fatal(e)
	}
	if e = engine.Run(ctx, plan.ID, strings.Repeat("9", 32)); e == nil {
		t.Fatal("corrupt source removed")
	}
	var failedPhase string
	if e = sourceDB.Database().QueryRow("SELECT state FROM migration_storage_journal WHERE task_id=? AND logical_id=?", plan.ID, row.ID).Scan(&failedPhase); e != nil || failedPhase != "deleting" {
		t.Fatal("source failure lost deletion fence", failedPhase, e)
	}
	var failures int
	if e = sourceDB.Database().QueryRow("SELECT COUNT(*) FROM migration_objects WHERE task_id=? AND logical_id=? AND state='pending'", plan.ID, row.ID).Scan(&failures); e != nil || failures != 1 {
		t.Fatal("source failure not durable", failures, e)
	}
	if id, e := repo.NextMigrationRun(ctx); e != nil || id != "" {
		t.Fatal("cleanup error auto-retried", id, e)
	}
	if e = os.WriteFile(filepath.Join(sourceDir, "media", row.Path), payloads[row.Path], 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.ControlMigration(ctx, plan.ID, "retry", store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	fault.lostCleanup = true
	if e = engine.Run(ctx, plan.ID, strings.Repeat("4", 32)); e == nil {
		t.Fatal("lost source receipt ignored")
	}
	if _, e = os.Stat(filepath.Join(sourceDir, "media", row.Path)); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("acknowledged physical deletion did not happen", e)
	}
	if _, e = repo.ControlMigration(ctx, plan.ID, "retry", store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	fault.lostUnit = true
	if e = engine.Run(ctx, plan.ID, strings.Repeat("5", 32)); e == nil {
		t.Fatal("lost unit receipt ignored")
	}
	var masterScopes int
	if e = db.Database().QueryRow("SELECT COUNT(*) FROM migration_scopes WHERE task_id=?", plan.ID).Scan(&masterScopes); e != nil || masterScopes == 0 {
		t.Fatal("Master released scope before dual unit receipt", masterScopes, e)
	}
	if _, e = repo.ControlMigration(ctx, plan.ID, "retry", store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	fault.lostTask = true
	if e = engine.Run(ctx, plan.ID, strings.Repeat("3", 32)); e == nil {
		t.Fatal("lost peer task receipt ignored")
	}
	var sourceTaskState string
	if e = sourceDB.Database().QueryRow("SELECT state FROM migration_tasks WHERE task_id=?", plan.ID).Scan(&sourceTaskState); e != nil || sourceTaskState != "completed" {
		t.Fatal("source task receipt not durable", sourceTaskState, e)
	}
	if _, e = repo.ControlMigration(ctx, plan.ID, "retry", store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e = engine.Run(ctx, plan.ID, strings.Repeat("2", 32)); e != nil {
		t.Fatal("source receipt replay failed", e)
	}
	work, e := repo.MigrationWork(ctx, plan.ID)
	if e != nil {
		t.Fatal(e)
	}
	for _, cp := range work.Objects {
		if cp.State != "cleaned" {
			t.Fatal("source checkpoint incomplete", cp.State)
		}
	}
	for _, unit := range work.Units {
		if unit.State != "cleaned" {
			t.Fatal("unit not durably finished", unit)
		}
	}
	if e = db.Database().QueryRow("SELECT COUNT(*) FROM migration_scopes WHERE task_id=?", plan.ID).Scan(&masterScopes); e != nil || masterScopes != 0 {
		t.Fatal("completed unit kept Master scope", masterScopes, e)
	}
	var sourceUsed int64
	if e = sourceDB.Database().QueryRow("SELECT used_bytes FROM cluster_storage_members WHERE member_id=?", sr.PeerID).Scan(&sourceUsed); e != nil || sourceUsed != 0 {
		t.Fatal("source accounting", sourceUsed, e)
	}
	if e = engine.Run(ctx, plan.ID, strings.Repeat("6", 32)); e != nil {
		t.Fatal("completed source phase replay", e)
	}
	for _, id := range ids {
		row, e := db.Pool().Resource(ctx, id)
		if e != nil || row.MemberID != tr.PeerID {
			t.Fatal("cleanup changed authority", row, e)
		}
		reader, e := master.ReadGlobalMedia(ctx, row)
		if e != nil {
			t.Fatal(e)
		}
		got, e := io.ReadAll(reader)
		reader.Close()
		if e != nil || !bytes.Equal(got, payloads[row.Path]) {
			t.Fatal("post-source-cleanup business bytes", e)
		}
	}
	task, e = repo.MigrationTask(ctx, plan.ID)
	if e != nil || task.State != "completed" || task.ErrorCode != "" {
		t.Fatal("whole task did not complete", task, e)
	}
	var drains int
	if e = db.Database().QueryRow("SELECT COUNT(*) FROM migration_drains WHERE owner_id=?", plan.ID).Scan(&drains); e != nil || drains != 1 {
		t.Fatal("implicit drain release", drains, e)
	}
	if e = engine.ReleaseDrain(ctx, plan.ID, tr.PeerID, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("wrong source confirmation released drain", e)
	}
	adminOwner := strings.Repeat("a", 32)
	for _, database := range []*sql.DB{db.Database(), sourceDB.Database()} {
		if _, e = database.Exec("INSERT INTO migration_drains(member_id,owner_id,reason,created_at) VALUES (?,?,'administrator',?)", sr.PeerID, adminOwner, time.Now().Unix()); e != nil {
			t.Fatal(e)
		}
	}
	for range 2 {
		if e = engine.ReleaseDrain(ctx, plan.ID, sr.PeerID, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
	}
	for _, database := range []*sql.DB{db.Database(), sourceDB.Database()} {
		if e = database.QueryRow("SELECT COUNT(*) FROM migration_drains WHERE member_id=? AND reason='administrator'", sr.PeerID).Scan(&drains); e != nil || drains != 1 {
			t.Fatal("admin restriction overwritten", drains, e)
		}
		if e = database.QueryRow("SELECT COUNT(*) FROM migration_drains WHERE owner_id=? AND reason='migration'", plan.ID).Scan(&drains); e != nil || drains != 0 {
			t.Fatal("task-owned drain retained", drains, e)
		}
	}
	t.Logf("Master runner moved %d actual bytes across one complete parent; lost acknowledgement, SQL cutover failure and authenticated source cleanup safely retried; fixture-only grace advance", catalog.TotalBytes)
}
