package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	client      *node.Service
	lost        bool
	lostCleanup bool
	reads       map[int64]int
}

func (c *runnerFaultCaller) Call(ctx context.Context, rel store.Relationship, path string, value any) (map[string]any, error) {
	if strings.HasSuffix(path, "/read") {
		raw, _ := json.Marshal(value)
		var request migrationdata.Request
		if json.Unmarshal(raw, &request) == nil {
			c.reads[request.Offset]++
		}
	}
	result, e := c.client.Call(ctx, rel, path, value)
	if e == nil && c.lost && strings.HasSuffix(path, "/append") {
		c.lost = false
		return nil, errors.New("injected lost append acknowledgement")
	}
	if e == nil && c.lostCleanup && strings.HasSuffix(path, "/cleanup") && result["state"] == "source_deleted" {
		c.lostCleanup = false
		return nil, errors.New("injected lost source deletion receipt")
	}
	return result, e
}

func TestMasterMigrationRunnerRealBytesRestartAndAtomicUnitRetry(t *testing.T) {
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
	for i, name := range []string{"music/RunnerUnit/a.mp3", "music/RunnerUnit/b.mp3"} {
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
	if _, e = repo.ControlMigration(ctx, plan.ID, "retry", store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Database().Exec("CREATE TRIGGER block_runner_cutover BEFORE UPDATE ON migration_units WHEN NEW.state='cleanup_pending' BEGIN SELECT RAISE(ABORT,'cutover unavailable'); END"); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Database().Exec("DROP TRIGGER IF EXISTS block_runner_cutover") })
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
	var targetUsed, targetReserved int64
	targetDB.Database().QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", tr.PeerID).Scan(&targetUsed, &targetReserved)
	if targetUsed != catalog.TotalBytes || targetReserved != 0 {
		t.Fatal("local publication accounting", targetUsed, targetReserved)
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
	if e = engine.Run(ctx, plan.ID, strings.Repeat("5", 32)); e != nil {
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
	if e != nil || task.State != "cleanup_pending" || task.ErrorCode != "" {
		t.Fatal("source phase falsely completed whole task", task, e)
	}
	t.Logf("Master runner moved %d actual bytes across one complete parent; lost acknowledgement, SQL cutover failure and authenticated source cleanup safely retried; fixture-only grace advance", catalog.TotalBytes)
}
