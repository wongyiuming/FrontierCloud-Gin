package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourcemigration"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type planObservationCounter struct {
	client           *node.Service
	starts, statuses atomic.Int64
}

func (c *planObservationCounter) Call(ctx context.Context, rel store.Relationship, route string, value any) (map[string]any, error) {
	if route == "/internal/v1/content-observation" {
		request, _ := value.(map[string]any)
		switch request["action"] {
		case "start":
			c.starts.Add(1)
		case "status":
			c.statuses.Add(1)
		}
	}
	return c.client.Call(ctx, rel, route, value)
}

// Seed facts and files only in this fixture's temporary native roots. No disk
// proof is injected: every resulting proof must be read and SHA-256 hashed by
// the authenticated peer content worker. Socket/TLS acceptance is separate.
func TestMasterMigrationPlanLargeActualNativeSourceBytes(t *testing.T) {
	if os.Getenv("FRONTIERCLOUD_TEST_LARGE_NATIVE_PLAN") != "1" {
		t.Skip("explicit 10008-file native content observation acceptance")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	_, db, _, _, master := clusterFixture(t, "https://master.test", transport, true)
	_, sourceDB, sourceDir, _, source := clusterFixture(t, "https://source.test", transport, true)
	_, _, _, _, target := clusterFixture(t, "https://target.test", transport, true)
	for _, v := range []struct {
		s              *node.Service
		role, endpoint string
		allocation     int64
	}{{master, "Master", "https://master.test", store.GiB}, {source, "Follower", "https://source.test", 0}, {target, "Follower", "https://target.test", 0}} {
		if _, e := v.s.Promote(ctx, v.role, v.endpoint, v.allocation, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
	}
	relations := []store.Relationship{}
	for _, peer := range []*node.Service{source, target} {
		pair, e := peer.CreatePair(ctx, store.NodeAudit{})
		if e != nil {
			t.Fatal(e)
		}
		id, e := master.ImportPair(ctx, pair, store.NodeAudit{})
		if e != nil {
			t.Fatal(e)
		}
		rel, e := db.Nodes().Relationship(ctx, id)
		if e != nil {
			t.Fatal(e)
		}
		cfg := store.ResourceConfiguration{}
		cfg.Storage.Enabled = true
		cfg.Storage.Allocation = 5 * store.GiB
		if e = db.Pool().ConfigureMember(ctx, rel.PeerID, cfg, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
		if e = master.Tick(ctx, rel); e != nil {
			t.Fatal(e)
		}
		relations = append(relations, rel)
	}
	const count = 10008
	payload := []byte("ID3tiny-native-source\n")
	sum := sha256.Sum256(payload)
	wantSHA := hex.EncodeToString(sum[:])
	started := time.Now()
	if e := os.MkdirAll(filepath.Join(sourceDir, "media", "music", "LargePlan"), 0755); e != nil {
		t.Fatal(e)
	}
	for offset := 0; offset < count; offset += store.MigrationPageObjects {
		objects := []store.MediaObject{}
		for i := offset; i < min(count, offset+store.MigrationPageObjects); i++ {
			name := fmt.Sprintf("music/LargePlan/t%05d.mp3", i)
			if e := os.WriteFile(filepath.Join(sourceDir, "media", name), payload, 0644); e != nil {
				t.Fatal(e)
			}
			objects = append(objects, store.MediaObject{Path: name, Kind: "audio"})
		}
		ids, e := sourceDB.Media().EnsureObjects(ctx, objects)
		if e != nil {
			t.Fatal(e)
		}
		tx, e := db.Database().BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		for _, o := range objects {
			hash := sha256.Sum256([]byte(o.Path))
			logical := hex.EncodeToString(hash[:])
			if _, e = tx.ExecContext(ctx, "INSERT INTO global_media_objects(media_id,storage_member_id,object_id,object_kind,media_path,path_locator,size_bytes,etag,state,created_at,updated_at) VALUES (?,?,?,'audio',?,?,?,?,'active',?,?)", logical, relations[0].PeerID, ids[o.Path], o.Path, logical, len(payload), `"`+wantSHA+`"`, time.Now().Unix(), time.Now().Unix()); e != nil {
				tx.Rollback()
				t.Fatal(e)
			}
		}
		if e = tx.Commit(); e != nil {
			t.Fatal(e)
		}
	}
	total := int64(count * len(payload))
	if _, e := db.Database().ExecContext(ctx, "UPDATE cluster_storage_members SET used_bytes=? WHERE member_id=?", total, relations[0].PeerID); e != nil {
		t.Fatal(e)
	}
	if _, e := sourceDB.Database().ExecContext(ctx, "UPDATE cluster_storage_members SET used_bytes=? WHERE member_id=?", total, relations[0].PeerID); e != nil {
		t.Fatal(e)
	}
	t.Logf("native files seeded=%d bytes=%d elapsed=%s", count, total, time.Since(started))
	for _, rel := range relations {
		if e := master.Tick(ctx, rel); e != nil {
			t.Fatal(e)
		}
	}
	live, stop := context.WithCancel(ctx)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-live.Done():
				return
			case <-ticker.C:
				for _, rel := range relations {
					if e := master.Tick(live, rel); e != nil && live.Err() == nil {
						t.Error("live authenticated heartbeat", e)
						cancel()
						return
					}
				}
			}
		}
	}()
	defer func() { stop(); <-joined }()
	client := &planObservationCounter{client: master}
	repo := db.Pool().(store.MigrationRepository)
	runner := &resourcemigration.Runner{Repository: repo, Nodes: db.Nodes(), Client: client}
	started = time.Now()
	var verifiedObjects, verifiedBytes int64
	observation, e := runner.ObservePlan(ctx, strings.Repeat("e", 32), relations[0].PeerID, relations[1].PeerID, func(objects, bytes int64) {
		verifiedObjects, verifiedBytes = objects, bytes
		if objects%1000 == 0 {
			t.Logf("native content verified=%d elapsed=%s", objects, time.Since(started))
		}
	})
	if e != nil {
		t.Fatal("complete native plan", verifiedObjects, verifiedBytes, e)
	}
	if observation.Plan.ObjectCount != count || verifiedObjects != count || verifiedBytes != total || observation.Plan.Catalog.TotalBlockers() != 0 || !observation.Plan.TargetAbsent || len(observation.SourceVolumes) != 3 || len(observation.TargetVolumes) != 3 {
		t.Fatal("incomplete native observation", observation.Plan.ObjectCount, verifiedObjects, verifiedBytes, observation.Plan.Catalog.Blockers)
	}
	var actual, wrong int64
	if e = db.Database().QueryRowContext(ctx, "SELECT COUNT(*),SUM(CASE WHEN native_seen<>1 OR source_sha256<>? THEN 1 ELSE 0 END) FROM migration_plan_bindings WHERE plan_id=?", wantSHA, observation.Plan.ID).Scan(&actual, &wrong); e != nil || actual != count || wrong != 0 {
		t.Fatal("actual-byte proof transcript", actual, wrong, e)
	}
	if client.starts.Load() != count || client.statuses.Load() < count {
		t.Fatal("source content worker was skipped", client.starts.Load(), client.statuses.Load())
	}
	for _, table := range []string{"migration_tasks", "migration_drains", "migration_scopes", "migration_capacity"} {
		var writes int
		if e = db.Database().QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&writes); e != nil || writes != 0 {
			t.Fatal("preview changed business authority", table, writes, e)
		}
	}
	t.Logf("native content PASS files=%d bytes=%d worker_starts=%d worker_statuses=%d elapsed=%s", actual, total, client.starts.Load(), client.statuses.Load(), time.Since(started))
}
