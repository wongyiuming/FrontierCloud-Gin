package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuthenticatedManagedContentObservation(t *testing.T) {
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	_, mdb, _, _, master := clusterFixture(t, "https://master.test", transport, true)
	router, sdb, dir, _, storage := clusterFixture(t, "https://storage.test", transport, true)
	if _, e := master.Promote(ctx, "Master", "https://master.test", store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e := storage.Promote(ctx, "Follower", "https://storage.test", 0, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	pair, e := storage.CreatePair(ctx, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	rid, e := master.ImportPair(ctx, pair, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	rel, e := mdb.Nodes().Relationship(ctx, rid)
	if e != nil {
		t.Fatal(e)
	}
	identity, e := master.IdentityState(ctx)
	if e != nil {
		t.Fatal(e)
	}
	data := []byte(strings.Repeat("actual opaque bytes", 10000))
	name := "music/hidden.mp3"
	if e = os.WriteFile(filepath.Join(dir, "media", name), data, 0600); e != nil {
		t.Fatal(e)
	}
	ids, e := sdb.Media().EnsureObjects(ctx, []store.MediaObject{{Path: name, Kind: "audio"}})
	if e != nil {
		t.Fatal(e)
	}
	item, e := sdb.Pool().(store.ManagedPhysicalRepository).ExpectedPhysicalObject(ctx, rid, rel.PeerID, identity.ID, "media", ids[name])
	if e != nil {
		t.Fatal(e)
	}
	request := map[string]any{"action": "start", "observation_id": strings.Repeat("1", 32), "binding": map[string]any{"member_id": rel.PeerID, "master_id": identity.ID, "relationship_id": rid, "scope": "data"}, "resource_kind": "media", "object_id": item.ObjectID, "metadata_sha256": item.MetadataSHA256, "expected_bytes": len(data)}
	route := "/internal/v1/content-observation"
	if status := migrationUnsignedStatus(router, route); status != 401 {
		t.Fatal("unsigned", status)
	}
	for key, value := range map[string]any{"path": "/etc/passwd", "url": "https://foreign.test", "key": "private"} {
		request[key] = value
		if _, e = master.Call(ctx, rel, route, request); e == nil {
			t.Fatal("unknown field", key)
		}
		delete(request, key)
	}
	request["metadata_sha256"] = strings.Repeat("0", 64)
	if _, e = master.Call(ctx, rel, route, request); e == nil {
		t.Fatal("stale metadata")
	}
	request["metadata_sha256"] = item.MetadataSHA256
	result, e := master.Call(ctx, rel, route, request)
	if e != nil {
		t.Fatal(e)
	}
	var job resourceinventory.ContentJob
	job = resourceinventory.ContentJob{}
	if e = decodeInventory(result, &job); e != nil {
		t.Fatal(e)
	}
	request["action"] = "status"
	request["incarnation"] = job.Incarnation
	deadline := time.Now().Add(10 * time.Second)
	for {
		result, e = master.Call(ctx, rel, route, request)
		if e != nil {
			t.Fatal(e)
		}
		job = resourceinventory.ContentJob{}
		if e = decodeInventory(result, &job); e != nil {
			t.Fatal(e)
		}
		if job.State == "observed" {
			break
		}
		if job.State == "failed" || time.Now().After(deadline) {
			t.Fatal("not observed", job)
		}
		time.Sleep(10 * time.Millisecond)
	}
	sum := sha256.Sum256(data)
	if job.Observation == nil || job.Observation.SHA256 != hex.EncodeToString(sum[:]) || job.Observation.Bytes != int64(len(data)) || job.Observation.Path != item.Path {
		t.Fatal("wrong bytes", job)
	}
	request["expected_bytes"] = len(data) + 1
	if _, e = master.Call(ctx, rel, route, request); e == nil {
		t.Fatal("cached request changed")
	}
	request["expected_bytes"] = len(data)
	request["action"] = "cancel"
	result, e = master.Call(ctx, rel, route, request)
	if e != nil {
		t.Fatal(e)
	}
	job = resourceinventory.ContentJob{}
	if e = decodeInventory(result, &job); e != nil || job.Observation != nil || job.State != "cancelled" {
		t.Fatal("cancel retained bytes", job, e)
	}
	if e = sdb.Nodes().RevokeRelationship(ctx, rid, true, store.NodeAudit{}); e == nil {
		t.Fatal("managed files must block revocation")
	}
	// Inject a revoked relationship only in this disposable SQLite fixture.
	// Production revocation protection remains unchanged.
	if _, e = sdb.Database().Exec("UPDATE node_relationships SET state='revoked' WHERE relationship_id=?", rid); e != nil {
		t.Fatal(e)
	}
	if _, e = master.Call(ctx, rel, route, request); e == nil {
		t.Fatal("revoked accepted")
	}
}
