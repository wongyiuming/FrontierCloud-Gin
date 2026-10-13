package httpapi

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSafeRetirementJoinsHTTPAuthorizedBeforeFenceAndRechecksLateMaterial(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	_, mdb, _, _, master := clusterFixture(t, "https://master.test", transport, true, true)
	router, pdb, dir, _, peer := clusterFixture(t, "https://peer.test", transport, true, true)
	if _, e := master.Promote(ctx, "Master", "https://master.test", store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e := peer.Promote(ctx, "Follower", "https://peer.test", 0, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	pair, e := peer.CreatePair(ctx, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	id, e := master.ImportPair(ctx, pair, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	rel, e := mdb.Nodes().Relationship(ctx, id)
	if e != nil {
		t.Fatal(e)
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	artifact := filepath.Join(dir, "late-fixture-material")
	route := "/internal/v1/retirement-test-held"
	router.POST(route, func(c *gin.Context) {
		body, ok := nodeBody(c)
		if !ok {
			return
		}
		if _, e := peer.Authenticate(c.Request.Context(), c.Request.Header, c.Request.Method, c.Request.URL.RequestURI(), body, false, false); e != nil {
			detail(c, 401, "stale authority")
			return
		}
		close(entered)
		select {
		case <-resume:
		case <-c.Request.Context().Done():
			return
		}
		if e := os.WriteFile(artifact, []byte("already authorized native work"), 0600); e != nil {
			t.Error(e)
			detail(c, 500, "fixture failed")
			return
		}
		c.JSON(200, gin.H{"done": true})
	})
	done := make(chan error, 1)
	go func() { _, e := master.Call(ctx, rel, route, map[string]any{}); done <- e }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, e = master.Call(ctx, rel, "/internal/v1/retirement", map[string]any{"action": "begin", "confirm_member_id": rel.PeerID}); e != nil {
		close(resume)
		t.Fatal(e)
	}
	limited, stop := context.WithTimeout(ctx, 50*time.Millisecond)
	_, e = master.Call(limited, rel, "/internal/v1/retirement", map[string]any{"action": "complete", "confirm_member_id": rel.PeerID})
	stop()
	if e == nil {
		close(resume)
		t.Fatal("in-flight authorized handler was not joined")
	}
	still, e := pdb.Nodes().Relationship(ctx, id)
	if e != nil || still.State != "retiring" {
		close(resume)
		t.Fatal("durable fence lost", still.State, e)
	}
	close(resume)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if _, e = master.Call(ctx, rel, "/internal/v1/retirement", map[string]any{"action": "complete", "confirm_member_id": rel.PeerID}); e == nil {
		t.Fatal("post-admission native material escaped fresh final scan")
	}
	if e = os.Remove(artifact); e != nil {
		t.Fatal(e)
	}
	if _, e = master.Call(ctx, rel, "/internal/v1/retirement", map[string]any{"action": "complete", "confirm_member_id": rel.PeerID}); e != nil {
		t.Fatal("clean joined request failed", e)
	}
	if _, e = master.Call(ctx, rel, route, map[string]any{}); e == nil {
		t.Fatal("old auth survived retirement")
	}
	if _, e = os.Stat(artifact); !os.IsNotExist(e) {
		t.Fatal("late request created material", e)
	}
	if _, release, e := peer.ActiveFollowerWork(ctx, id); e == nil {
		release()
		t.Fatal("queued old async job survived retirement")
	}
	if _, e = master.Call(ctx, rel, "/internal/v1/retirement", map[string]any{"action": "status", "confirm_member_id": rel.PeerID}); e != nil {
		t.Fatal("dedicated receipt replay was blocked", e)
	}
}
