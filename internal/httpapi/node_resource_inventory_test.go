package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAuthenticatedPhysicalInventoryReadOnlyScopeReplayAndRevocation(t *testing.T) {
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
	for _, name := range []string{"media/music/hidden", ".business-backups"} {
		if e = os.MkdirAll(filepath.Join(dir, name), 0700); e != nil {
			t.Fatal(e)
		}
	}
	for i := 0; i < 90; i++ {
		if e = os.WriteFile(filepath.Join(dir, fmt.Sprintf("media/music/hidden/%03d.mp3", i)), []byte("ID3"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.WriteFile(filepath.Join(dir, ".business-backups/only-recovery.tar"), []byte("fixture backup; do not transfer content"), 0600); e != nil {
		t.Fatal(e)
	}
	route := "/internal/v1/resource-inventory"
	if status := migrationUnsignedStatus(router, route); status != 401 {
		t.Fatal("unsigned inventory", status)
	}
	id := strings.Repeat("1", 32)
	req := map[string]any{"action": "open", "scope": "data", "member_id": rel.PeerID, "session_id": id}
	opened, e := master.Call(ctx, rel, route, req)
	if e != nil {
		t.Fatal(e)
	}
	var session resourceinventory.Session
	if e = decodeInventory(opened, &session); e != nil {
		t.Fatal(e)
	}
	if session.Binding.MemberID != rel.PeerID || session.Binding.MasterID == rel.PeerID || session.ExpiresAt <= time.Now().Unix() || session.ExpiresAt > time.Now().Add(resourceinventory.SessionTTL).Unix() {
		t.Fatal("unbound open", session)
	}
	again, e := master.Call(ctx, rel, route, req)
	if e != nil || !reflect.DeepEqual(opened, again) {
		t.Fatal("open acknowledgment replay", e)
	}
	req["scope"] = "../../secrets"
	if _, e = master.Call(ctx, rel, route, req); e == nil {
		t.Fatal("arbitrary scope accepted")
	}
	req["scope"] = "data"
	req["member_id"] = strings.Repeat("2", 32)
	if _, e = master.Call(ctx, rel, route, req); e == nil {
		t.Fatal("foreign member")
	}
	req["member_id"] = rel.PeerID
	req["path"] = "/etc"
	if _, e = master.Call(ctx, rel, route, req); e == nil {
		t.Fatal("arbitrary root")
	}
	delete(req, "path")
	req["session_id"] = strings.Repeat("2", 32)
	if _, e = master.Call(ctx, rel, route, req); e == nil {
		t.Fatal("parallel root scan")
	}
	req["session_id"] = id
	req["action"] = "page"
	req["incarnation"] = session.Incarnation
	seen := map[string]bool{}
	for sequence := uint64(0); ; sequence++ {
		req["sequence"] = sequence
		value, e := master.Call(ctx, rel, route, req)
		if e != nil {
			t.Fatal(e)
		}
		replay, e := master.Call(ctx, rel, route, req)
		if e != nil || !reflect.DeepEqual(value, replay) {
			t.Fatal("page acknowledgment replay", e)
		}
		var page resourceinventory.SessionPage
		if e = decodeInventory(value, &page); e != nil {
			t.Fatal(e)
		}
		if page.Session != session || len(page.Page.Entries) > resourceinventory.PageEntries {
			t.Fatal("page binding", page)
		}
		for _, entry := range page.Page.Entries {
			seen[entry.Path] = true
		}
		if page.Page.Complete {
			break
		}
	}
	for _, name := range []string{"media/music/hidden/089.mp3", ".business-backups/only-recovery.tar"} {
		if !seen[name] {
			t.Fatal("physical path omitted", name)
		}
	}
	var tasks, drains int
	if e = sdb.Database().QueryRow("SELECT COUNT(*) FROM migration_tasks").Scan(&tasks); e != nil {
		t.Fatal(e)
	}
	if e = sdb.Database().QueryRow("SELECT COUNT(*) FROM migration_drains").Scan(&drains); e != nil || tasks != 0 || drains != 0 {
		t.Fatal("observation mutated business", tasks, drains, e)
	}
	// Authentication is repeated even for a cached terminal page.
	upstream, e := sdb.Nodes().Relationship(ctx, rid)
	if e != nil {
		t.Fatal(e)
	}
	if e = sdb.Nodes().RevokeRelationship(ctx, upstream.ID, false, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e = master.Call(ctx, rel, route, req); e == nil {
		t.Fatal("revoked peer read cached inventory")
	}
}

func decodeInventory(value any, out any) error {
	raw, e := json.Marshal(value)
	if e != nil {
		return e
	}
	return json.Unmarshal(raw, out)
}
