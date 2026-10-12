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
	managed := "music/hidden/000.mp3"
	if _, e = sdb.Media().EnsureObjects(ctx, []store.MediaObject{{Path: managed, Kind: "audio"}}); e != nil {
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
	categories := map[string]string{}
	for sequence := uint64(0); ; sequence++ {
		req["sequence"] = sequence
		value, e := master.Call(ctx, rel, route, req)
		if e != nil {
			t.Fatal(e)
		}
		// Mutate metadata only in this isolated fixture, after observing the
		// physical page, to prove acknowledgment replay keeps the original facts.
		var first struct {
			Page resourceinventory.Page `json:"page"`
		}
		if e = decodeInventory(value, &first); e != nil {
			t.Fatal(e)
		}
		changed := false
		for _, entry := range first.Page.Entries {
			if entry.Path == "media/"+managed {
				changed = true
			}
		}
		if changed {
			if _, e = sdb.Database().Exec("UPDATE media_objects SET object_kind='lyric' WHERE media_path=?", managed); e != nil {
				t.Fatal(e)
			}
		}
		replay, e := master.Call(ctx, rel, route, req)
		if changed {
			if _, err := sdb.Database().Exec("UPDATE media_objects SET object_kind='audio' WHERE media_path=?", managed); err != nil {
				t.Fatal(err)
			}
		}
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
		var annotated struct {
			Facts []store.PhysicalInventoryFact `json:"facts"`
		}
		if e = decodeInventory(value, &annotated); e != nil || len(annotated.Facts) != len(page.Page.Entries) {
			t.Fatal("missing page facts", e)
		}
		for i, entry := range page.Page.Entries {
			seen[entry.Path] = true
			categories[entry.Path] = annotated.Facts[i].Category
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
	if categories["media/"+managed] != "managed_media" || categories["media/music/hidden/089.mp3"] != "unmanaged_file" || categories[".business-backups/only-recovery.tar"] != "backup_material" {
		t.Fatal("incorrect native page classification", categories)
	}
	var tasks, drains int
	if e = sdb.Database().QueryRow("SELECT COUNT(*) FROM migration_tasks").Scan(&tasks); e != nil {
		t.Fatal(e)
	}
	if e = sdb.Database().QueryRow("SELECT COUNT(*) FROM migration_drains").Scan(&drains); e != nil || tasks != 0 || drains != 0 {
		t.Fatal("observation mutated business", tasks, drains, e)
	}
	// Remove one exact fixture file, retaining its managed metadata. The
	// independent expected manifest must report the missing resource.
	if e = os.Remove(filepath.Join(dir, "media", managed)); e != nil {
		t.Fatal(e)
	}
	req["action"] = "expected"
	req["resource"] = "media"
	req["after"] = ""
	req["sequence"] = uint64(0)
	expected, e := master.Call(ctx, rel, route, req)
	if e != nil {
		t.Fatal(e)
	}
	var expectedPage struct {
		Manifest store.ExpectedPhysicalPage   `json:"manifest"`
		Presence []resourceinventory.Presence `json:"presence"`
	}
	if e = decodeInventory(expected, &expectedPage); e != nil || len(expectedPage.Manifest.Items) != 1 || len(expectedPage.Presence) != 1 || expectedPage.Presence[0].State != "missing" {
		t.Fatal("expected missing resource omitted", expectedPage, e)
	}
	repeated, e := master.Call(ctx, rel, route, req)
	if e != nil || !reflect.DeepEqual(expected, repeated) {
		t.Fatal("expected page replay", e)
	}
	// Legacy SQL-backed generations are reported without inventing a path or
	// claiming payload integrity from their stored metadata state.
	owner := session.Binding.MasterID
	if _, e = sdb.Database().Exec("INSERT INTO cluster_business_backups(master_id,generation,checksum,size_bytes,chunk_count,state,created_at,updated_at) VALUES (?,321,?,7,1,'ready',1,1)", owner, strings.Repeat("7", 64)); e != nil {
		t.Fatal(e)
	}
	req["resource"] = "backup"
	req["after"] = ""
	value, e := master.Call(ctx, rel, route, req)
	if e != nil {
		t.Fatal(e)
	}
	var backupPage struct {
		Manifest store.ExpectedPhysicalPage   `json:"manifest"`
		Presence []resourceinventory.Presence `json:"presence"`
	}
	if e = decodeInventory(value, &backupPage); e != nil || len(backupPage.Manifest.Items) != 1 || len(backupPage.Presence) != 1 || backupPage.Manifest.Items[0].Backing != "database" || backupPage.Presence[0].State != "database_backed_unverified" {
		t.Fatal("legacy backup backing", backupPage, e)
	}
	// Authentication is repeated even for a cached terminal page.
	upstream, e := sdb.Nodes().Relationship(ctx, rid)
	if e != nil {
		t.Fatal(e)
	}
	if e = sdb.Nodes().RevokeRelationship(ctx, upstream.ID, false, store.NodeAudit{}); e == nil {
		t.Fatal("managed resource did not block ordinary revocation")
	}
	// Inject only a revocation fact in this isolated database to verify that
	// cached observations never bypass authentication. No resource is deleted.
	if _, e = sdb.Database().Exec("UPDATE node_relationships SET state='revoked' WHERE relationship_id=?", upstream.ID); e != nil {
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
