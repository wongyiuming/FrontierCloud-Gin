package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestMigrationRegistrationUsesPairedMasterBodyAuthentication(t *testing.T) {
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	_, masterDB, _, _, master := clusterFixture(t, "https://master.test", transport, true)
	targetRouter, targetDB, _, _, target := clusterFixture(t, "https://target.test", transport, true)
	if _, e := master.Promote(ctx, "Master", "https://master.test", 5*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e := target.Promote(ctx, "Follower", "https://target.test", 0, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	pair, e := target.CreatePair(ctx, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	relID, e := master.ImportPair(ctx, pair, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	rel, e := masterDB.Nodes().Relationship(ctx, relID)
	if e != nil {
		t.Fatal(e)
	}
	cfg := store.ResourceConfiguration{}
	cfg.Storage.Enabled = true
	cfg.Storage.Allocation = 5 * store.GiB
	if e = masterDB.Pool().ConfigureMember(ctx, rel.PeerID, cfg, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e = master.Tick(ctx, rel); e != nil {
		t.Fatal(e)
	}
	rel, e = masterDB.Nodes().Relationship(ctx, relID)
	if e != nil {
		t.Fatal(e)
	}
	mid, e := masterDB.Nodes().ReadIdentity(ctx)
	if e != nil {
		t.Fatal(e)
	}
	header := store.MigrationPeerHeader{Format: "frontiercloud-peer-migration", Version: 1, TaskID: strings.Repeat("d", 32), MasterID: mid.ID, SourceID: strings.Repeat("e", 32), TargetID: rel.PeerID, SourceRelationship: strings.Repeat("f", 32), TargetRelationship: relID, PlanSHA: strings.Repeat("1", 64), ObjectCount: 1, Bytes: 7}
	lease := store.MigrationLease{TaskID: header.TaskID, RunnerID: strings.Repeat("a", 32), Epoch: 1, ExpiresAt: time.Now().Unix() + 60}
	url := "https://target.test/internal/v1/resource-migration/register"
	if w := request(targetRouter, "POST", url, `{"state":"queued"}`); w.Code != 401 {
		t.Fatal("unsigned registration admitted", w.Code)
	}
	call := func(h store.MigrationPeerHeader) error {
		raw, e := json.Marshal(map[string]any{"header": h, "lease": lease, "state": "queued"})
		if e != nil {
			return e
		}
		var value map[string]any
		if e = controlJSON(raw, &value); e != nil {
			return e
		}
		_, e = master.Call(ctx, rel, "/internal/v1/resource-migration/register", value)
		return e
	}
	wrong := header
	wrong.MasterID = strings.Repeat("b", 32)
	if e = call(wrong); !errors.Is(e, node.ErrRemoteConflict) {
		t.Fatal("paired key bypassed task Master identity", e)
	}
	if e = call(header); e != nil {
		t.Fatal(e)
	}
	if e = call(header); e != nil {
		t.Fatal("idempotent authenticated registration", e)
	}
	var reserved int64
	if e = targetDB.Database().QueryRow("SELECT reserved_bytes FROM migration_capacity WHERE task_id=?", header.TaskID).Scan(&reserved); e != nil || reserved != 7 {
		t.Fatal("authenticated task capacity", reserved, e)
	}
}
