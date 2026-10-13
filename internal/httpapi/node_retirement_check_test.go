package httpapi

import (
	"context"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/noderetirement"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type retirementCaller struct {
	noderetirement.Caller
	mutate func(string, map[string]any)
	closes int
}

func (c *retirementCaller) Call(ctx context.Context, rel store.Relationship, route string, req any) (map[string]any, error) {
	action := req.(map[string]any)["action"].(string)
	if action == "close" {
		c.closes++
	}
	value, e := c.Caller.Call(ctx, rel, route, req)
	if e == nil && c.mutate != nil {
		c.mutate(action, value)
	}
	return value, e
}
func TestNodeRetirementCheckAuthenticatedPagingAndIncompleteResponses(t *testing.T) {
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	_, mdb, _, _, master := clusterFixture(t, "https://master.test", transport, true)
	_, sdb, dir, _, storage := clusterFixture(t, "https://storage.test", transport, true)
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
	if e = os.MkdirAll(filepath.Join(dir, "media", "nested"), 0700); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 90; i++ {
		if e = os.WriteFile(filepath.Join(dir, "media", "nested", fmt.Sprintf("%03d.mp3", i)), []byte("ID3"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = sdb.Media().EnsureObjects(ctx, []store.MediaObject{{Path: "nested/missing.mp3", Kind: "audio"}}); e != nil {
		t.Fatal(e)
	}
	identity, e := mdb.Nodes().ReadIdentity(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = sdb.Database().Exec("INSERT INTO cluster_business_backups(master_id,generation,checksum,size_bytes,chunk_count,state,created_at,updated_at) VALUES (?,321,?,7,1,'ready',1,1)", identity.ID, strings.Repeat("7", 64)); e != nil {
		t.Fatal(e)
	}
	caller := &retirementCaller{Caller: master}
	service := noderetirement.Service{Repository: mdb.Pool().(store.RetirementRepository), Nodes: mdb.Nodes(), Client: caller}
	report, e := service.Check(ctx, rel.PeerID, rid)
	if e != nil || !report.ObservationComplete || !report.PreflightOnly || report.PhysicalEntries < 90 || report.ExpectedItems != 2 || caller.closes != 3 {
		t.Fatal("incomplete report", report, e, caller.closes)
	}
	concerns := map[string]noderetirement.Concern{}
	for _, c := range report.Concerns {
		concerns[c.Code] = c
		if len(c.Samples) > noderetirement.MaxSamples {
			t.Fatal("unbounded samples", c)
		}
	}
	if concerns["physical_unmanaged_file"].Count < 90 || concerns["expected_missing"].Count != 1 || concerns["backup_retention_required"].Count != 1 || concerns["expected_database_backed_unverified"].Count != 1 {
		t.Fatal("omitted independent blockers", concerns)
	}
	for _, fault := range []string{"sequence", "binding", "digest", "cursor", "volumes", "capacity"} {
		t.Run(fault, func(t *testing.T) {
			caller.mutate = func(action string, value map[string]any) {
				if action == "page" {
					page := value["page"].(map[string]any)
					switch fault {
					case "sequence":
						page["sequence"] = float64(99)
					case "binding":
						value["session"].(map[string]any)["binding"].(map[string]any)["member_id"] = identity.ID
					case "digest":
						page["observation_sha256"] = strings.Repeat("0", 64)
					}
				}
				if action == "volumes" {
					if fault == "volumes" {
						value["volumes"] = []any{}
					}
					if fault == "capacity" {
						value["volumes"].([]any)[0].(map[string]any)["free_bytes"] = -1
					}
				}
				if action == "expected" && fault == "cursor" {
					value["manifest"].(map[string]any)["next"] = "invalid"
				}
			}
			before := caller.closes
			report, e := service.Check(ctx, rel.PeerID, rid)
			if !errors.Is(e, noderetirement.ErrObservation) || report.ObservationComplete || caller.closes != before+1 {
				t.Fatal("accepted incomplete observation or leaked session", e, report, caller.closes)
			}
		})
	}
	caller.mutate = nil
	delete(transport.routers, "https://storage.test")
	report, e = service.Check(ctx, rel.PeerID, rid)
	if e == nil || report.ObservationComplete {
		t.Fatal("offline peer accepted", e, report)
	}
	var tasks, drains int
	if e = sdb.Database().QueryRow("SELECT COUNT(*) FROM migration_tasks").Scan(&tasks); e != nil {
		t.Fatal(e)
	}
	if e = sdb.Database().QueryRow("SELECT COUNT(*) FROM migration_drains").Scan(&drains); e != nil || tasks != 0 || drains != 0 {
		t.Fatal("read-only check mutated business", tasks, drains, e)
	}
}
