package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourcemigration"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestMigrationPlanClientUsesConfirmedServerPlanAndBounds(t *testing.T) {
	master, id, request, source, target := strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32), strings.Repeat("d", 32), strings.Repeat("e", 32)
	now := time.Now().Unix()
	mode := "valid"
	startCalls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/nodes") {
			fmt.Fprintf(w, `{"role":"Master","node_id":%q}`, master)
			return
		}
		v := resourcemigration.PlanView{ID: id, RequestID: request, State: "ready", Source: store.StorageMember{ID: source}, Target: store.StorageMember{ID: target}, ReviewSHA: strings.Repeat("f", 64), CreatedAt: now, ExpiresAt: now + 300, Complete: true, Objects: []store.MigrationObject{}, After: r.URL.Query().Get("after"), Next: r.URL.Query().Get("after")}
		if r.Method == "POST" {
			if r.Header.Get("X-CSRF-Token") != "fixture" {
				t.Error("missing CSRF")
			}
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Error("bad body")
			}
			if strings.HasSuffix(r.URL.Path, "/start") {
				startCalls++
				if len(body) != 3 || body["review_sha256"] != v.ReviewSHA || body["confirm_source_id"] != source || body["confirm_target_id"] != target {
					t.Error("not bound to reviewed plan")
				}
				v.State = "starting"
			} else if len(body) != 3 || body["request_id"] != request || body["source_id"] != source || body["target_id"] != target {
				t.Error("client supplied facts")
			}
		}
		switch mode {
		case "stage":
            v.ErrorStage = "https://private-untrusted-stage.example"
            v.State = "failed"
        case "failed":
            v.ErrorStage = resourcemigration.PlanStageSourceContent
            v.ErrorCode = "physical_observation_changed_or_unavailable"
            v.State = "failed"
        case "foreign":
			v.Source.ID = master
		case "large":
			v.Objects = make([]store.MigrationObject, 17)
		case "cursor":
			v.Next = strings.Repeat("1", 64)
		case "unproved":
			v.ObjectCount = 1
		case "conflict":
			w.WriteHeader(409)
			fmt.Fprint(w, `{"detail":"private credential"}`)
			return
		}
		json.NewEncoder(w).Encode(v)
	}))
	defer server.Close()
	c, e := NewNodeClient(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	c.client.Transport = server.Client().Transport
	c.csrf = "fixture"
	v, e := c.CreateMigrationPlan(context.Background(), request, source, target)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.StartMigrationPlan(context.Background(), id, v.ReviewSHA, source, target); e != nil {
		t.Fatal(e)
	}
	if _, e = c.StartMigrationPlan(context.Background(), id, "fake", source, target); e == nil || startCalls != 1 {
		t.Fatal("invalid local confirmation sent")
	}
	mode = "failed"
	if failed, e := c.MigrationPlanStatus(context.Background(), id, ""); e != nil || failed.ErrorStage != resourcemigration.PlanStageSourceContent { t.Fatal("controlled failure stage rejected", e) }
	for _, fault := range []string{"foreign", "large", "cursor", "unproved", "conflict", "stage"} {
		mode = fault
		if _, e = c.MigrationPlanStatus(context.Background(), id, ""); e == nil || strings.Contains(e.Error(), "private") {
			t.Fatal("unbounded/untrusted plan accepted", fault, e)
		}
	}
}
