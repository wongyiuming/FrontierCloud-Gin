package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMigrationClientBoundedQueriesConfirmationsAndConflict(t *testing.T) {
	master, id, source, target := strings.Repeat("a", 32), strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32)
	mode := "valid"
	task := store.MigrationTask{ID: id, MasterID: master, SourceID: source, TargetID: target, PlanSHA: strings.Repeat("f", 64), State: "queued", Revision: 7, ObjectCount: 1, TotalBytes: 10}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/media/admin/nodes" {
			fmt.Fprintf(w, `{"role":"Master","node_id":%q}`, master)
			return
		}
		if mode == "conflict" {
			w.WriteHeader(409)
			fmt.Fprint(w, `{"detail":"private fixture should not be echoed"}`)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/control") {
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			if r.Header.Get("X-CSRF-Token") != "fixture" || body["confirm_source_id"] != source || body["confirm_target_id"] != target || body["revision"] != float64(7) {
				t.Error("missing authority confirmation")
			}
			value := task
			value.State = "paused"
			value.Revision = 8
			if mode == "foreign" {
				value.MasterID = target
			}
			json.NewEncoder(w).Encode(value)
			return
		}
		after := r.URL.Query().Get("after")
		report := store.MigrationStatus{Task: task, After: after, Next: strings.Repeat("1", 64), Complete: true, Objects: []store.MigrationObjectStatus{{ID: strings.Repeat("1", 64), UnitID: strings.Repeat("4", 64), Path: "music/hidden/fixture.mp3", State: "pending", Bytes: 10}}, ObjectStages: []store.MigrationStage{{State: "pending", Count: 1, Bytes: 10}}}
		switch mode {
		case "foreign":
			report.Task.MasterID = target
		case "cursor":
			report.Next = strings.Repeat("f", 64)
		case "ready":
			report.RetirementReady = true
		case "bytes":
			report.Objects[0].VerifiedBytes = 11
		case "many":
			report.Objects = append(report.Objects, make([]store.MigrationObjectStatus, 16)...)
		}
		json.NewEncoder(w).Encode(report)
	}))
	defer server.Close()
	client, e := NewNodeClient(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	client.client.Transport = server.Client().Transport
	client.csrf = "fixture"
	report, e := client.MigrationStatus(context.Background(), id, strings.Repeat("0", 64))
	if e != nil || report.Task.ID != id || len(report.Objects) != 1 {
		t.Fatal(report, e)
	}
	result, e := client.ControlMigration(context.Background(), id, "pause", 7, source, target)
	if e != nil || result.State != "paused" || result.Revision != 8 {
		t.Fatal(result, e)
	}
	for _, fault := range []string{"foreign", "cursor", "ready", "bytes", "many", "conflict"} {
		mode = fault
		if _, e = client.MigrationStatus(context.Background(), id, ""); e == nil || strings.Contains(e.Error(), "private") {
			t.Fatal("unsafe status response", fault, e)
		}
	}
	mode = "foreign"
	if _, e = client.ControlMigration(context.Background(), id, "pause", 7, source, target); e == nil {
		t.Fatal("foreign control acknowledgment")
	}
	mode = "conflict"
	if _, e = client.ControlMigration(context.Background(), id, "pause", 7, source, target); e != ErrMigrationClientConflict {
		t.Fatal("conflict lost", e)
	}
}
