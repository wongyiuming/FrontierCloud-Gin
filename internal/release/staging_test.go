package release

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestDevelopmentHeadRequiresNewestExactSuccessfulDevPush(t *testing.T) {
	sha := strings.Repeat("a", 40)
	for _, kind := range []string{"success", "failed", "pending", "wrong-sha", "wrong-branch", "wrong-event", "missing"} {
		t.Run(kind, func(t *testing.T) {
			v := verifierFixture(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/branches/dev":
					json.NewEncoder(w).Encode(map[string]any{"commit": map[string]any{"sha": sha}})
				case "/actions/workflows/docker.yml/runs":
					if r.URL.Query().Get("head_sha") != sha || r.URL.Query().Get("event") != "push" {
						t.Error("unscoped CI query")
					}
					newest := map[string]any{"head_sha": sha, "head_branch": "dev", "event": "push", "status": "completed", "conclusion": "success", "run_number": 9}
					older := map[string]any{"head_sha": sha, "head_branch": "dev", "event": "push", "status": "completed", "conclusion": "success", "run_number": 8}
					if kind == "failed" {
						newest["conclusion"] = "failure"
					}
					if kind == "pending" {
						newest["status"] = "in_progress"
					}
					if kind == "wrong-sha" {
						newest["head_sha"] = strings.Repeat("b", 40)
						older["head_sha"] = strings.Repeat("b", 40)
					}
					if kind == "wrong-branch" {
						newest["head_branch"] = "main"
						older["head_branch"] = "main"
					}
					if kind == "wrong-event" {
						newest["event"] = "workflow_dispatch"
						older["event"] = "workflow_dispatch"
					}
					rows := []any{older, newest}
					if kind == "missing" {
						rows = nil
					}
					json.NewEncoder(w).Encode(map[string]any{"workflow_runs": rows})
				default:
					t.Error("unexpected path", r.URL.Path)
					w.WriteHeader(404)
				}
			})
			actual, err := v.DevelopmentHead(context.Background())
			if (err == nil) != (kind == "success") || err == nil && actual != sha {
				t.Fatal(actual, err)
			}
		})
	}
}

func TestCDManagedSiteRejectsProductionReleaseMutations(t *testing.T) {
	c, _, agent, _ := localReleaseFixture()
	c.CDManaged = true
	status, err := c.Status(context.Background(), false)
	if err != nil || status["can_upgrade"] != false || status["can_rollback"] != false {
		t.Fatal(status, err)
	}
	for _, mode := range []string{"upgrade", "rollback"} {
		if _, err := c.Start(context.Background(), mode); err == nil {
			t.Fatal("CD and manual updater raced")
		}
	}
	if agent.starts != 0 {
		t.Fatal("CD-managed site started a production action")
	}
}

func TestDevelopmentHeadHonorsRateLimitBackoff(t *testing.T) {
	calls := 0
	v := verifierFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(429)
	})
	for i := 0; i < 2; i++ {
		if _, err := v.DevelopmentHead(context.Background()); err == nil {
			t.Fatal("rate limit accepted")
		}
	}
	if calls != 1 {
		t.Fatal("rate limit retry bypassed backoff", calls)
	}
}
