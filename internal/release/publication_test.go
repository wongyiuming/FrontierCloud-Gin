package release

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestPublicationDistinguishesCIAndPublisherStages(t *testing.T) {
	sha := strings.Repeat("a", 40)
	for _, stage := range []string{"main_ci_waiting", "main_ci_running", "main_ci_failed", "image_publication_waiting", "image_build_or_publication_running", "image_publication_failed", "published"} {
		t.Run(stage, func(t *testing.T) {
			v := verifierFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("head_sha") != sha {
					t.Error("unbound publication query")
				}
				ci := strings.Contains(r.URL.Path, "docker.yml")
				event := "workflow_run"
				if ci {
					event = "push"
				}
				if r.URL.Query().Get("event") != event {
					t.Error("wrong event")
				}
				candidate := map[string]any{"head_sha": sha, "head_branch": "main", "event": event, "run_number": 9, "status": "completed", "conclusion": "success"}
				runs := []any{candidate}
				if ci && strings.HasPrefix(stage, "main_ci_") || !ci && strings.HasPrefix(stage, "image_") {
					switch {
					case strings.HasSuffix(stage, "waiting"):
						runs = nil
					case strings.HasSuffix(stage, "running"):
						candidate["status"] = "in_progress"
						candidate["conclusion"] = nil
					case strings.HasSuffix(stage, "failed"):
						candidate["conclusion"] = "failure"
					}
				}
				// Older success never masks a newer failure/pending attempt.
				if len(runs) > 0 {
					runs = append(runs, map[string]any{"head_sha": sha, "head_branch": "main", "event": event, "run_number": 8, "status": "completed", "conclusion": "success"})
				}
				json.NewEncoder(w).Encode(map[string]any{"workflow_runs": runs})
			})
			p, err := v.Publication(context.Background(), sha)
			if err != nil || p.Stage != stage {
				t.Fatal(p, err)
			}
		})
	}
}

func TestPublicationRejectsForeignRunAndReportsAPIFailure(t *testing.T) {
	for _, kind := range []string{"branch", "event", "sha", "network-api"} {
		t.Run(kind, func(t *testing.T) {
			sha := strings.Repeat("a", 40)
			v := verifierFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if kind == "network-api" {
					w.WriteHeader(503)
					return
				}
				run := map[string]any{"head_sha": sha, "head_branch": "main", "event": "push", "run_number": 5, "status": "completed", "conclusion": "success"}
				switch kind {
				case "branch":
					run["head_branch"] = "dev"
				case "event":
					run["event"] = "workflow_dispatch"
				case "sha":
					run["head_sha"] = strings.Repeat("b", 40)
				}
				json.NewEncoder(w).Encode(map[string]any{"workflow_runs": []any{run}})
			})
			p, err := v.Publication(context.Background(), sha)
			if kind == "network-api" {
				if err == nil || !strings.Contains(err.Error(), "503") {
					t.Fatal(err)
				}
				return
			}
			if err != nil || p.Stage != "main_ci_waiting" {
				t.Fatal(p, err)
			}
		})
	}
}
