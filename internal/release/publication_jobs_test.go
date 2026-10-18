package release

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestPublicationReportsActualBuildPublishAndAliasJob(t *testing.T) {
	sha := strings.Repeat("a", 40)
	for name, want := range map[string]string{"compile (web)": "image_build_running", "publish (nginx)": "image_publish_running", "publish-latest": "image_alias_promotion_running", "plan": "image_build_or_publication_running"} {
		t.Run(name, func(t *testing.T) {
			v := verifierFixture(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.Path, "docker.yml"):
					fmt.Fprintf(w, `{"workflow_runs":[{"head_sha":%q,"head_branch":"main","event":"push","run_number":1,"status":"completed","conclusion":"success"}]}`, sha)
				case strings.Contains(r.URL.Path, "publish-images.yml"):
					fmt.Fprintf(w, `{"workflow_runs":[{"id":12,"run_attempt":2,"head_sha":%q,"head_branch":"main","event":"workflow_run","run_number":2,"status":"in_progress"}]}`, sha)
				case r.URL.Path == "/actions/runs/12/attempts/2/jobs":
					fmt.Fprintf(w, `{"jobs":[{"name":%q,"status":"in_progress"}]}`, name)
				default:
					t.Error("unexpected job lookup", r.URL)
					w.WriteHeader(404)
				}
			})
			p, err := v.Publication(context.Background(), sha)
			if err != nil || p.Stage != want {
				t.Fatal(p, err)
			}
		})
	}
}
