package release

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// PublicationState is read from the exact main CI and trusted publisher, never
// inferred from a registry 404. A newer failed/running attempt overrides success.
type PublicationState struct {
	Revision string `json:"revision"`
	Stage    string `json:"stage"`
}

func (p PublicationState) Error() string {
	return fmt.Sprintf("release %s: %s; not eligible for upgrade", p.Revision, p.Stage)
}

func (v *Verifier) Publication(parent context.Context, target string) (PublicationState, error) {
	p := PublicationState{Revision: target}
	if !ValidSHA(target) {
		return p, ErrManifest
	}
	select {
	case v.lock <- struct{}{}:
	case <-parent.Done():
		return p, parent.Err()
	}
	defer func() { <-v.lock }()
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	for _, workflow := range []struct{ file, event, waiting, running, failed string }{
		{"docker.yml", "push", "main_ci_waiting", "main_ci_running", "main_ci_failed"},
		{"publish-images.yml", "workflow_run", "image_publication_waiting", "image_build_or_publication_running", "image_publication_failed"},
	} {
		var result struct {
			Runs []run `json:"workflow_runs"`
		}
		_, err := v.get(ctx, "/actions/workflows/"+workflow.file+"/runs?event="+workflow.event+"&head_sha="+target+"&per_page=20", &result)
		if err != nil {
			return p, SafeVerificationFailure(err)
		}
		sort.SliceStable(result.Runs, func(i, j int) bool { return result.Runs[i].Number > result.Runs[j].Number })
		p.Stage = workflow.waiting
		for _, r := range result.Runs {
			if r.SHA != target || r.Branch != v.policy.Branch || r.Event != workflow.event {
				continue
			}
			p.Stage = workflow.running
			if r.Status == "completed" {
				p.Stage = workflow.failed
				if r.Conclusion != nil && *r.Conclusion == "success" {
					p.Stage = "published"
				}
			}
			if workflow.event == "workflow_run" && r.Status != "completed" && r.ID > 0 && r.Attempt > 0 {
				var jobs struct {
					Jobs []struct {
						Name   string `json:"name"`
						Status string `json:"status"`
					} `json:"jobs"`
				}
				route := fmt.Sprintf("/actions/runs/%d/attempts/%d/jobs?per_page=100", r.ID, r.Attempt)
				if _, err := v.get(ctx, route, &jobs); err != nil {
					return p, SafeVerificationFailure(err)
				}
				for _, job := range jobs.Jobs {
					if job.Status != "in_progress" {
						continue
					}
					switch {
					case strings.HasPrefix(job.Name, "compile ("):
						p.Stage = "image_build_running"
					case strings.HasPrefix(job.Name, "publish ("):
						p.Stage = "image_publish_running"
					case job.Name == "publish-latest":
						p.Stage = "image_alias_promotion_running"
					}
				}
			}
			break
		}
		if p.Stage != "published" {
			return p, nil
		}
	}
	return p, nil
}

func (v *Verifier) MainHead(ctx context.Context) (string, error) {
	var branch struct {
		Commit commit `json:"commit"`
	}
	if _, err := v.get(ctx, "/branches/"+v.policy.Branch, &branch); err != nil {
		return "", SafeVerificationFailure(err)
	}
	if !ValidSHA(branch.Commit.SHA) {
		return "", ErrManifest
	}
	return branch.Commit.SHA, nil
}

// Relation rejects implicit downgrades and unrelated releases. GitHub's ahead
// means target descends from installed; behind means installed is newer.
func (v *Verifier) Relation(ctx context.Context, installed, target string) (string, error) {
	if !ValidSHA(installed) || !ValidSHA(target) {
		return "", ErrManifest
	}
	if installed == target {
		return "identical", nil
	}
	var result struct {
		Status string `json:"status"`
	}
	if _, err := v.get(ctx, "/compare/"+installed+"..."+target, &result); err != nil {
		return "", SafeVerificationFailure(err)
	}
	switch result.Status {
	case "ahead", "behind", "identical":
		return result.Status, nil
	}
	return "", errors.New("release history diverged; automatic upgrade refused")
}
