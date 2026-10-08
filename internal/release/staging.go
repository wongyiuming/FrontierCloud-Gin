package release

import (
	"context"
	"errors"
	"sort"
	"time"
)

// DevelopmentHead is preproduction proof, never production publication proof.
// No old successful run may override the newest exact dev push.
func (v *Verifier) DevelopmentHead(ctx context.Context) (string, error) {
	select {
	case v.lock <- struct{}{}:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	defer func() { <-v.lock }()
	if v.now().Before(v.backoff) {
		return "", errors.New("development CI verification rate limited")
	}
	rememberFailure := func(err error) error {
		var failure *apiFailure
		if errors.As(err, &failure) && failure.kind == "rate_limited" {
			v.backoff = v.now().Add(time.Duration(failure.retry) * time.Second)
		}
		return err
	}
	var branch struct {
		Commit commit `json:"commit"`
	}
	if _, err := v.get(ctx, "/branches/dev", &branch); err != nil {
		return "", rememberFailure(err)
	}
	sha := branch.Commit.SHA
	if !ValidSHA(sha) {
		return "", errors.New("invalid development HEAD")
	}
	var runs struct {
		Runs []run `json:"workflow_runs"`
	}
	if _, err := v.get(ctx, "/actions/workflows/docker.yml/runs?event=push&head_sha="+sha+"&per_page=20", &runs); err != nil {
		return "", rememberFailure(err)
	}
	sort.SliceStable(runs.Runs, func(i, j int) bool { return runs.Runs[i].Number > runs.Runs[j].Number })
	for _, r := range runs.Runs {
		if r.Branch != "dev" || r.Event != "push" || r.SHA != sha {
			continue
		}
		if r.Status == "completed" && r.Conclusion != nil && *r.Conclusion == "success" {
			return sha, nil
		}
		return "", errors.New("newest exact development push CI has not succeeded")
	}
	return "", errors.New("development HEAD has no exact push CI")
}
