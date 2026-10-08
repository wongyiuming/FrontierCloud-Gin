package release

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// History is discovery, never rollback authorization. StartVersion verifies
// the selected exact tree/CI; the updater independently checks Git ancestry.
type Version struct {
	SHA         string `json:"sha"`
	SourceSHA   string `json:"source_sha"`
	Title       string `json:"title"`
	Description string `json:"description"`
	MergedAt    string `json:"merged_at"`
	URL         string `json:"url"`
	PR          int    `json:"pr"`
}

func (v *Verifier) History(parent context.Context) ([]Version, error) {
	select {
	case v.lock <- struct{}{}:
	case <-parent.Done():
		return nil, parent.Err()
	}
	defer func() { <-v.lock }()
	now := v.now()
	if now.Before(v.backoff) {
		return nil, errors.New("release history rate limited")
	}
	if v.history != nil && now.Sub(v.historyChecked) < 5*time.Minute {
		return append([]Version(nil), v.history...), nil
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	var pulls []pull
	if _, err := v.get(ctx, "/pulls?state=closed&base="+url.QueryEscape(v.policy.Branch)+"&sort=updated&direction=desc&per_page=30", &pulls); err != nil {
		var failure *apiFailure
		if errors.As(err, &failure) && failure.kind == "rate_limited" {
			v.backoff = now.Add(time.Duration(failure.retry) * time.Second)
		}
		return nil, err
	}
	versions := []Version{}
	seen := map[string]bool{}
	for _, p := range pulls {
		if p.Merged == nil || *p.Merged == "" || !ValidSHA(p.MergeSHA) || !ValidSHA(p.Head.SHA) || p.Base.Ref != v.policy.Branch || p.Head.Ref != v.policy.Source || p.Head.Repo.FullName != "wongyiuming/FrontierCloud-Gin" || p.Number < 1 || seen[p.MergeSHA] {
			continue
		}
		seen[p.MergeSHA] = true
		title := strings.TrimSpace(p.Title)
		if title == "" {
			title = "Reviewed release " + p.MergeSHA[:12]
		}
		// Bound public display data and avoid letting PR text become HTML or SQL.
		if len(title) > 512 {
			title = string([]rune(title)[:min(len([]rune(title)), 128)])
		}
		description := strings.TrimSpace(p.Body)
		if len(description) > 4096 {
			description = string([]rune(description)[:min(len([]rune(description)), 1024)]) + "…"
		}
		versions = append(versions, Version{p.MergeSHA, p.Head.SHA, title, description, *p.Merged, fmt.Sprintf("https://github.com/wongyiuming/FrontierCloud-Gin/pull/%d", p.Number), p.Number})
	}
	sort.SliceStable(versions, func(i, j int) bool { return versions[i].MergedAt > versions[j].MergedAt })
	if len(versions) > 10 {
		versions = versions[:10]
	}
	v.history, v.historyChecked = append([]Version(nil), versions...), now
	return versions, nil
}
