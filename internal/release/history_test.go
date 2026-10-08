package release

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHistoryIsBoundedReviewedDiscoveryCachedAndNotAuthorization(t *testing.T) {
	calls := 0
	v := verifierFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/pulls" || r.URL.Query().Get("base") != "main" || r.URL.Query().Get("state") != "closed" || r.URL.Query().Get("per_page") != "30" {
			t.Error("unbounded or wrong branch discovery", r.URL)
		}
		values := []map[string]any{}
		for i := 1; i <= 16; i++ {
			item := map[string]any{"number": i, "title": "<script>unsafe title is data</script>", "body": strings.Repeat("长", 5000), "merge_commit_sha": fmt.Sprintf("%040x", i), "merged_at": fmt.Sprintf("2026-10-%02dT00:00:00Z", i), "base": map[string]any{"ref": "main"}, "head": map[string]any{"ref": "dev", "sha": strings.Repeat("b", 40), "repo": map[string]any{"full_name": "wongyiuming/FrontierCloud-Gin"}}}
			if i == 16 {
				item["merged_at"] = nil
			}
			if i == 15 {
				item["head"] = map[string]any{"ref": "dev", "sha": strings.Repeat("b", 40), "repo": map[string]any{"full_name": "foreign/repo"}}
			}
			if i == 14 {
				item["merge_commit_sha"] = "invalid"
			}
			values = append(values, item)
		}
		json.NewEncoder(w).Encode(values)
	})
	now := time.Now()
	v.now = func() time.Time { return now }
	versions, err := v.History(context.Background())
	if err != nil || len(versions) != 10 || versions[0].PR != 13 {
		t.Fatal(versions, err)
	}
	if len([]rune(versions[0].Description)) > 1025 || versions[0].URL != "https://github.com/wongyiuming/FrontierCloud-Gin/pull/13" {
		t.Fatal(versions[0])
	}
	versions[0].Title = "mutated"
	again, err := v.History(context.Background())
	if err != nil || calls != 1 || again[0].Title == "mutated" {
		t.Fatal(calls, again, err)
	}
	now = now.Add(6 * time.Minute)
	if _, err = v.History(context.Background()); err != nil || calls != 2 {
		t.Fatal(calls, err)
	}
}

func TestHistoryRateLimitBackoffAvoidsRepeatedRequests(t *testing.T) {
	calls := 0
	v := verifierFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(429)
	})
	for range 2 {
		if _, err := v.History(context.Background()); err == nil {
			t.Fatal("rate limit hidden")
		}
	}
	if calls != 1 {
		t.Fatal("repeated rate-limited request", calls)
	}
}
