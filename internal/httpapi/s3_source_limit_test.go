package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestS3SourceBrowsingBudgetKeepsOrdinaryPlaybackAdmission(t *testing.T) {
	f := newS3HTTP(t, "Master")
	f.enable(t, f.add(t))
	// Album metadata reads obtain the same short-lived source grants as playback.
	// They must not exhaust the eight-per-minute ECDH creation allowance.
	for i := range 20 {
		row := f.publish(t, fmt.Sprintf("music/album/track-%02d.mp3", i), nil)
		body := fmt.Sprintf(`{"file_path":%q,"object_id":%q}`, row.Path, row.ObjectID)
		if response := f.call(http.MethodPost, "/api/v1/media/crypto/source", body, true, false, true); response.Code != http.StatusOK {
			t.Fatalf("album source %d denied before playback: status %d", i+1, response.Code)
		}
	}
	if len(f.public.cryptoSessionLimit.windows) != 0 {
		t.Fatal("source metadata reads consumed ECDH admission")
	}
}

func TestS3SourceAdmissionKeepsBrowserIPAndGlobalBudgets(t *testing.T) {
	now := time.Unix(1800000000, 0)
	t.Run("shared-IP-and-cookie-rotation", func(t *testing.T) {
		a := s3SourceAdmission{now: func() time.Time { return now }}
		// Four independent listeners behind one NAT can each browse an album.
		for browser := range s3SourceIPGrants / s3SourceCookieGrants {
			binding := fmt.Sprintf("browser:%d", browser)
			for range s3SourceCookieGrants {
				if !a.allow("198.51.100.1", binding) {
					t.Fatal("one browser exhausted another browser's budget")
				}
			}
			if a.allow("198.51.100.2", binding) {
				t.Fatal("IP rotation bypassed the browser limit")
			}
		}
		if a.allow("198.51.100.1", "rotated-cookie") {
			t.Fatal("cookie rotation bypassed the real IP limit")
		}
		if !a.allow("198.51.100.2", "another-browser") {
			t.Fatal("one real peer exhausted a different peer")
		}
		if a.windows["global"].count != s3SourceIPGrants+1 {
			t.Fatal("denied requests consumed other budgets")
		}
	})
	t.Run("global", func(t *testing.T) {
		a := s3SourceAdmission{now: func() time.Time { return now }}
		for i := range s3SourceGlobalGrants {
			if !a.allow(fmt.Sprintf("198.51.100.%d", i/s3SourceCookieGrants+1), fmt.Sprintf("browser:%d", i)) {
				t.Fatal("global budget denied before its exact limit", i)
			}
		}
		if a.allow("203.0.113.1", "another-browser") {
			t.Fatal("independent peers bypassed the process budget")
		}
		if len(a.windows) > s3SourceAdmissionEntries {
			t.Fatal("source admission cache exceeded its bound")
		}
	})
}

func TestS3SourceAdmissionReclaimsExpiredBoundedState(t *testing.T) {
	now := time.Unix(1800000000, 0)
	a := s3SourceAdmission{now: func() time.Time { return now }, windows: map[string]s3SourceWindow{}}
	for i := range s3SourceAdmissionEntries - 2 {
		a.windows[fmt.Sprint(i)] = s3SourceWindow{1, now.Add(s3SourceGrantWindow)}
	}
	before := len(a.windows)
	if a.allow("198.51.100.1", "first-browser") || len(a.windows) != before {
		t.Fatal("full cache partially admitted a new budget")
	}
	now = now.Add(s3SourceGrantWindow)
	if !a.allow("198.51.100.1", "first-browser") || len(a.windows) != 3 {
		t.Fatal("expired cache did not reclaim its exact bounded state")
	}
	if a.allow("", "first-browser") || a.allow("198.51.100.1", "") || len(a.windows) != 3 {
		t.Fatal("missing identities changed admission state")
	}
	for range s3SourceCookieGrants - 1 {
		if !a.allow("198.51.100.1", "first-browser") {
			t.Fatal("reclaimed browser window was not usable")
		}
	}
	if a.allow("198.51.100.1", "first-browser") {
		t.Fatal("reclaimed window lost its limit")
	}
	now = now.Add(s3SourceGrantWindow)
	if !a.allow("198.51.100.1", "first-browser") {
		t.Fatal("expired browser window stayed locked out")
	}
}

func TestS3SourceAdmissionConcurrentBudgetIsAtomic(t *testing.T) {
	now := time.Unix(1800000000, 0)
	a := s3SourceAdmission{now: func() time.Time { return now }}
	var admitted atomic.Int32
	var workers sync.WaitGroup
	for range s3SourceCookieGrants * 2 {
		workers.Go(func() {
			if a.allow("198.51.100.1", "one-browser") {
				admitted.Add(1)
			}
		})
	}
	workers.Wait()
	if admitted.Load() != s3SourceCookieGrants {
		t.Fatal("concurrent source requests escaped the exact browser budget", admitted.Load())
	}
	for _, key := range []string{"global", "ip:198.51.100.1", "cookie:one-browser"} {
		if a.windows[key].count != s3SourceCookieGrants {
			t.Fatal("concurrent denial partially charged another budget", key)
		}
	}
}

func TestS3SourceAdmissionUsesOnlyConfiguredTrustedProxy(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		t.Run(fmt.Sprint(trusted), func(t *testing.T) {
			p := &Public{}
			if trusted {
				p.settings.TrustedProxyNetworks = []string{"10.0.0.0/8"}
			}
			count := 0
			check := func(peer, forwarded string) *httptest.ResponseRecorder {
				response := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(response)
				c.Request = httptest.NewRequest(http.MethodPost, "/source", nil)
				c.Request.RemoteAddr = peer + ":12345"
				c.Request.Header.Set("X-Real-IP", forwarded)
				count++
				if p.allowPublicS3Source(c, fmt.Sprintf("browser:%064x", count)) {
					c.Status(http.StatusNoContent)
				}
				c.Writer.WriteHeaderNow()
				return response
			}
			peer, forwarded := "198.51.100.1", "203.0.113.1"
			if trusted {
				peer, forwarded = "10.1.2.3", "198.51.100.1"
			}
			for i := range s3SourceIPGrants {
				if !trusted {
					forwarded = fmt.Sprintf("203.0.113.%d", i%254+1)
				}
				if response := check(peer, forwarded); response.Code != http.StatusNoContent {
					t.Fatal("source client denied before its real IP budget", i, response.Code)
				}
			}
			if response := check(peer, forwarded); response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "60" {
				t.Fatal("forged identity or cookie rotation bypassed IP admission", response.Code)
			}
			if trusted {
				forwarded = "198.51.100.2"
			} else {
				peer = "198.51.100.2"
			}
			if response := check(peer, forwarded); response.Code != http.StatusNoContent {
				t.Fatal("independent client shared another client's window", response.Code)
			}
		})
	}
}
