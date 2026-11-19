package httpapi

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Record the previous plaintext endpoint's behavior independently of the new
// encrypted tree. It does not confer access to encrypted lyric keys or bytes.
func TestLegacyPlainLyricHTTPFallbackAndHiddenTrack(t *testing.T) {
	for _, master := range []bool{false, true} {
		label := "Standalone"
		if master {
			label = "Master"
		}
		t.Run(label, func(t *testing.T) {
			router, db, dir, public := publicFixture(t, false)
			ctx := context.Background()
			if master {
				// The legacy revision predates configurable ingress origins.
				if current, ok := any(public.control).(interface{ ConfigurePublicOrigin(string) error }); ok {
					if err := current.ConfigurePublicOrigin("https://lyric-master.test"); err != nil {
						t.Fatal(err)
					}
				}
				if err := public.media.WithPromotion(ctx, "Master", func(p store.NodePromotion) error {
					p.Endpoint, p.Allocation = "https://lyric-master.test", 10*store.GiB
					_, err := db.Nodes().PromoteIdentity(ctx, p, store.NodeAudit{})
					return err
				}); err != nil {
					t.Fatal(err)
				}
				public.media.ConfigureCluster(db.Nodes(), db.Pool(), nil)
			}
			url := "/api/v1/media/lyrics/content?track=music/artist/song.mp3"
			check := func(want string) {
				t.Helper()
				w := request(router, "GET", url, "")
				if w.Code != 200 || !strings.Contains(w.Body.String(), want) {
					t.Fatalf("legacy lyric response: %d %q", w.Code, w.Body.String())
				}
			}
			check("建设中，暂无歌词")
			if err := public.media.Hide(ctx, []string{"music/artist"}, true, store.AdminAudit{}); err != nil {
				t.Fatal(err)
			}
			check("建设中，暂无歌词")
			lyric := "lyrics/fixture.lrc"
			if err := os.WriteFile(filepath.Join(dir, "media", filepath.FromSlash(lyric)), []byte("[00:01]explicit fixture\n"), 0644); err != nil {
				t.Fatal(err)
			}
			if _, err := public.media.ReplaceLyrics(ctx, "track", "music/artist/song.mp3", []string{lyric}, store.AdminAudit{}); err != nil {
				t.Fatal(err)
			}
			check("explicit fixture")
			if err := os.WriteFile(filepath.Join(dir, "media", filepath.FromSlash(lyric)), []byte("not timed lyrics\n"), 0644); err != nil {
				t.Fatal(err)
			}
			if got := request(router, "GET", url, ""); got.Code != 404 || strings.Contains(got.Body.String(), "建设中，暂无歌词") {
				t.Fatalf("existing malformed lyric must not become fallback: %d %q", got.Code, got.Body.String())
			}
			if err := os.Remove(filepath.Join(dir, "media", filepath.FromSlash(lyric))); err != nil {
				t.Fatal(err)
			}
			check("建设中，暂无歌词")
		})
	}
}

func TestLegacyKaraokeHiddenPlainLyricHTTP(t *testing.T) {
	router, _, dir, public := publicFixture(t, false)
	resolver, err := network.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	RegisterKaraokeMedia(router, public, resolver)
	catalog := request(router, "GET", "/api/v1/media/catalog/media?media_type=music&path=music/artist&playback_session_id=fixture", "")
	var data struct{ Entries []media.Track }
	if catalog.Code != 200 || json.Unmarshal(catalog.Body.Bytes(), &data) != nil || len(data.Entries) != 1 || data.Entries[0].KaraokeID == "" {
		t.Fatal("fixture catalog", catalog.Code, catalog.Body.String())
	}
	lyric := "lyrics/fixture.lrc"
	if err := os.WriteFile(filepath.Join(dir, "media", filepath.FromSlash(lyric)), []byte("[00:01]explicit fixture\n"), 0644); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := public.media.ReplaceLyrics(ctx, "track", "music/artist/song.mp3", []string{lyric}, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	target := "/api/v1/karaoke/lyrics?" + url.Values{"media": {data.Entries[0].KaraokeID}}.Encode()
	if got := request(router, "GET", target, ""); got.Code != 200 || !strings.Contains(got.Body.String(), "explicit fixture") {
		t.Fatalf("visible karaoke lyric: %d %q", got.Code, got.Body.String())
	}
	if err := public.media.Hide(ctx, []string{"music/artist"}, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	got := request(router, "GET", target, "")
	if got.Code != 200 || !strings.Contains(got.Body.String(), "explicit fixture") {
		t.Fatalf("hidden karaoke lyric: %d %q", got.Code, got.Body.String())
	}
}
