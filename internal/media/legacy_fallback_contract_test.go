package media

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// This is a compatibility observation for the old plaintext implementation,
// not an assertion that an encrypted tree may retain or mutate plaintext paths.
func TestLegacyDefaultLyricFallbackContract(t *testing.T) {
	for _, master := range []bool{false, true} {
		name := "Standalone"
		fixture := deleteFixture
		if master {
			name, fixture = "Master", masterFixture
		}
		t.Run(name, func(t *testing.T) {
			root, db, svc := fixture(t)
			ctx := context.Background()
			track := "music/artist/song.mp3"
			read := func() ([]LyricEntry, error) {
				if master {
					return svc.LyricsResource(ctx, track, "")
				}
				return svc.Lyrics(ctx, track)
			}
			want := []LyricEntry{{Time: 0, Text: "建设中，暂无歌词"}}
			if got, err := read(); err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("missing link fallback: %#v, %v", got, err)
			}
			// Hiding the source does not change this legacy lyric endpoint's
			// fallback behavior; it does not grant access to private lyrics.
			if err := svc.Hide(ctx, []string{"music/artist"}, true, store.AdminAudit{}); err != nil {
				t.Fatal(err)
			}
			if got, err := read(); err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("hidden track fallback: %#v, %v", got, err)
			}
			if err := svc.Hide(ctx, []string{"music/artist"}, false, store.AdminAudit{}); err != nil {
				t.Fatal(err)
			}
			custom := "lyrics/artist/song.lrc"
			if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(custom)), []byte("[00:01]explicit fixture\n"), 0644); err != nil {
				t.Fatal(err)
			}
			if _, err := svc.ReplaceLyrics(ctx, "track", track, []string{custom}, store.AdminAudit{}); err != nil {
				t.Fatal(err)
			}
			if got, err := read(); err != nil || !reflect.DeepEqual(got, []LyricEntry{{Time: 1, Text: "explicit fixture"}}) {
				t.Fatalf("explicit lyric displaced by fallback: %#v, %v", got, err)
			}
			if err := svc.Hide(ctx, []string{"music/artist"}, true, store.AdminAudit{}); err != nil {
				t.Fatal(err)
			}
			if got, err := read(); err != nil || !reflect.DeepEqual(got, []LyricEntry{{Time: 1, Text: "explicit fixture"}}) {
				t.Fatalf("legacy hidden track explicit plaintext lyric: %#v, %v", got, err)
			}
			if err := svc.Hide(ctx, []string{"music/artist"}, false, store.AdminAudit{}); err != nil {
				t.Fatal(err)
			}
			ids, err := db.Media().EnsureObjects(ctx, []store.MediaObject{{Path: track, Kind: "audio"}})
			if err != nil {
				t.Fatal(err)
			}
			if got, err := db.Media().LyricPath(ctx, ids[track]); err != nil || got != custom {
				t.Fatalf("explicit association changed: %q, %v", got, err)
			}
			if err := os.Remove(filepath.Join(root, filepath.FromSlash(custom))); err != nil {
				t.Fatal(err)
			}
			if got, err := read(); err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("missing linked file fallback: %#v, %v", got, err)
			}
			if got, err := db.Media().LyricPath(ctx, ids[track]); err != nil || got != defaultLyric {
				t.Fatalf("missing linked file was not replaced by default: %q, %v", got, err)
			}
		})
	}
}
