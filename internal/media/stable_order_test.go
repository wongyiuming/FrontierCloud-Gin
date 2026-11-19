package media

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestCatalogSortUsesPreferencePathAndIDNotPlayScore(t *testing.T) {
	items := []Track{
		{MediaPath: "music/A/z.mp3", MediaID: "b", PlaybackStats: store.PlaybackStats{Preference: 0, PlayScore: 9000}},
		{MediaPath: "music/A/a.mp3", MediaID: "b", PlaybackStats: store.PlaybackStats{Preference: 0, PlayScore: 0}},
		{MediaPath: "music/A/a.mp3", MediaID: "a", PlaybackStats: store.PlaybackStats{Preference: 0, PlayScore: 1}},
		{MediaPath: "music/A/top.mp3", MediaID: "c", PlaybackStats: store.PlaybackStats{Preference: 1, PlayScore: 0}},
		{MediaPath: "music/A/low.mp3", MediaID: "d", PlaybackStats: store.PlaybackStats{Preference: -1, PlayScore: 100000}},
	}
	sortTracks(items)
	var got []string
	for _, item := range items {
		got = append(got, item.MediaPath+":"+item.MediaID)
	}
	want := []string{"music/A/top.mp3:c", "music/A/a.mp3:a", "music/A/a.mp3:b", "music/A/z.mp3:b", "music/A/low.mp3:d"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("catalog ordering changed: %v", got)
	}
}

func TestEqualPriorityCatalogStableAcrossSessionsAndCache(t *testing.T) {
	for _, master := range []bool{false, true} {
		t.Run(map[bool]string{false: "Local", true: "Master"}[master], func(t *testing.T) {
			fixture := deleteFixture
			if master {
				fixture = masterFixture
			}
			root, db, svc := fixture(t)
			ctx := context.Background()
			if !master {
				id, e := node.Initialize(ctx, db.Nodes(), filepath.Join(t.TempDir(), "secrets"))
				if e != nil {
					t.Fatal(e)
				}
				svc.identity = id
			}
			for _, name := range []string{"zeta.mp3", "alpha.mp3", "middle.mp3"} {
				p := "music/artist/" + name
				if master {
					reservation, e := svc.ReserveMasterUpload(ctx, name, "music/artist", "", "primary", 10, 255, store.AdminAudit{})
					if e != nil {
						t.Fatal(e)
					}
					if _, e = svc.UploadMasterBytes(ctx, reservation.ID, strings.NewReader("ID3payload"), store.AdminAudit{}); e != nil {
						t.Fatal(e)
					}
				} else {
					if e := os.WriteFile(filepath.Join(root, p), []byte("ID3payload"), 0600); e != nil {
						t.Fatal(e)
					}
				}
			}
			var baseline []string
			for _, ttl := range []time.Duration{0, time.Minute} {
				svc.ConfigureCatalogCache(ttl)
				for _, session := range []string{"first-session", "second-session", "third-session", ""} {
					tracks, e := svc.Catalog(ctx, "music", "music/artist", session, false)
					if e != nil {
						t.Fatal(e)
					}
					paths := make([]string, len(tracks))
					for i, v := range tracks {
						paths[i] = v.MediaPath
					}
					if baseline == nil {
						baseline = paths
					}
					if !reflect.DeepEqual(paths, baseline) {
						t.Fatalf("session/cache reordered %v -> %v", baseline, paths)
					}
					if len(paths) != 4 || paths[0] != "music/artist/alpha.mp3" || paths[3] != "music/artist/zeta.mp3" {
						t.Fatal("non-deterministic path ordering", paths)
					}
				}
			}
			if _, e := db.Media().SetPreference(ctx, store.MediaObject{Path: "music/artist/zeta.mp3", Kind: "audio"}, 99, store.AdminAudit{}); e != nil {
				t.Fatal(e)
			}
			tracks, e := svc.Catalog(ctx, "music", "music/artist", "new-session", false)
			if e != nil || tracks[0].MediaPath != "music/artist/zeta.mp3" {
				t.Fatal("priority no longer sorts first", tracks, e)
			}
		})
	}
}
