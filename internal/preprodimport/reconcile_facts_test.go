package preprodimport

import (
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

func TestReconcilePlainAndLyricFactsRequiresExactSource(t *testing.T) {
	id, lyricID := strings.Repeat("1", 64), strings.Repeat("2", 64)
	media := Media{MediaID: id, Path: "music/album/song.mp3", Kind: "audio"}
	complete := completeSnapshot{Facts: sourceCompleteFacts{
		Objects:    []sourceObjectFact{{ID: id, Kind: "audio", Path: media.Path, CreatedAt: "created", UpdatedAt: "updated"}},
		Visibility: []sourceVisibilityFact{{Path: media.Path, Hidden: 1, UpdatedAt: "hidden"}},
		Playback:   []sourcePlaybackFact{{MediaID: id, Path: "music/old.mp3", Preference: 2, PlayScore: 7, CreatedAt: "p-created", UpdatedAt: "p-updated"}},
		LyricLinks: []sourceLyricLinkFact{{MediaID: id, MediaPath: "music/old.mp3", LyricID: lyricID, LyricPath: "lyrics/old.lrc", CreatedAt: "l-created", UpdatedAt: "l-updated"}},
	}}
	exact := sealedtree.Facts{ObjectID: id,
		Object:     &sealedtree.ObjectFact{CreatedAt: "created", UpdatedAt: "updated"},
		Visibility: &sealedtree.VisibilityFact{Hidden: 1, UpdatedAt: "hidden"},
		Playback:   &sealedtree.PlaybackFact{LegacyMediaPath: "music/old.mp3", Preference: 2, PlayScore: 7, CreatedAt: "p-created", UpdatedAt: "p-updated"},
		Lyric:      &sealedtree.LyricFact{LegacyMediaPath: "music/old.mp3", LyricID: lyricID, LegacyLyricPath: "lyrics/old.lrc", CreatedAt: "l-created", UpdatedAt: "l-updated"},
	}
	if err := reconcileSourceObjectFacts(complete, media, exact, nil); err != nil {
		t.Fatal(err)
	}
	// An authenticated explicit link to the built-in default stays an
	// internal fallback, never an ordinary user-manageable relation.
	complete.Projection.Lyrics = []Lyric{{ID: lyricID, Path: "lyrics/default.lrc", Builtin: true}}
	complete.Facts.LyricLinks[0].LyricPath = "lyrics/default.lrc"
	if reconcileSourceObjectFacts(complete, media, exact, nil) == nil {
		t.Fatal("builtin fallback accepted as ordinary lyric relation")
	}
	fallback := exact
	fallback.Lyric = nil
	fallback.InternalDefaultLyric = &sealedtree.DefaultLyricFact{LegacyMediaPath: "music/old.mp3", DefaultLyricID: lyricID, CreatedAt: "l-created", UpdatedAt: "l-updated"}
	if err := reconcileSourceObjectFacts(complete, media, fallback, nil); err != nil {
		t.Fatal(err)
	}
	complete.Facts.LyricLinks[0].LyricPath = "lyrics/old.lrc"
	if reconcileSourceObjectFacts(complete, media, fallback, nil) == nil {
		t.Fatal("wrong default path accepted")
	}
	complete.Projection.Lyrics[0].Builtin = false
	tests := map[string]func(*sealedtree.Facts){
		"missing visibility":    func(f *sealedtree.Facts) { f.Visibility = nil },
		"changed hidden":        func(f *sealedtree.Facts) { f.Visibility = &sealedtree.VisibilityFact{Hidden: 0, UpdatedAt: "hidden"} },
		"changed playback":      func(f *sealedtree.Facts) { f.Playback = nil },
		"wrong lyric":           func(f *sealedtree.Facts) { f.Lyric = &sealedtree.LyricFact{LyricID: strings.Repeat("3", 64)} },
		"changed creation":      func(f *sealedtree.Facts) { f.Object = &sealedtree.ObjectFact{CreatedAt: "other", UpdatedAt: "updated"} },
		"unexpected revocation": func(f *sealedtree.Facts) { f.Revocation = &sealedtree.RevocationIntent{} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			bad := exact
			mutate(&bad)
			if reconcileSourceObjectFacts(complete, media, bad, nil) == nil {
				t.Fatal("mismatched pending facts accepted")
			}
		})
	}
	lyric := Media{MediaID: lyricID, Path: "lyrics/album/song.lrc", Kind: "lyric"}
	complete.Facts.Objects = append(complete.Facts.Objects, sourceObjectFact{ID: lyricID, Kind: "lyric", Path: lyric.Path, CreatedAt: "a", UpdatedAt: "b"})
	complete.Facts.Visibility = append(complete.Facts.Visibility, sourceVisibilityFact{Path: lyric.Path, Hidden: 0, UpdatedAt: "v"})
	lyricFacts := sealedtree.Facts{ObjectID: lyricID, Object: &sealedtree.ObjectFact{CreatedAt: "a", UpdatedAt: "b"}, Visibility: &sealedtree.VisibilityFact{Hidden: 0, UpdatedAt: "v"}}
	if err := reconcileSourceObjectFacts(complete, lyric, lyricFacts, nil); err != nil {
		t.Fatal(err)
	}
	lyricFacts.Visibility = nil
	if reconcileSourceObjectFacts(complete, lyric, lyricFacts, nil) == nil {
		t.Fatal("explicit visible lyric collapsed into missing row")
	}
}

func TestSourceLyricResolutionBindsSnapshotGenerationAndMode(t *testing.T) {
	id, lyricID := strings.Repeat("a", 64), strings.Repeat("b", 64)
	digest, generation := strings.Repeat("c", 64), strings.Repeat("d", 64)
	media := Media{MediaID: id, Kind: "audio"}
	complete := completeSnapshot{}
	none, err := sourceLyricResolution(complete, media, digest, generation)
	if err != nil || none.State != "none" || none.SourceDigest != digest || none.SourceGeneration != generation {
		t.Fatal("missing source association", err)
	}
	complete.Facts.LyricLinks = []sourceLyricLinkFact{{MediaID: id, LyricID: lyricID, LyricPath: "lyrics/default.lrc"}}
	complete.Projection.Lyrics = []Lyric{{ID: lyricID, Path: "lyrics/default.lrc", Builtin: true}}
	fallback, err := sourceLyricResolution(complete, media, digest, generation)
	if err != nil || fallback.State != "default" || fallback.Evidence == none.Evidence {
		t.Fatal("default evidence", err)
	}
	complete.Projection.Lyrics[0].Builtin = false
	explicit, err := sourceLyricResolution(complete, media, digest, generation)
	if err != nil || explicit.State != "explicit" || explicit.Evidence == fallback.Evidence {
		t.Fatal("explicit evidence", err)
	}
	changed, err := sourceLyricResolution(complete, media, strings.Repeat("e", 64), generation)
	if err != nil || changed.Evidence == explicit.Evidence {
		t.Fatal("source digest not bound", err)
	}
	changed, err = sourceLyricResolution(complete, media, digest, strings.Repeat("f", 64))
	if err != nil || changed.Evidence == explicit.Evidence {
		t.Fatal("generation not bound", err)
	}
	complete.Projection.Lyrics[0].Builtin = true
	complete.Facts.LyricLinks[0].LyricPath = "lyrics/other.lrc"
	if _, err = sourceLyricResolution(complete, media, digest, generation); err == nil {
		t.Fatal("mismatched builtin path accepted")
	}
}
