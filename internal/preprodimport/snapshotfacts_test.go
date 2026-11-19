package preprodimport

import (
	"strings"
	"testing"
)

func syntheticCompleteFacts(s Snapshot) sourceCompleteFacts {
	f := sourceCompleteFacts{DeclaredSections: []string{"objects", "placements", "visibility", "playback", "lyric_links", "encryption"}}
	f.Objects = append(f.Objects, sourceObjectFact{ID: strings.Repeat("6", 64), Kind: "audio", Path: "music/other/local.mp3", CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z"})
	for _, d := range s.Directories {
		f.Objects = append(f.Objects, sourceObjectFact{ID: d.ID, Kind: "directory", Path: d.Path, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z"})
	}
	for _, m := range s.Media {
		f.Placements = append(f.Placements, sourcePlacementFact{MediaID: m.MediaID, State: "active", ETag: "opaque", CreatedAt: 1, UpdatedAt: 2})
		if m.Encryption != nil {
			f.Encryption = append(f.Encryption, sourceEncryptionFact{Kind: "media", ObjectID: m.MediaID, FileID: m.Encryption.FileID, CreatedAt: 1})
		}
	}
	for _, v := range s.Visibility {
		hidden := int64(0)
		if v.Hidden {
			hidden = 1
		}
		f.Visibility = append(f.Visibility, sourceVisibilityFact{Path: v.Path, Hidden: hidden, UpdatedAt: "2026-01-01T00:00:00Z"})
	}
	for _, p := range s.Preferences {
		f.Playback = append(f.Playback, sourcePlaybackFact{MediaID: p.ID, Path: "music/album", Preference: p.Value, PlayScore: p.PlayScore, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z"})
	}
	for _, l := range s.Links {
		f.LyricLinks = append(f.LyricLinks, sourceLyricLinkFact{MediaID: l.MediaID, LyricID: l.LyricID, MediaPath: "music/album/song.mp3", LyricPath: "lyrics/a/song.lrc", CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z"})
	}
	for _, n := range s.RetiredNonces {
		f.Encryption = append(f.Encryption, sourceEncryptionFact{Kind: "media", ObjectID: n.ObjectID, FileID: n.FileID, CreatedAt: 1})
	}
	return f
}

func TestSyntheticCompleteSnapshotBindsSourceFacts(t *testing.T) {
	s, _, _, _ := fixture(t)
	all := completeSnapshot{Projection: s, Facts: syntheticCompleteFacts(s)}
	original, err := completeSnapshotDigest(all)
	if err != nil {
		t.Fatal(err)
	}
	changed := all
	changed.Facts.Placements = append([]sourcePlacementFact(nil), all.Facts.Placements...)
	changed.Facts.Placements[0].UpdatedAt++
	other, err := completeSnapshotDigest(changed)
	if err != nil || other == original {
		t.Fatalf("placement time not bound: %v", err)
	}
	missing := all
	missing.Facts.LyricLinks = nil
	if _, err := completeSnapshotDigest(missing); err == nil {
		t.Fatal("missing lyric facts accepted")
	}
	missing = all
	missing.Facts.DeclaredSections = append([]string(nil), all.Facts.DeclaredSections[:5]...)
	if _, err := completeSnapshotDigest(missing); err == nil {
		t.Fatal("undeclared encryption facts accepted")
	}
	changed = all
	changed.Facts.Visibility = append([]sourceVisibilityFact(nil), all.Facts.Visibility...)
	changed.Facts.Visibility[0].Hidden = 1 - changed.Facts.Visibility[0].Hidden
	if _, err := completeSnapshotDigest(changed); err == nil {
		t.Fatal("visibility conflict accepted")
	}
	changed = all
	changed.Facts.Visibility = append([]sourceVisibilityFact(nil), all.Facts.Visibility...)
	changed.Facts.Visibility[0].Hidden = 2
	if _, err := completeSnapshotDigest(changed); err == nil {
		t.Fatal("invalid stored hidden value accepted")
	}
	changed = all
	changed.Facts.Objects = append([]sourceObjectFact(nil), all.Facts.Objects...)
	changed.Facts.Objects[1].Path = "music/wrong"
	if _, err := completeSnapshotDigest(changed); err == nil {
		t.Fatal("known directory mapped to wrong path")
	}
	changed = all
	changed.Facts.Placements = append([]sourcePlacementFact(nil), all.Facts.Placements...)
	changed.Facts.Placements[0].State = "unknown"
	if _, err := completeSnapshotDigest(changed); err == nil {
		t.Fatal("unknown placement state accepted")
	}
}
