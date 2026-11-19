package preprodimport

import (
	"reflect"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

// reconcileSourceObjectFacts compares the durable pending facts with the
// already-authenticated complete source projection. A missing optional row and
// an explicit false value remain distinct. It is an observation, not a permit
// to publish, and the caller must hold and recheck its tree lease.
func reconcileSourceObjectFacts(s completeSnapshot, media Media, actual sealedtree.Facts, resolution *sealedtree.LyricResolutionFact) error {
	expected, err := sourceObjectTreeFacts(s, media, resolution)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, expected) {
		return invalid("pending source facts mismatch")
	}
	return nil
}

// sourceObjectTreeFacts is usable only after source snapshot authentication.
// It constructs the encrypted pending record without writing any source path
// to an owner or treating the resulting facts as publication authority.
func sourceObjectTreeFacts(s completeSnapshot, media Media, resolution *sealedtree.LyricResolutionFact) (sealedtree.Facts, error) {
	expected := sealedtree.Facts{ObjectID: media.MediaID, LyricResolution: resolution}
	for _, v := range s.Facts.Objects {
		if v.ID == media.MediaID {
			expected.Object = &sealedtree.ObjectFact{CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt}
		}
	}
	for _, v := range s.Facts.Visibility {
		if v.Path == media.Path {
			expected.Visibility = &sealedtree.VisibilityFact{Hidden: v.Hidden, UpdatedAt: v.UpdatedAt}
		}
	}
	for _, v := range s.Facts.Playback {
		if v.MediaID == media.MediaID {
			expected.Playback = &sealedtree.PlaybackFact{LegacyMediaPath: v.Path, Preference: int64(v.Preference), PlayScore: v.PlayScore, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt}
		}
	}
	for _, v := range s.Facts.LyricLinks {
		if v.MediaID == media.MediaID {
			if sourceIsBuiltinLyric(s, v.LyricID) {
				if media.Kind != "audio" || v.LyricPath != "lyrics/default.lrc" {
					return sealedtree.Facts{}, invalid("builtin lyric source")
				}
				expected.InternalDefaultLyric = &sealedtree.DefaultLyricFact{LegacyMediaPath: v.MediaPath, DefaultLyricID: v.LyricID, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt}
			} else {
				expected.Lyric = &sealedtree.LyricFact{LegacyMediaPath: v.MediaPath, LyricID: v.LyricID, LegacyLyricPath: v.LyricPath, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt}
			}
		}
	}
	return expected, nil
}

// A source fallback is never a user-managed lyric relation. The caller first
// authenticates the complete source, whose validation checks the reserved
// path, built-in marker and exact fixed-content size and SHA-256.
func sourceIsBuiltinLyric(s completeSnapshot, lyricID string) bool {
	for _, lyric := range s.Projection.Lyrics {
		if lyric.ID == lyricID {
			return lyric.Builtin
		}
	}
	return false
}

// sourceLyricResolution is called only after authenticateCompleteSource has
// verified the signed snapshot, its pin, full facts and target generation. The
// digest binds that evidence; it is not itself a signature or a publication
// permit. The caller must persist the complete signed source separately.
func sourceLyricResolution(s completeSnapshot, media Media, sourceDigest, generation string) (*sealedtree.LyricResolutionFact, error) {
	if media.Kind != "audio" {
		return nil, nil
	}
	state, lyricID := "none", ""
	for _, link := range s.Facts.LyricLinks {
		if link.MediaID != media.MediaID {
			continue
		}
		if lyricID != "" {
			return nil, invalid("duplicate source lyric resolution")
		}
		lyricID, state = link.LyricID, "explicit"
		if sourceIsBuiltinLyric(s, lyricID) {
			if link.LyricPath != "lyrics/default.lrc" {
				return nil, invalid("builtin lyric source")
			}
			state = "default"
		}
	}
	evidence, err := sealedtree.LyricResolutionEvidence(sourceDigest, generation, media.MediaID, state, lyricID)
	if err != nil {
		return nil, invalid("source lyric resolution evidence")
	}
	return &sealedtree.LyricResolutionFact{State: state, Evidence: evidence, SourceDigest: sourceDigest, SourceGeneration: generation}, nil
}
