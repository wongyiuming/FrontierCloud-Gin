package business

import "testing"

func TestSelectedUploadKindKeepsLyricsLocalNamespaceAndLimits(t *testing.T) {
	for _, tc := range []struct {
		parent, name string
		size         int64
		want         string
		ok           bool
	}{
		{"lyrics", "song.lrc", 1, "lyric", true},
		{"lyrics/artist/album", "歌.LRC", 2 * 1024 * 1024, "lyric", true},
		{"lyrics", "default.lrc", 1, "", false},
		{"lyrics", "song.mp3", 1, "", false},
		{"lyrics/a/b/c", "song.lrc", 1, "", false},
		{"lyrics/../music", "song.lrc", 1, "", false},
		{"lyrics", ".hidden.lrc", 1, "", false},
		{"lyrics", "song.lrc", 0, "", false},
		{"lyrics", "song.lrc", 2*1024*1024 + 1, "", false},
		{"music/artist", "song.mp3", 1, "audio", true},
		{"vido/director", "film.mp4", 1, "video", true},
	} {
		kind, ok := selectedUploadKind(tc.parent, tc.name, tc.size, tc.size+16)
		if kind != tc.want || ok != tc.ok {
			t.Errorf("%q %q size=%d: got %q %v", tc.parent, tc.name, tc.size, kind, ok)
		}
	}
}
