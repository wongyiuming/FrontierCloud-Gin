package sealedtree

import (
	"strings"
	"testing"
)

func TestLyricResolutionEvidenceBindsDecision(t *testing.T) {
	source, generation, track, lyric := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64)
	base, err := LyricResolutionEvidence(source, generation, track, "default", lyric)
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][5]string{
		{strings.Repeat("e", 64), generation, track, "default", lyric},
		{source, strings.Repeat("e", 64), track, "default", lyric},
		{source, generation, strings.Repeat("e", 64), "default", lyric},
		{source, generation, track, "explicit", lyric},
		{source, generation, track, "default", strings.Repeat("e", 64)},
	} {
		got, e := LyricResolutionEvidence(args[0], args[1], args[2], args[3], args[4])
		if e != nil || got == base {
			t.Fatal("different resolution shared evidence", e)
		}
	}
	if _, err = LyricResolutionEvidence(source, generation, track, "none", lyric); err == nil {
		t.Fatal("none accepted lyric ID")
	}
	if _, err = LyricResolutionEvidence(source, generation, track, "default", ""); err == nil {
		t.Fatal("default accepted missing ID")
	}
}
