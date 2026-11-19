//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestLyricDisplaySelectionKeepsFallbackSeparate(t *testing.T) {
	ctx := context.Background()
	_, s, root, _, _ := fencedFixture(t)
	pub, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(nil)
	for i := 0; i < 4; i++ {
		id := fmt.Sprintf("%064x", i+100)
		entry := Entry{ParentID: s.rootID, ObjectID: id, Kind: "audio", Name: fmt.Sprintf("hidden-%d.mp3", i)}
		facts := Facts{ObjectID: id, Visibility: &VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}}
		state, lyricID := "", ""
		if i == 1 {
			state = "none"
		}
		if i == 2 {
			state, lyricID = "default", fmt.Sprintf("%064x", 999)
			facts.InternalDefaultLyric = &DefaultLyricFact{LegacyMediaPath: "music/old.mp3", DefaultLyricID: lyricID, CreatedAt: "c", UpdatedAt: "u"}
		}
		if i == 3 {
			state, lyricID = "explicit", fmt.Sprintf("%064x", 998)
			facts.Lyric = &LyricFact{LegacyMediaPath: "music/old.mp3", LyricID: lyricID, LegacyLyricPath: "lyrics/custom.lrc", CreatedAt: "c", UpdatedAt: "u"}
		}
		if state != "" {
			evidence, e := LyricResolutionEvidence(strings.Repeat("d", 64), strings.Repeat("e", 64), id, state, lyricID)
			if e != nil {
				t.Fatal(e)
			}
			facts.LyricResolution = &LyricResolutionFact{State: state, Evidence: evidence}
		}
		loc := fixturePlacement(t, id)
		loc.Bytes, loc.SHA256, loc.BlobID, loc.ReadAlias, loc.State = 0, hex.EncodeToString(sum[:]), "", "", "active"
		p, e := s.PrepareFileWithFreshLocators(ctx, entry, loc, facts)
		if e != nil {
			t.Fatal(e)
		}
		if e = s.PublishPending(ctx, p.OperationID, pub, bytes.NewReader(nil)); e != nil {
			t.Fatal(e)
		}
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	for i := 0; i < 4; i++ {
		id := fmt.Sprintf("%064x", i+100)
		selection, e := s.SelectLyricForDisplayWithLease(ctx, lease, id)
		if i == 0 {
			if !errors.Is(e, ErrInvalid) {
				t.Fatal("unproven absence accepted", e)
			}
		} else if e != nil {
			t.Fatal(e)
		}
		if (i == 1 || i == 2) && (!selection.BuiltinFallback || selection.ExplicitLyricID != "" || selection.Evidence == "") {
			t.Fatal("missing built-in fallback")
		}
		if i == 3 && (selection.BuiltinFallback || selection.ExplicitLyricID != fmt.Sprintf("%064x", 998)) {
			t.Fatal("explicit association lost")
		}
		if _, e = s.ReadVisibleObjectWithLease(ctx, lease, id); !errors.Is(e, ErrHidden) {
			t.Fatal("selection granted hidden media", e)
		}
	}
	invalid := Facts{ObjectID: fmt.Sprintf("%064x", 100), Lyric: &LyricFact{LegacyMediaPath: "music/a.mp3", LyricID: fmt.Sprintf("%064x", 998), LegacyLyricPath: "lyrics/a.lrc", CreatedAt: "c", UpdatedAt: "u"}, InternalDefaultLyric: &DefaultLyricFact{LegacyMediaPath: "music/a.mp3", DefaultLyricID: fmt.Sprintf("%064x", 999), CreatedAt: "c", UpdatedAt: "u"}}
	if _, e := s.tree.SealFacts(invalid, 1); !errors.Is(e, ErrInvalid) {
		t.Fatal("explicit/default ambiguity accepted", e)
	}
}
