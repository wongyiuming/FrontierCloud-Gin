//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLinkedVisibleLyricUsesSameTreeLease(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, s, root, _, _ := fencedFixture(t)
	music := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "music"}
	lyrics := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("c", 64), Kind: "directory", Name: "lyrics"}
	for _, dir := range []Entry{music, lyrics} {
		if err := s.CreateDirectoryWithFacts(ctx, dir, Facts{ObjectID: dir.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	track := Entry{ParentID: music.ObjectID, ObjectID: strings.Repeat("d", 64), Kind: "audio", Name: "track.mp3"}
	lyric := Entry{ParentID: lyrics.ObjectID, ObjectID: strings.Repeat("e", 64), Kind: "lyric", Name: "track.lrc"}
	publisher, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	publish := func(entry Entry, facts Facts) {
		t.Helper()
		content := []byte("synthetic " + entry.Kind)
		digest := sha256.Sum256(content)
		placement := fixturePlacement(t, entry.ObjectID)
		placement.BlobID, placement.ReadAlias = "", ""
		placement.Bytes, placement.SHA256 = int64(len(content)), hex.EncodeToString(digest[:])
		prepared, err := s.PrepareFileWithFreshLocators(ctx, entry, placement, facts)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.PublishPending(ctx, prepared.OperationID, publisher, bytes.NewReader(content)); err != nil {
			t.Fatal(err)
		}
	}
	publish(lyric, Facts{ObjectID: lyric.ObjectID})
	trackFacts := Facts{ObjectID: track.ObjectID, Lyric: &LyricFact{LyricID: lyric.ObjectID, LegacyMediaPath: "music/track.mp3", LegacyLyricPath: "lyrics/track.lrc", CreatedAt: "2026-01-01", UpdatedAt: "2026-01-01"}}
	publish(track, trackFacts)
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	gotTrack, gotLyric, err := s.ReadLinkedVisibleLyricWithLease(ctx, lease, track.ObjectID)
	if err != nil || gotTrack.Entry != track || gotLyric.Entry != lyric || gotLyric.Placement.ReadAlias == "" {
		t.Fatalf("linked visible objects: %v", err)
	}
	if _, _, err := s.ReadLinkedVisibleLyricWithLease(ctx, lease, lyric.ObjectID); err == nil {
		t.Fatal("lyric treated as a track")
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := s.SetFacts(ctx, Facts{ObjectID: lyrics.ObjectID, Visibility: &VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-02"}}, 1)
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		t.Fatalf("visibility changed while linked read lease held: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	lease.Release()
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ReadLinkedVisibleLyricWithLease(ctx, lease, track.ObjectID); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("released lease accepted", err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if a, b, err := s.ReadLinkedVisibleLyricWithLease(ctx, lease, track.ObjectID); !errors.Is(err, ErrHidden) || a.Path != "" || b.Path != "" {
		t.Fatal("hidden lyric ancestor exposed linked data", err)
	}
	lease.Release()
	if _, err := s.SetFacts(ctx, Facts{ObjectID: lyrics.ObjectID}, 2); err != nil {
		t.Fatal(err)
	}
	trackFacts.Lyric.LyricID = strings.Repeat("f", 64)
	if _, err := s.SetFacts(ctx, trackFacts, 1); err != nil {
		t.Fatal(err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if a, b, err := s.ReadLinkedVisibleLyricWithLease(ctx, lease, track.ObjectID); err == nil || a.Path != "" || b.Path != "" {
		t.Fatal("missing linked lyric returned partial data")
	}
}
