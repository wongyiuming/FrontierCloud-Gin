package sealedtree

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func fixtureFacts(id string) Facts {
	return Facts{ObjectID: id,
		Object:     &ObjectFact{CreatedAt: "2026-01-01", UpdatedAt: "2026-02-01"},
		Visibility: &VisibilityFact{Hidden: 1, UpdatedAt: "2026-02-02"},
		Playback:   &PlaybackFact{LegacyMediaPath: "music/私密专辑/私密曲目.mp3", PlayScore: 17, Preference: -3, CreatedAt: "2026-02-03", UpdatedAt: "2026-02-04"},
		Lyric:      &LyricFact{LegacyMediaPath: "music/私密专辑/私密曲目.mp3", LyricID: strings.Repeat("f", 64), LegacyLyricPath: "lyrics/私密/歌词.lrc", CreatedAt: "2026-02-05", UpdatedAt: "2026-02-06"},
	}
}

func TestFactsSealFixedSizeAndRejectWrongIdentityOrRevision(t *testing.T) {
	tree := fixture(t)
	facts := fixtureFacts(strings.Repeat("b", 64))
	record, err := tree.SealFacts(facts, 1)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := tree.OpenFacts(record)
	if err != nil || !reflect.DeepEqual(opened, facts) {
		t.Fatal("facts not preserved", err)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{facts.ObjectID, facts.Playback.LegacyMediaPath, facts.Lyric.LyricID, facts.Lyric.LegacyLyricPath, "私密专辑"} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatal("fact secret persisted outside ciphertext")
		}
	}
	minimal, err := tree.SealFacts(Facts{ObjectID: facts.ObjectID}, 1)
	if err != nil || len(minimal.Sealed) != len(record.Sealed) {
		t.Fatal("facts leak their content length", err)
	}
	wrong := record
	wrong.Revision++
	if _, err = tree.OpenFacts(wrong); !errors.Is(err, ErrInvalid) {
		t.Fatal("revision tamper accepted")
	}
	wrong = record
	wrong.ObjectIndex = strings.Repeat("0", 64)
	if _, err = tree.OpenFacts(wrong); !errors.Is(err, ErrInvalid) {
		t.Fatal("object substitution accepted")
	}
	wrong = record
	wrong.Sealed = append([]byte(nil), record.Sealed...)
	wrong.Sealed[len(wrong.Sealed)-1] ^= 1
	if _, err = tree.OpenFacts(wrong); !errors.Is(err, ErrInvalid) {
		t.Fatal("ciphertext tamper accepted")
	}
}

func TestFactsRejectInvalidVisibilityValues(t *testing.T) {
	tree := fixture(t)
	for _, hidden := range []int64{-1, 2, 99} {
		facts := Facts{ObjectID: strings.Repeat("b", 64), Visibility: &VisibilityFact{Hidden: hidden, UpdatedAt: "2026-01-01"}}
		if _, err := tree.SealFacts(facts, 1); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid visibility accepted", hidden, err)
		}
	}
}

func TestFactsStoreCASAndDirectoryTransaction(t *testing.T) {
	ctx := context.Background()
	db, s, _ := sqliteFixture(t)
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "directory", Name: "隐藏专辑"}
	facts := fixtureFacts(entry.ObjectID)
	facts.Lyric = nil
	if err := s.CreateDirectoryWithFacts(ctx, entry, facts); err != nil {
		t.Fatal(err)
	}
	got, version, err := s.GetFacts(ctx, entry.ObjectID)
	if err != nil || version != 1 || !reflect.DeepEqual(got, facts) {
		t.Fatal("facts not committed atomically", err)
	}
	updated := facts
	updated.Visibility = &VisibilityFact{Hidden: 0, UpdatedAt: "2026-03-01"}
	if next, err := s.SetFacts(ctx, updated, 1); err != nil || next != 2 {
		t.Fatal("facts update failed", err)
	}
	if _, err = s.SetFacts(ctx, facts, 1); !errors.Is(err, ErrConflict) {
		t.Fatal("stale update accepted", err)
	}
	if count, err := s.Check(ctx); err != nil || count != 1 {
		t.Fatal("valid facts failed check", err)
	}
	if _, err = db.Exec(`UPDATE sealed_tree_facts SET sealed=zeroblob(length(sealed))`); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.GetFacts(ctx, entry.ObjectID); !errors.Is(err, ErrInvalid) {
		t.Fatal("corrupt facts opened", err)
	}
	if _, err = s.Check(ctx); !errors.Is(err, ErrInvalid) {
		t.Fatal("corrupt facts passed integrity check", err)
	}
}

func TestDirectoryFactsInsertFailureRollsBackNameAndReservations(t *testing.T) {
	ctx := context.Background()
	db, s, _ := sqliteFixture(t)
	if _, err := db.Exec(`CREATE TRIGGER reject_facts BEFORE INSERT ON sealed_tree_facts BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("c", 64), Kind: "directory", Name: "hidden"}
	facts := fixtureFacts(entry.ObjectID)
	facts.Lyric = nil
	if err := s.CreateDirectoryWithFacts(ctx, entry, facts); err == nil {
		t.Fatal("failed fact insert accepted")
	}
	if _, _, err := s.Get(ctx, entry.ObjectID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("name survived failed fact transaction", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_encryption_ids`).Scan(&n); err != nil || n != 1 {
		t.Fatal("failed transaction leaked reservation", err)
	}
}

func TestLyricRelationCannotBeAttachedToNonAudio(t *testing.T) {
	ctx := context.Background()
	_, s, _ := sqliteFixture(t)
	dir := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("d", 64), Kind: "directory", Name: "album"}
	if err := s.CreateDirectoryWithFacts(ctx, dir, fixtureFacts(dir.ObjectID)); !errors.Is(err, ErrInvalid) {
		t.Fatal("lyric attached to directory", err)
	}
	video := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("e", 64), Kind: "video", Name: "movie.mp4"}
	if _, err := s.PrepareFileWithFacts(ctx, video, fixturePlacement(t, video.ObjectID), fixtureFacts(video.ObjectID)); !errors.Is(err, ErrInvalid) {
		t.Fatal("lyric attached to video", err)
	}
}

func TestResolvePathUsesRenamedTreeRatherThanLegacyFactPaths(t *testing.T) {
	ctx := context.Background()
	_, s, _ := sqliteFixture(t)
	music := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("1", 64), Kind: "directory", Name: "music"}
	album := Entry{ParentID: music.ObjectID, ObjectID: strings.Repeat("2", 64), Kind: "directory", Name: "私密专辑"}
	track := Entry{ParentID: album.ObjectID, ObjectID: strings.Repeat("3", 64), Kind: "audio", Name: "私密曲目.mp3"}
	if err := s.Create(ctx, music); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, album); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateFile(ctx, track, fixturePlacement(t, track.ObjectID)); err != nil {
		t.Fatal(err)
	}
	facts := fixtureFacts(track.ObjectID)
	if _, err := s.SetFacts(ctx, facts, 0); err != nil {
		t.Fatal(err)
	}
	if path, err := s.ResolvePath(ctx, track.ObjectID); err != nil || path != "music/私密专辑/私密曲目.mp3" {
		t.Fatal("initial path incorrect", err)
	}
	if _, err := s.Move(ctx, album.ObjectID, music.ObjectID, "新专辑", 1); err != nil {
		t.Fatal(err)
	}
	if path, err := s.ResolvePath(ctx, track.ObjectID); err != nil || path != "music/新专辑/私密曲目.mp3" {
		t.Fatal("rename did not update resolved path", err)
	}
	got, _, err := s.GetFacts(ctx, track.ObjectID)
	if err != nil || got.Playback.LegacyMediaPath != facts.Playback.LegacyMediaPath {
		t.Fatal("historical evidence changed unexpectedly", err)
	}
}

func TestVisibleResolutionChecksEveryAncestorAndFailsClosedWithoutFacts(t *testing.T) {
	ctx := context.Background()
	db, s, _ := sqliteFixture(t)
	music := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("1", 64), Kind: "directory", Name: "music"}
	album := Entry{ParentID: music.ObjectID, ObjectID: strings.Repeat("2", 64), Kind: "directory", Name: "album"}
	track := Entry{ParentID: album.ObjectID, ObjectID: strings.Repeat("3", 64), Kind: "audio", Name: "track.mp3"}
	if err := s.CreateDirectoryWithFacts(ctx, music, Facts{ObjectID: music.ObjectID}); err != nil {
		t.Fatal(err)
	}
	hidden := Facts{ObjectID: album.ObjectID, Visibility: &VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}}
	if err := s.CreateDirectoryWithFacts(ctx, album, hidden); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateFile(ctx, track, fixturePlacement(t, track.ObjectID)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetFacts(ctx, Facts{ObjectID: track.ObjectID}, 0); err != nil {
		t.Fatal(err)
	}
	if path, err := s.ResolveVisiblePath(ctx, track.ObjectID); !errors.Is(err, ErrHidden) || path != "" {
		t.Fatal("hidden ancestor exposed descendant", err)
	}
	hidden.Visibility = &VisibilityFact{Hidden: 0, UpdatedAt: "2026-01-02"}
	if _, err := s.SetFacts(ctx, hidden, 1); err != nil {
		t.Fatal(err)
	}
	if path, err := s.ResolveVisiblePath(ctx, track.ObjectID); err != nil || path != "music/album/track.mp3" {
		t.Fatal("visible path failed", err)
	}
	index, err := s.tree.ObjectIndex(music.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`DELETE FROM sealed_tree_facts WHERE object_index=?`, index); err != nil {
		t.Fatal(err)
	}
	if path, err := s.ResolveVisiblePath(ctx, track.ObjectID); !errors.Is(err, ErrInvalid) || path != "" {
		t.Fatal("missing ancestor facts allowed access", err)
	}
}
