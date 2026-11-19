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

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

func TestNativePlaybackSealsScoreAndDeduplicatesAtomically(t *testing.T) {
	ctx := context.Background()
	db, tree, root, _, _ := fencedFixture(t)
	statements, err := migrations.Statements("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range statements {
		if strings.HasPrefix(statement, "CREATE TABLE IF NOT EXISTS media_playback_events ") {
			if _, err = db.Exec(statement); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	music := Entry{ParentID: tree.rootID, ObjectID: strings.Repeat("c", 64), Kind: "directory", Name: "music"}
	album := Entry{ParentID: music.ObjectID, ObjectID: strings.Repeat("d", 64), Kind: "directory", Name: "私密专辑"}
	for _, dir := range []Entry{music, album} {
		facts := Facts{ObjectID: dir.ObjectID}
		if dir == album {
			facts.Visibility = &VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}
		}
		if err = tree.CreateDirectoryWithFacts(ctx, dir, facts); err != nil {
			t.Fatal(err)
		}
	}
	track := Entry{ParentID: album.ObjectID, ObjectID: strings.Repeat("b", 64), Kind: "audio", Name: "私密曲目.mp3"}
	path := "music/" + album.Name + "/" + track.Name
	content := []byte("synthetic audio")
	sum := sha256.Sum256(content)
	placement := fixturePlacement(t, track.ObjectID)
	placement.Bytes, placement.SHA256 = int64(len(content)), hex.EncodeToString(sum[:])
	placement.State = "active"
	placement.BlobID, placement.ReadAlias = "", ""
	facts := Facts{ObjectID: track.ObjectID, Playback: &PlaybackFact{Preference: 17, PlayScore: 3, CreatedAt: "2026-01-01", UpdatedAt: "2026-01-01"}}
	prepared, err := tree.PrepareFileWithFreshLocators(ctx, track, placement, facts)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = tree.PublishPending(ctx, prepared.OperationID, publisher, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	session := "12345678-1234-1234-1234-123456789abc"
	report := func(at time.Time) (store.PlaybackResult, error) {
		return tree.recordNativePlayback(ctx, path, track.ObjectID, session, at)
	}
	if _, err = db.Exec(`CREATE TRIGGER reject_score BEFORE UPDATE ON sealed_tree_facts BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = report(now); err == nil || !strings.Contains(err.Error(), "fixture") {
		t.Fatalf("failed score update did not reach the rollback fixture: %v", err)
	}
	var count int
	if err = db.QueryRow(`SELECT COUNT(*) FROM media_playback_events`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("event escaped the failed transaction: %d %v", count, err)
	}
	if _, err = db.Exec(`DROP TRIGGER reject_score`); err != nil {
		t.Fatal(err)
	}
	expiredLookup := "s1-" + tree.listingMAC("playback-event-key", track.ObjectID, "older-fixture")[:33]
	expiredAt := now.Add(-time.Second).Format(playbackTimeFormat)
	countedAt := now.Add(-playbackEventTTL - time.Second).Format(playbackTimeFormat)
	if _, err = db.Exec(`INSERT INTO media_playback_events VALUES(?,?,?,?)`, expiredLookup, tree.nativePlaybackReceipt(expiredLookup, countedAt, expiredAt), countedAt, expiredAt); err != nil {
		t.Fatal(err)
	}
	var before, after int64
	for _, step := range []struct {
		offset  time.Duration
		score   int64
		counted bool
	}{{0, 4, true}, {time.Second, 4, false}, {playbackEventTTL, 5, true}} {
		if err = db.QueryRow(`SELECT write_fence FROM sealed_tree_meta WHERE singleton=1`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		result, err := report(now.Add(step.offset))
		if err != nil || result.MediaID != track.ObjectID || result.PlayScore != step.score || result.Preference != 17 || result.Counted != step.counted {
			t.Fatalf("unexpected report at %v: %+v %v", step.offset, result, err)
		}
		if err = db.QueryRow(`SELECT write_fence FROM sealed_tree_meta WHERE singleton=1`).Scan(&after); err != nil || !step.counted && after != before {
			t.Fatalf("duplicate report advanced the tree write fence: %d → %d %v", before, after, err)
		}
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM media_playback_events`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("expired event was retained: %d %v", count, err)
	}
	if _, err = tree.recordNativePlayback(ctx, path, strings.Repeat("e", 64), session, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong resource ID accepted: %v", err)
	}
	facts, _, err = tree.GetFacts(ctx, track.ObjectID)
	if err != nil || facts.Playback == nil || facts.Playback.PlayScore != 5 || facts.Playback.Preference != 17 || facts.Playback.LegacyMediaPath != "" {
		t.Fatalf("unexpected encrypted facts: %+v %v", facts.Playback, err)
	}
	var lookup, receipt string
	if err = db.QueryRow(`SELECT playback_session_id,media_id FROM media_playback_events`).Scan(&lookup, &receipt); err != nil || !strings.HasPrefix(lookup, "s1-") || lookup == session || receipt == track.ObjectID || !hexID(receipt) {
		t.Fatalf("plaintext or malformed event identifiers: %v", err)
	}
	if _, err = db.Exec(`UPDATE media_playback_events SET expires_at='2026-01-01'`); err != nil {
		t.Fatal(err)
	}
	if _, err = report(now.Add(playbackEventTTL + time.Second)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("changed event expiry accepted: %v", err)
	}
	index, err := tree.tree.ObjectIndex(track.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO sealed_tree_revocations(operation_index,object_index) VALUES(?,?)`, strings.Repeat("a", 64), index); err != nil {
		t.Fatal(err)
	}
	if _, err = report(now.Add(playbackEventTTL + time.Second)); !errors.Is(err, ErrRevocationPending) {
		t.Fatalf("pending revocation did not stop playback accounting: %v", err)
	}
}
