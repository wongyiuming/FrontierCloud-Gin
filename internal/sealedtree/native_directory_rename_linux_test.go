//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestNativeDirectoryRenameAtomicAndFenced(t *testing.T) {
	ctx := context.Background()
	db, s, root, _, _ := fencedFixture(t)
	_, err := db.Exec(`CREATE TABLE admin_audit_log (session_id_hash TEXT, action TEXT, target_count INTEGER, source_summary TEXT, result TEXT, detail TEXT, client_ip TEXT, user_agent TEXT, request_id TEXT, trace_id TEXT, created_at TEXT)`)
	if err != nil {
		t.Fatal(err)
	}
	music := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("1", 64), Kind: "directory", Name: "music"}
	album := Entry{ParentID: music.ObjectID, ObjectID: strings.Repeat("2", 64), Kind: "directory", Name: "private-album"}
	occupied := Entry{ParentID: music.ObjectID, ObjectID: strings.Repeat("3", 64), Kind: "directory", Name: "occupied"}
	sub := Entry{ParentID: album.ObjectID, ObjectID: strings.Repeat("4", 64), Kind: "directory", Name: "disc"}
	for _, entry := range []Entry{music, album, occupied, sub} {
		facts := Facts{ObjectID: entry.ObjectID}
		if entry.ObjectID == album.ObjectID {
			facts.Playback = &PlaybackFact{Preference: 31, CreatedAt: "2026", UpdatedAt: "2026"}
		}
		if err := s.CreateDirectoryWithFacts(ctx, entry, facts); err != nil {
			t.Fatal(err)
		}
	}
	track := Entry{ParentID: sub.ObjectID, ObjectID: strings.Repeat("5", 64), Kind: "audio", Name: "track.mp3"}
	content := []byte("synthetic media")
	sum := sha256.Sum256(content)
	place := fixturePlacement(t, track.ObjectID)
	place.Bytes = int64(len(content))
	place.SHA256 = hex.EncodeToString(sum[:])
	place.BlobID = ""
	place.ReadAlias = ""
	facts := fixtureFacts(track.ObjectID)
	prepared, err := s.PrepareFileWithFreshLocators(ctx, track, place, facts)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.PublishPending(ctx, prepared.OperationID, publisher, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	resolve := func() (string, error) {
		lease, e := s.AcquireReadFence(ctx)
		if e != nil {
			return "", e
		}
		defer lease.Release()
		return s.resolvePath(ctx, track.ObjectID, false)
	}
	audit := store.AdminAudit{SessionHash: strings.Repeat("a", 64), ClientIP: "192.0.2.1", RequestID: "request-1", SourceSummary: "private-album"}
	if _, err = db.Exec(`CREATE TRIGGER reject_rename_audit BEFORE INSERT ON admin_audit_log BEGIN SELECT RAISE(ABORT,'test'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RenameNativeDirectory(ctx, "music/private-album", "renamed", audit); err == nil {
		t.Fatal("audit failure accepted")
	}
	if got, e := resolve(); e != nil || got != "music/private-album/disc/track.mp3" {
		t.Fatal("failed transaction changed path", got, e)
	}
	if _, err = db.Exec(`DROP TRIGGER reject_rename_audit`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RenameNativeDirectory(ctx, "music/private-album", "occupied", audit); !errors.Is(err, ErrConflict) {
		t.Fatal("existing sibling accepted", err)
	}
	got, err := s.RenameNativeDirectory(ctx, "music/private-album", "renamed", audit)
	if err != nil || got.Status != "renamed" || got.Old != "music/private-album" || got.New != "music/renamed" {
		t.Fatal("rename", got, err)
	}
	if got, e := resolve(); e != nil || got != "music/renamed/disc/track.mp3" {
		t.Fatal("descendant identity/path", got, e)
	}
	after, _, err := s.GetFacts(ctx, track.ObjectID)
	if err != nil || after.Lyric == nil || after.Lyric.LyricID != facts.Lyric.LyricID {
		t.Fatal("lyric reference changed", err)
	}
	df, _, err := s.GetFacts(ctx, album.ObjectID)
	if err != nil || df.Playback == nil || df.Playback.Preference != 31 {
		t.Fatal("directory priority changed", err)
	}
	var count int
	var summary, detail sql.NullString
	var ip, request string
	err = db.QueryRow(`SELECT COUNT(*), MAX(source_summary), MAX(detail), MAX(client_ip), MAX(request_id) FROM admin_audit_log WHERE action='directory_rename'`).Scan(&count, &summary, &detail, &ip, &request)
	if err != nil || count != 1 || summary.Valid || detail.Valid || ip != "192.0.2.1" || request != "request-1" {
		t.Fatal("audit missing, unbounded, or leaked path", err)
	}
	unchanged, err := s.RenameNativeDirectory(ctx, "music/renamed", "renamed", audit)
	if err != nil || unchanged.Status != "unchanged" {
		t.Fatal("unchanged", err)
	}
	if _, err = s.RenameNativeDirectory(ctx, "music", "bad", audit); !errors.Is(err, ErrInvalid) {
		t.Fatal("root renamed", err)
	}
	pending := Entry{ParentID: sub.ObjectID, ObjectID: strings.Repeat("6", 64), Kind: "audio", Name: "pending.mp3"}
	pp := fixturePlacement(t, pending.ObjectID)
	pp.BlobID = ""
	pp.ReadAlias = ""
	if _, err = s.PrepareFileWithFreshLocators(ctx, pending, pp, Facts{ObjectID: pending.ObjectID}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RenameNativeDirectory(ctx, "music/renamed", "blocked", audit); !errors.Is(err, ErrConflict) {
		t.Fatal("pending reservation allowed rename", err)
	}
	if got, e := resolve(); e != nil || got != "music/renamed/disc/track.mp3" {
		t.Fatal("pending conflict changed tree", got, e)
	}
}

func TestNativeDirectoryRenameRejectsOverlongDescendants(t *testing.T) {
	ctx := context.Background()
	db, s, root, _, _ := fencedFixture(t)
	if _, err := db.Exec(`CREATE TABLE admin_audit_log (session_id_hash TEXT,action TEXT,target_count INTEGER,source_summary TEXT,result TEXT,detail TEXT,client_ip TEXT,user_agent TEXT,request_id TEXT,trace_id TEXT,created_at TEXT)`); err != nil {
		t.Fatal(err)
	}
	music := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("7", 64), Kind: "directory", Name: "music"}
	album := Entry{ParentID: music.ObjectID, ObjectID: strings.Repeat("8", 64), Kind: "directory", Name: "a"}
	for _, entry := range []Entry{music, album} {
		if err := s.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: entry.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	track := Entry{ParentID: album.ObjectID, ObjectID: strings.Repeat("9", 64), Kind: "audio", Name: strings.Repeat("x", 1011) + ".mp3"}
	content := []byte("fixture")
	sum := sha256.Sum256(content)
	place := fixturePlacement(t, track.ObjectID)
	place.Bytes = int64(len(content))
	place.SHA256 = hex.EncodeToString(sum[:])
	place.BlobID = ""
	place.ReadAlias = ""
	prepared, err := s.PrepareFileWithFreshLocators(ctx, track, place, Facts{ObjectID: track.ObjectID})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.PublishPending(ctx, prepared.OperationID, pub, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RenameNativeDirectory(ctx, "music/a", "longer", store.AdminAudit{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("overlong descendant accepted", err)
	}
	entry, revision, err := s.Find(ctx, music.ObjectID, "a")
	if err != nil || entry.ObjectID != album.ObjectID || revision != 1 {
		t.Fatal("failed rename changed directory", err)
	}
	if _, err = s.RenameNativeDirectory(ctx, "music/a", "b", store.AdminAudit{}); err != nil {
		t.Fatal("same-length safe rename failed", err)
	}
}
