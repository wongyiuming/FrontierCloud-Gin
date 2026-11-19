//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestNativeLyricAutoMatchesWithinCompleteScopes(t *testing.T) {
	ctx := context.Background()
	db, tree, root, _, _ := fencedFixture(t)
	for _, query := range []string{
		`CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT NOT NULL,role TEXT NOT NULL)`,
		`INSERT INTO node_identity VALUES(1,'ffffffffffffffffffffffffffffffff','Master')`,
		`CREATE TABLE admin_audit_log(session_id_hash TEXT,action TEXT,target_count INTEGER,source_summary TEXT,result TEXT,detail TEXT,client_ip TEXT,user_agent TEXT,request_id TEXT,trace_id TEXT,created_at TEXT)`,
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	dirs := map[string]string{".": tree.rootID}
	for i, name := range []string{"music", "music/album", "music/mixed", "lyrics", "lyrics/album", "lyrics/other"} {
		id := fmt.Sprintf("%064x", i+1)
		entry := Entry{ObjectID: id, ParentID: dirs[path.Dir(name)], Kind: "directory", Name: path.Base(name)}
		if err := tree.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: id}); err != nil {
			t.Fatal(err)
		}
		dirs[name] = id
	}
	publisher, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(nil)
	objects := make(map[string]string)
	missingID := fmt.Sprintf("%064x", 99)
	for i, name := range []string{
		"music/album/song.mp3", "music/mixed/song.mp3", "music/mixed/unique.mp3", "music/mixed/missing.mp3", "music/mixed/keep.mp3",
		"lyrics/album/song.lrc", "lyrics/other/song.lrc", "lyrics/other/unique.lrc", "lyrics/other/keep.lrc",
	} {
		id := fmt.Sprintf("%064x", i+10)
		entry := Entry{ObjectID: id, ParentID: dirs[path.Dir(name)], Kind: "lyric", Name: path.Base(name)}
		facts := Facts{ObjectID: id}
		if strings.HasPrefix(name, "music/") {
			entry.Kind = "audio"
			facts.LyricResolution = &LyricResolutionFact{State: "none", Origin: "native", OperationID: id, PreviousRevision: 1, RelationCreatedAt: "created", RelationUpdatedAt: "updated"}
			if name == "music/mixed/keep.mp3" {
				facts.LyricResolution.State = "explicit"
				facts.Lyric = &LyricFact{LegacyMediaPath: name, LyricID: missingID, LegacyLyricPath: "lyrics/absent.lrc", CreatedAt: "created", UpdatedAt: "updated"}
			}
			facts.LyricResolution.Evidence, err = tree.nativeLyricEvidence(facts)
			if err != nil {
				t.Fatal(err)
			}
		}
		placement := fixturePlacement(t, id)
		placement.Bytes, placement.SHA256, placement.BlobID, placement.ReadAlias, placement.State = 0, hex.EncodeToString(sum[:]), "", "", "active"
		pending, err := tree.PrepareFileWithFreshLocators(ctx, entry, placement, facts)
		if err != nil {
			t.Fatal(err)
		}
		if err = tree.PublishPending(ctx, pending.OperationID, publisher, bytes.NewReader(nil)); err != nil {
			t.Fatal(err)
		}
		objects[name] = id
	}
	check := func(name, want string, expectedRevision int64) {
		t.Helper()
		facts, revision, err := tree.GetFacts(ctx, objects[name])
		got := ""
		if facts.Lyric != nil {
			got = facts.Lyric.LyricID
		}
		if err != nil || revision != expectedRevision || got != want {
			t.Fatalf("%s: got relation %q and revision %d: %v", name, got, revision, err)
		}
	}
	if _, err = db.Exec(`CREATE TRIGGER reject_auto_audit BEFORE INSERT ON admin_audit_log BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if got, err := tree.ApplyNativeLyricAuto(ctx, "", "", store.AdminAudit{}); err == nil || got != (store.AutoLyricResult{}) {
		t.Fatal("failed audit reported committed changes", got, err)
	}
	check("music/album/song.mp3", "", 1)
	check("music/mixed/unique.mp3", "", 1)
	if _, err = db.Exec(`DROP TRIGGER reject_auto_audit`); err != nil {
		t.Fatal(err)
	}
	got, err := tree.ApplyNativeLyricAuto(ctx, "music", "lyrics", store.AdminAudit{})
	if err != nil || got != (store.AutoLyricResult{Linked: 2, Preserved: 1, Ambiguous: 1, Unmatched: 1}) {
		t.Fatal("unexpected same-name result", got, err)
	}
	check("music/album/song.mp3", objects["lyrics/album/song.lrc"], 2)
	check("music/mixed/song.mp3", "", 1)
	check("music/mixed/unique.mp3", objects["lyrics/other/unique.lrc"], 2)
	check("music/mixed/keep.mp3", missingID, 1)
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rows, _, err := tree.ReadNativeLyricScopeWithLease(ctx, lease, "music", "music", 1); rows != nil || !errors.Is(err, ErrLyricScopeLimit) {
		lease.Release()
		t.Fatal("incomplete subtree returned as exact", len(rows), err)
	}
	rows, visited, err := tree.ReadNativeLyricScopeWithLease(ctx, lease, "music", "music", 10)
	lease.Release()
	if err != nil || len(rows) != 5 || visited != 7 {
		t.Fatal("descendant track scope differs", len(rows), visited, err)
	}
	var kept bool
	for _, row := range rows {
		if row.Path == "music/mixed/keep.mp3" && row.LinkedLyricID == missingID {
			kept = true
		}
	}
	if !kept {
		t.Fatal("existing explicit relation disappeared from the authenticated scope")
	}
	var detail string
	if err = db.QueryRow(`SELECT detail FROM admin_audit_log`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(detail, ":")
	if len(parts) != 6 {
		t.Fatal("unexpected audit framing")
	}
	audit, err := tree.ReadEncryptedLyricAudit(ctx, parts[1])
	if err != nil || audit.Audit.Action != "lyric_auto_relate" || audit.Origin != "music" || audit.Relations != 2 || len(audit.Changes) != 2 {
		t.Fatal("automatic audit unavailable", err)
	}
	got, err = tree.ApplyNativeLyricAuto(ctx, "music/mixed", "lyrics/other", store.AdminAudit{})
	if err != nil || got != (store.AutoLyricResult{Linked: 1, Preserved: 2, Unmatched: 1}) {
		t.Fatal("unexpected scoped result", got, err)
	}
	check("music/mixed/song.mp3", objects["lyrics/other/song.lrc"], 2)
}

func TestNativeLyricAutoRejectsOverLimitPlan(t *testing.T) {
	tracks := make([]lyricAutoEntry, MaxNativeLyricPatchTracks+1)
	for i := range tracks {
		tracks[i] = lyricAutoEntry{path: fmt.Sprintf("music/category%d/same.mp3", i), id: fmt.Sprintf("%064x", i+1), revision: 1}
	}
	lyrics := []lyricAutoEntry{{path: "lyrics/same.lrc", id: fmt.Sprintf("%064x", 999)}}
	changes, counts, err := planLyricAuto(tracks, lyrics)
	if !errors.Is(err, ErrNativeLyricAutoScopeLimit) || len(changes) != 0 || counts != (store.AutoLyricResult{}) {
		t.Fatal("oversized automatic request planned a partial write", len(changes), counts, err)
	}
}
