//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestNativeDirectoryVisibilityAtomicAndFenced(t *testing.T) {
	ctx := context.Background()
	db, tree, root, _, _ := fencedFixture(t)
	if _, err := db.Exec(`CREATE TABLE admin_audit_log (session_id_hash TEXT, action TEXT, target_count INTEGER, source_summary TEXT, result TEXT, detail TEXT, client_ip TEXT, user_agent TEXT, request_id TEXT, trace_id TEXT, created_at TEXT)`); err != nil {
		t.Fatal(err)
	}
	music := Entry{ParentID: tree.rootID, ObjectID: strings.Repeat("1", 64), Kind: "directory", Name: "music"}
	album := Entry{ParentID: music.ObjectID, ObjectID: strings.Repeat("2", 64), Kind: "directory", Name: "private-album"}
	child := Entry{ParentID: album.ObjectID, ObjectID: strings.Repeat("3", 64), Kind: "directory", Name: "disc"}
	other := Entry{ParentID: music.ObjectID, ObjectID: strings.Repeat("4", 64), Kind: "directory", Name: "other"}
	outside := Entry{ParentID: child.ObjectID, ObjectID: strings.Repeat("5", 64), Kind: "directory", Name: "unsupported-depth"}
	for _, entry := range []Entry{music, album, child, other, outside} {
		facts := Facts{ObjectID: entry.ObjectID}
		if entry == album {
			facts.Playback = &PlaybackFact{Preference: 31, CreatedAt: "2026", UpdatedAt: "2026"}
		}
		if entry == child || entry == other || entry == outside {
			facts.Visibility = &VisibilityFact{Hidden: 1, UpdatedAt: "2026"}
		}
		if err := tree.CreateDirectoryWithFacts(ctx, entry, facts); err != nil {
			t.Fatal(err)
		}
	}
	track := Entry{ParentID: album.ObjectID, ObjectID: strings.Repeat("6", 64), Kind: "audio", Name: "track.mp3"}
	content := []byte("synthetic media")
	digest := sha256.Sum256(content)
	placement := fixturePlacement(t, track.ObjectID)
	placement.BlobID, placement.ReadAlias = "", ""
	placement.Bytes, placement.SHA256 = int64(len(content)), hex.EncodeToString(digest[:])
	trackFacts := fixtureFacts(track.ObjectID)
	trackFacts.Visibility = nil
	prepared, err := tree.PrepareFileWithFreshLocators(ctx, track, placement, trackFacts)
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
	const target = "music/private-album"
	audit := store.AdminAudit{SessionHash: strings.Repeat("a", 64), SourceSummary: target, Detail: "private", RequestID: "request-1"}
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := tree.CaptureCatalogScopeWithLease(ctx, lease, music.ObjectID, false)
	if err != nil {
		lease.Release()
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	if _, err = tree.SetNativeDirectoryVisibility(bounded, []string{target}, true, audit); err == nil {
		cancel()
		lease.Release()
		t.Fatal("visibility writer passed the public read fence")
	}
	cancel()
	lease.Release()

	if _, err = db.Exec(`CREATE TRIGGER refuse_visibility_audit BEFORE INSERT ON admin_audit_log BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = tree.SetNativeDirectoryVisibility(ctx, []string{target}, true, audit); err == nil {
		t.Fatal("audit failure accepted")
	}
	if _, err = db.Exec(`DROP TRIGGER refuse_visibility_audit`); err != nil {
		t.Fatal(err)
	}
	if _, err = tree.SetNativeDirectoryVisibility(ctx, []string{target, target + "/track.mp3"}, true, audit); !errors.Is(err, ErrInvalid) {
		t.Fatal("mixed file batch accepted", err)
	}
	lease, err = tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	visible, err := tree.ReadVisibleObjectWithLease(ctx, lease, track.ObjectID)
	if err == nil {
		err = tree.CheckCatalogScopeWithLease(ctx, lease, music.ObjectID, false, proof)
	}
	lease.Release()
	if err != nil || visible.Path != target+"/track.mp3" {
		t.Fatal("refused write changed the visible tree", err)
	}
	if n, err := tree.SetNativeDirectoryVisibility(ctx, []string{target, target}, true, audit); err != nil || n != 1 {
		t.Fatal("hide", n, err)
	}
	if n, err := tree.SetNativeDirectoryVisibility(ctx, []string{target}, true, audit); err != nil || n != 0 {
		t.Fatal("idempotent hide", n, err)
	}
	lease, err = tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tree.ReadVisibleObjectWithLease(ctx, lease, track.ObjectID); !errors.Is(err, ErrHidden) {
		lease.Release()
		t.Fatal("hidden ancestor still grants a visible read", err)
	}
	if err = tree.CheckCatalogScopeWithLease(ctx, lease, music.ObjectID, false, proof); !errors.Is(err, ErrFenceChanged) {
		lease.Release()
		t.Fatal("hide did not invalidate the previous scope", err)
	}
	lease.Release()
	if n, err := tree.SetNativeDirectoryVisibility(ctx, []string{target, target + "/disc"}, false, audit); err != nil || n != 2 {
		t.Fatal("restore clears only requested supported subtree rules", n, err)
	}
	lease, err = tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if got, err := tree.ReadVisibleObjectWithLease(ctx, lease, track.ObjectID); err != nil || !reflect.DeepEqual(got.Placement, visible.Placement) || !reflect.DeepEqual(got.Facts, visible.Facts) {
		t.Fatal("restoration changed the media placement or facts", err)
	}
	for _, entry := range []Entry{other, outside} {
		facts, rev, err := tree.GetFacts(ctx, entry.ObjectID)
		if err != nil || rev != 1 || facts.Visibility == nil || facts.Visibility.Hidden != 1 {
			t.Fatal("unrelated hide rule changed", entry.Name, err)
		}
	}
	facts, _, err := tree.GetFacts(ctx, album.ObjectID)
	if err != nil || facts.Playback == nil || facts.Playback.Preference != 31 || facts.Visibility != nil {
		t.Fatal("restore changed directory priority or retained its rule", err)
	}
	var count, targets int
	var summary, detail sql.NullString
	if err = db.QueryRow(`SELECT COUNT(*), SUM(target_count), MAX(source_summary), MAX(detail) FROM admin_audit_log WHERE action IN ('hide','unhide')`).Scan(&count, &targets, &summary, &detail); err != nil || count != 2 || targets != 3 || summary.Valid || detail.Valid {
		t.Fatal("visibility audit missing, duplicated or disclosed path", count, targets, err)
	}
}
