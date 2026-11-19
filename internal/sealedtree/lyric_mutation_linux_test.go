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

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestNativeLyricBatchIsAtomicAndAuditIsSealed(t *testing.T) {
	ctx := context.Background()
	db, s, root, _, _ := fencedFixture(t)
	for _, q := range []string{
		`CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT NOT NULL,role TEXT NOT NULL)`,
		`INSERT INTO node_identity VALUES(1,'ffffffffffffffffffffffffffffffff','Master')`,
		`CREATE TABLE admin_audit_log(session_id_hash TEXT,action TEXT,target_count INTEGER,source_summary TEXT,result TEXT,detail TEXT,client_ip TEXT,user_agent TEXT,request_id TEXT,trace_id TEXT,created_at TEXT)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	dirs := []Entry{{ParentID: s.rootID, ObjectID: fmt.Sprintf("%064x", 1), Kind: "directory", Name: "music"}, {ParentID: s.rootID, ObjectID: fmt.Sprintf("%064x", 2), Kind: "directory", Name: "lyrics"}}
	for _, d := range dirs {
		if err := s.CreateDirectoryWithFacts(ctx, d, Facts{ObjectID: d.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	pub, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(nil)
	entries := []Entry{
		{ParentID: dirs[0].ObjectID, ObjectID: fmt.Sprintf("%064x", 3), Kind: "audio", Name: "secret-one.mp3"},
		{ParentID: dirs[0].ObjectID, ObjectID: fmt.Sprintf("%064x", 4), Kind: "audio", Name: "secret-two.mp3"},
		{ParentID: dirs[1].ObjectID, ObjectID: fmt.Sprintf("%064x", 5), Kind: "lyric", Name: "secret.lrc"},
		{ParentID: dirs[0].ObjectID, ObjectID: fmt.Sprintf("%064x", 6), Kind: "audio", Name: "secret-three.mp3"},
		{ParentID: dirs[1].ObjectID, ObjectID: fmt.Sprintf("%064x", 7), Kind: "lyric", Name: "other.lrc"},
	}
	publish := func(t *testing.T, entries []Entry) {
		t.Helper()
		for _, e := range entries {
			p := fixturePlacement(t, e.ObjectID)
			p.Bytes, p.SHA256, p.BlobID, p.ReadAlias, p.State = 0, hex.EncodeToString(sum[:]), "", "", "active"
			op, err := s.PrepareFileWithFreshLocators(ctx, e, p, Facts{ObjectID: e.ObjectID})
			if err != nil {
				t.Fatal(err)
			}
			if err = s.PublishPending(ctx, op.OperationID, pub, bytes.NewReader(nil)); err != nil {
				t.Fatal(err)
			}
		}
	}
	publish(t, entries[:3])
	changes := []NativeLyricChange{{TrackID: entries[0].ObjectID, ExpectedFactsRevision: 1, LyricID: entries[2].ObjectID}, {TrackID: entries[1].ObjectID, ExpectedFactsRevision: 1, LyricID: entries[2].ObjectID}}
	if _, err = db.Exec(`CREATE TRIGGER reject_second_audit BEFORE INSERT ON admin_audit_log BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if err = s.ApplyNativeLyricBatch(ctx, NativeLyricOperation{OriginID: entries[2].ObjectID, TargetIDs: []string{entries[0].ObjectID, entries[1].ObjectID}, Changes: changes}, store.AdminAudit{SessionHash: "session-secret"}); err == nil {
		t.Fatal("partial audit accepted")
	}
	var count int
	if err = db.QueryRow(`SELECT COUNT(*) FROM admin_audit_log`).Scan(&count); err != nil || count != 0 {
		t.Fatal("audit did not roll back", err)
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries[:2] {
		view, err := s.ReadListingObjectWithLease(ctx, lease, e.ObjectID, true)
		if err != nil || view.FactsRevision != 1 || view.Facts.Lyric != nil {
			t.Fatal("facts did not roll back", err)
		}
	}
	lease.Release()
	if _, err = db.Exec(`DROP TRIGGER reject_second_audit`); err != nil {
		t.Fatal(err)
	}
	if err = s.ApplyNativeLyricBatch(ctx, NativeLyricOperation{OriginID: entries[2].ObjectID, TargetIDs: []string{entries[0].ObjectID, entries[1].ObjectID}, Changes: changes}, store.AdminAudit{SessionHash: "session-secret"}); err != nil {
		t.Fatal(err)
	}
	first, _, err := s.GetFacts(ctx, entries[0].ObjectID)
	if err != nil || first.Lyric == nil {
		t.Fatal("missing first association", err)
	}
	createdAt := first.Lyric.CreatedAt
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries[:2] {
		got, err := s.SelectLyricForDisplayWithLease(ctx, lease, e.ObjectID)
		if err != nil || got.ExplicitLyricID != entries[2].ObjectID || got.Origin != "native" {
			t.Fatal("native relation missing", err)
		}
	}
	page, _, err := s.ListCatalogPageWithLease(ctx, lease, dirs[0].ObjectID, "", 10, false)
	if err != nil || s.VerifyNativeCatalogLyricFactsWithLease(ctx, lease, page) != nil {
		t.Fatal("native batch evidence rejected", err)
	}
	resolution := *page[0].Facts.LyricResolution
	resolution.Evidence = strings.Repeat("0", 64)
	page[0].Facts.LyricResolution = &resolution
	if s.VerifyNativeCatalogLyricFactsWithLease(ctx, lease, page) == nil {
		t.Fatal("tampered native batch evidence accepted")
	}
	lease.Release()
	var combined string
	if err = db.QueryRow(`SELECT group_concat(detail,'') FROM admin_audit_log`).Scan(&combined); err != nil {
		t.Fatal(err)
	}
	fields := strings.Split(combined, ":")
	if len(fields) != 6 {
		t.Fatal("audit was not one logical operation")
	}
	decoded, err := s.ReadEncryptedLyricAudit(ctx, fields[1])
	if err != nil || decoded.Origin != "lyrics/secret.lrc" || len(decoded.Targets) != 2 || decoded.Relations != 2 || len(decoded.Changes) != 2 {
		t.Fatal("logical audit did not recover", err)
	}
	for _, secret := range []string{"secret-one.mp3", "secret-two.mp3", "secret.lrc", "session-secret"} {
		if strings.Contains(combined, secret) {
			t.Fatal("audit exposed plaintext")
		}
	}
	if err = s.ApplyNativeLyricBatch(ctx, NativeLyricOperation{OriginID: entries[2].ObjectID, TargetIDs: []string{entries[0].ObjectID, entries[1].ObjectID}, Changes: changes}, store.AdminAudit{}); err == nil {
		t.Fatal("stale revision accepted")
	}
	if err = s.ApplyNativeLyricBatch(ctx, NativeLyricOperation{OriginID: entries[0].ObjectID, Changes: []NativeLyricChange{{TrackID: entries[0].ObjectID, ExpectedFactsRevision: 2}}}, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.SelectLyricForDisplayWithLease(ctx, lease, entries[0].ObjectID)
	if err != nil || !got.BuiltinFallback || got.ExplicitLyricID != "" {
		t.Fatal("unbind did not select internal fallback", err)
	}
	unbound, err := s.ReadListingObjectWithLease(ctx, lease, entries[0].ObjectID, true)
	if err != nil || unbound.Facts.LyricResolution == nil || unbound.Facts.LyricResolution.State != "default" || unbound.Facts.InternalDefaultLyric != nil {
		t.Fatal("explicit built-in relation was lost", err)
	}
	lease.Release()
	if err = s.ApplyNativeLyricBatch(ctx, NativeLyricOperation{OriginID: entries[2].ObjectID, Changes: []NativeLyricChange{{TrackID: entries[0].ObjectID, ExpectedFactsRevision: 3}}}, store.AdminAudit{}); err == nil {
		t.Fatal("unrelated track unbound through lyric operation")
	}
	if err = s.ApplyNativeLyricBatch(ctx, NativeLyricOperation{OriginID: entries[0].ObjectID, TargetIDs: []string{entries[2].ObjectID}, Changes: []NativeLyricChange{{TrackID: entries[0].ObjectID, ExpectedFactsRevision: 3, LyricID: entries[2].ObjectID}}}, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	last, _, err := s.GetFacts(ctx, entries[0].ObjectID)
	if err != nil || last.Lyric == nil || last.Lyric.CreatedAt != createdAt {
		t.Fatal("fallback transition lost original relation creation time", err)
	}
	t.Run("priority preserves the lyric relation", func(t *testing.T) {
		track := "music/secret-one.mp3"
		if _, err := s.SetNativePriority(ctx, track, entries[1].ObjectID, 7, false); err != store.ErrPriorityStale {
			t.Fatal("mismatched resource identity accepted", err)
		}
		if _, err := s.SetNativePriority(ctx, track, entries[0].ObjectID, 7, true); err != store.ErrPriorityMove {
			t.Fatal("track treated as directory", err)
		}
		if _, err := db.Exec(`CREATE TRIGGER reject_priority_audit BEFORE INSERT ON admin_audit_log WHEN NEW.action='media_priority' BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := s.SetNativePriority(ctx, track, entries[0].ObjectID, 7, false); err == nil {
			t.Fatal("priority write committed without audit")
		}
		unchanged, revision, err := s.GetFacts(ctx, entries[0].ObjectID)
		if err != nil || unchanged.Playback != nil {
			t.Fatal("priority write did not roll back", err)
		}
		if _, err = db.Exec(`DROP TRIGGER reject_priority_audit`); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			result, err := s.SetNativePriority(ctx, track, entries[0].ObjectID, 7, false)
			if err != nil || result.Preference != 7 || result.MediaID != entries[0].ObjectID {
				t.Fatal("priority update failed", err)
			}
		}
		updated, next, err := s.GetFacts(ctx, entries[0].ObjectID)
		if err != nil || next != revision+1 || updated.Playback == nil || updated.Playback.Preference != 7 || updated.Playback.LegacyMediaPath != "" || updated.Lyric == nil || *updated.Lyric != *last.Lyric {
			t.Fatal("priority failed to preserve encrypted facts or retry was not idempotent", err)
		}
		if err = db.QueryRow(`SELECT COUNT(*) FROM admin_audit_log WHERE action='media_priority' AND source_summary IS NULL AND detail IS NULL`).Scan(&count); err != nil || count != 1 {
			t.Fatal("expected one redacted audit event", err)
		}
	})
	t.Run("path patch preserves unlisted tracks and rejects a stale unlink atomically", func(t *testing.T) {
		publish(t, entries[3:])
		first, second, third := "music/secret-one.mp3", "music/secret-two.mp3", "music/secret-three.mp3"
		lyric, other := "lyrics/secret.lrc", "lyrics/other.lrc"
		check := func(track Entry, want string) int64 {
			t.Helper()
			facts, revision, err := s.GetFacts(ctx, track.ObjectID)
			if err != nil || (facts.Lyric == nil) != (want == "") || (facts.Lyric != nil && facts.Lyric.LyricID != want) {
				t.Fatal("unexpected lyric after patch", track.Name, err)
			}
			return revision
		}
		unchanged := check(entries[1], entries[2].ObjectID)
		if err := s.ApplyNativeLyricPathPatch(ctx, lyric, []string{third}, []string{first}, store.AdminAudit{}); err != nil {
			t.Fatal(err)
		}
		check(entries[0], "")
		if check(entries[1], entries[2].ObjectID) != unchanged {
			t.Fatal("patch changed an unlisted track")
		}
		check(entries[3], entries[2].ObjectID)
		if err := s.ApplyNativeLyricPathPatch(ctx, other, []string{second}, []string{third}, store.AdminAudit{}); !errors.Is(err, ErrConflict) {
			t.Fatal("patch removed a track linked to a different lyric", err)
		}
		if check(entries[1], entries[2].ObjectID) != unchanged {
			t.Fatal("failed removal committed an earlier addition")
		}
		for _, selection := range []struct{ link, unlink []string }{
			{[]string{first, first}, nil}, {[]string{first}, []string{first}}, {nil, nil},
			{make([]string, MaxNativeLyricPatchTracks), []string{first}},
		} {
			if err := s.ApplyNativeLyricPathPatch(ctx, lyric, selection.link, selection.unlink, store.AdminAudit{}); !errors.Is(err, ErrInvalid) {
				t.Fatal("invalid track selection accepted", err)
			}
		}
	})
}

func TestEncryptedLyricAuditFragmentsFailClosed(t *testing.T) {
	ctx := context.Background()
	db, s, _, _, _ := fencedFixture(t)
	if _, err := db.Exec(`CREATE TABLE admin_audit_log(session_id_hash TEXT,action TEXT,target_count INTEGER,source_summary TEXT,result TEXT,detail TEXT,client_ip TEXT,user_agent TEXT,request_id TEXT,trace_id TEXT,created_at TEXT)`); err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 500)
	for i := range paths {
		paths[i] = fmt.Sprintf("music/%04d/", i) + strings.Repeat("秘密", 70) + ".mp3"
	}
	op, err := NewBlobID()
	if err != nil {
		t.Fatal(err)
	}
	value := lyricAuditPayload{Origin: "lyrics/sensitive.lrc", Targets: paths, Relations: len(paths), At: "2026-01-01", Audit: store.AdminAudit{TargetCount: len(paths) + 1}}
	if _, err = db.Exec(`CREATE TRIGGER reject_second_fragment BEFORE INSERT ON admin_audit_log WHEN (SELECT COUNT(*) FROM admin_audit_log)>0 BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	failed, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.appendEncryptedLyricAudit(ctx, failed, op, value); err == nil {
		t.Fatal("fragment fault accepted")
	}
	if err = failed.Rollback(); err != nil {
		t.Fatal(err)
	}
	var rolledBack int
	if err = db.QueryRow(`SELECT COUNT(*) FROM admin_audit_log`).Scan(&rolledBack); err != nil || rolledBack != 0 {
		t.Fatal("partial fragment survived", err)
	}
	if _, err = db.Exec(`DROP TRIGGER reject_second_fragment`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.appendEncryptedLyricAudit(ctx, tx, op, value); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got, err := s.ReadEncryptedLyricAudit(ctx, op)
	if err != nil || len(got.Targets) != len(paths) || got.Targets[499] != paths[499] {
		t.Fatal("long audit failed recovery", err)
	}
	var count int
	if err = db.QueryRow(`SELECT COUNT(*) FROM admin_audit_log`).Scan(&count); err != nil || count < 2 {
		t.Fatal("fixture did not fragment", err)
	}
	var detail string
	if err = db.QueryRow(`SELECT detail FROM admin_audit_log LIMIT 1`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(detail, "sensitive") || strings.Contains(detail, "秘密") {
		t.Fatal("plaintext audit")
	}
	if _, err = db.Exec(`INSERT INTO admin_audit_log SELECT * FROM admin_audit_log WHERE detail=?`, detail); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadEncryptedLyricAudit(ctx, op); err == nil {
		t.Fatal("duplicate fragment accepted")
	}
	if _, err = db.Exec(`DELETE FROM admin_audit_log WHERE rowid=(SELECT MAX(rowid) FROM admin_audit_log WHERE detail=?)`, detail); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`DELETE FROM admin_audit_log WHERE detail=?`, detail); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadEncryptedLyricAudit(ctx, op); err == nil {
		t.Fatal("missing audit fragment accepted")
	}
}
