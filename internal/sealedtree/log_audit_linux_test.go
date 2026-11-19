package sealedtree

import (
	"bytes"
	"context"
	"encoding/base64"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/logarchive"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	"strings"
	"testing"
	"time"
)

func TestLogNativeTreeActionsUseEncryptedTransactionalArchive(t *testing.T) {
	ctx := context.Background()
	db, tree, _, _, _ := fencedFixture(t)
	if _, e := db.Exec(`CREATE TABLE admin_audit_log(session_id_hash TEXT,action TEXT,target_count INTEGER,source_summary TEXT,result TEXT,detail TEXT,client_ip TEXT,user_agent TEXT,request_id TEXT,trace_id TEXT,created_at TEXT)`); e != nil {
		t.Fatal(e)
	}
	key, _ := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	catalog, e := logarchive.SharedCatalog(db, key, strings.Repeat("a", 32))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = catalog.Configure(ctx, logarchive.Target{MemberID: strings.Repeat("b", 32), RelationshipID: strings.Repeat("c", 32), Origin: "https://logs.test"}, 0); e != nil {
		t.Fatal(e)
	}
	tree.ConfigureLogArchive(catalog)
	music := Entry{ParentID: tree.rootID, ObjectID: strings.Repeat("1", 64), Kind: "directory", Name: "music"}
	album := Entry{ParentID: music.ObjectID, ObjectID: strings.Repeat("2", 64), Kind: "directory", Name: "private-album"}
	for _, v := range []Entry{music, album} {
		if e = tree.CreateDirectoryWithFacts(ctx, v, Facts{ObjectID: v.ObjectID}); e != nil {
			t.Fatal(e)
		}
	}
	audit := store.AdminAudit{UserAgent: "private-audit-agent", RequestID: "native-log-test"}
	if n, e := tree.SetNativeDirectoryVisibility(ctx, []string{"music/private-album"}, true, audit); e != nil || n != 1 {
		t.Fatal("visibility", e)
	}
	if _, e = tree.SetNativePriority(ctx, "music/private-album", album.ObjectID, 31, true); e != nil {
		t.Fatal("priority", e)
	}
	if _, e = tree.RenameNativeDirectory(ctx, "music/private-album", "renamed", audit); e != nil {
		t.Fatal("rename", e)
	}
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	payload := lyricAuditPayload{Origin: "lyrics/private.lrc", Targets: []string{"music/renamed/song.mp3"}, Changes: []LyricAuditChange{{Track: "music/renamed/song.mp3", Lyric: "lyrics/private.lrc"}}, Relations: 1, Audit: audit}
	if e = tree.appendEncryptedLyricAudit(ctx, tx, strings.Repeat("d", 32), payload); e != nil {
		tx.Rollback()
		t.Fatal("lyric audit", e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	var old int
	if e = db.QueryRow("SELECT COUNT(*) FROM admin_audit_log").Scan(&old); e != nil || old != 0 {
		t.Fatal("tree mutation bypassed log archive", old, e)
	}
	now := time.Now().Add(time.Millisecond)
	entries, _, e := catalog.Query(ctx, now.Add(-time.Hour), now, now, logarchive.Audit, false, "")
	if e != nil || len(entries) < 6 {
		t.Fatal("tree audit sources missing", len(entries), e)
	}
	found := false
	for _, v := range entries {
		entry, e := catalog.Entry(ctx, v.Record.Header.ID)
		if e != nil {
			t.Fatal(e)
		}
		plain, e := logarchive.OpenForMaster(key, entry.Record, entry.Ciphertext)
		if e != nil {
			t.Fatal(e)
		}
		found = found || bytes.Contains(plain, []byte("lyrics/private.lrc"))
	}
	if !found {
		t.Fatal("lyric audit is not readable/searchable after browser decryption")
	}
	// A mutation still rolls back if its required audit cannot be committed.
	if _, e = db.Exec("UPDATE log_budget SET used_bytes=134217728 WHERE id=1"); e != nil {
		t.Fatal(e)
	}
	if _, e = tree.SetNativeDirectoryVisibility(ctx, []string{"music/renamed"}, false, audit); e == nil {
		t.Fatal("native mutation ignored audit failure")
	}
	facts, _, e := tree.GetFacts(ctx, album.ObjectID)
	if e != nil || facts.Visibility == nil || facts.Visibility.Hidden != 1 {
		t.Fatal("audit failure did not roll back native visibility", e)
	}
}
