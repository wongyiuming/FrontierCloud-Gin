//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestLyricTransactionCacheScopesAndRevalidates(t *testing.T) {
	ctx := context.Background()
	db, s, root, _, _ := fencedFixture(t)
	for _, q := range []string{`CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT NOT NULL,role TEXT NOT NULL)`, `INSERT INTO node_identity VALUES(1,'ffffffffffffffffffffffffffffffff','Master')`, `CREATE TABLE admin_audit_log(session_id_hash TEXT,action TEXT,target_count INTEGER,source_summary TEXT,result TEXT,detail TEXT,client_ip TEXT,user_agent TEXT,request_id TEXT,trace_id TEXT,created_at TEXT)`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	dirs := []Entry{{ParentID: s.rootID, ObjectID: fmt.Sprintf("%064x", 1), Kind: "directory", Name: "music"}, {ParentID: s.rootID, ObjectID: fmt.Sprintf("%064x", 2), Kind: "directory", Name: "lyrics"}, {ParentID: fmt.Sprintf("%064x", 1), ObjectID: fmt.Sprintf("%064x", 3), Kind: "directory", Name: "one"}, {ParentID: fmt.Sprintf("%064x", 1), ObjectID: fmt.Sprintf("%064x", 4), Kind: "directory", Name: "two"}, {ParentID: fmt.Sprintf("%064x", 1), ObjectID: fmt.Sprintf("%064x", 5), Kind: "directory", Name: "unrelated"}}
	for _, d := range dirs {
		if err := s.CreateDirectoryWithFacts(ctx, d, Facts{ObjectID: d.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	entries := []Entry{{ParentID: dirs[2].ObjectID, ObjectID: fmt.Sprintf("%064x", 6), Kind: "audio", Name: "a.mp3"}, {ParentID: dirs[2].ObjectID, ObjectID: fmt.Sprintf("%064x", 7), Kind: "audio", Name: "b.mp3"}, {ParentID: dirs[3].ObjectID, ObjectID: fmt.Sprintf("%064x", 8), Kind: "audio", Name: "c.mp3"}, {ParentID: dirs[1].ObjectID, ObjectID: fmt.Sprintf("%064x", 9), Kind: "lyric", Name: "first.lrc"}, {ParentID: dirs[1].ObjectID, ObjectID: fmt.Sprintf("%064x", 10), Kind: "lyric", Name: "second.lrc"}}
	pub, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(nil)
	for _, entry := range entries {
		p := fixturePlacement(t, entry.ObjectID)
		p.Bytes, p.SHA256, p.BlobID, p.ReadAlias, p.State = 0, hex.EncodeToString(sum[:]), "", "", "active"
		op, e := s.PrepareFileWithFreshLocators(ctx, entry, p, Facts{ObjectID: entry.ObjectID})
		if e != nil {
			t.Fatal(e)
		}
		if e = s.PublishPending(ctx, op.OperationID, pub, bytes.NewReader(nil)); e != nil {
			t.Fatal(e)
		}
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	proofs := make([]CatalogScopeProof, 3)
	for i, d := range dirs[2:5] {
		proofs[i], err = s.CaptureCatalogScopeWithLease(ctx, lease, d.ObjectID, false)
		if err != nil {
			t.Fatal(err)
		}
	}
	lease.Release()
	request := NativeLyricOperation{OriginID: entries[3].ObjectID, TargetIDs: []string{entries[0].ObjectID, entries[1].ObjectID, entries[2].ObjectID}}
	for _, entry := range entries[:3] {
		request.Changes = append(request.Changes, NativeLyricChange{TrackID: entry.ObjectID, ExpectedFactsRevision: 1, LyricID: entries[3].ObjectID})
	}
	if _, err = db.Exec(`CREATE TRIGGER fail_scope BEFORE UPDATE ON sealed_tree_listing BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if err = s.ApplyNativeLyricBatch(ctx, request, store.AdminAudit{}); err == nil {
		t.Fatal("scope failure accepted")
	}
	for _, entry := range entries[:3] {
		f, revision, e := s.GetFacts(ctx, entry.ObjectID)
		if e != nil || revision != 1 || f.Lyric != nil {
			t.Fatal("scope error did not roll back", e)
		}
	}
	if _, err = db.Exec(`DROP TRIGGER fail_scope`); err != nil {
		t.Fatal(err)
	}
	if err = s.ApplyNativeLyricBatch(ctx, request, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i, d := range dirs[2:5] {
		e := s.CheckCatalogScopeWithLease(ctx, lease, d.ObjectID, false, proofs[i])
		if i < 2 && e == nil || i == 2 && e != nil {
			t.Fatal("scope invalidation incorrect", i, e)
		}
	}
	lease.Release()
	idx, err := s.tree.ObjectIndex(entries[4].ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	var original []byte
	if err = db.QueryRow(`SELECT sealed FROM sealed_tree_placements WHERE object_index=?`, idx).Scan(&original); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE sealed_tree_placements SET sealed=zeroblob(length(sealed)) WHERE object_index=?`, idx); err != nil {
		t.Fatal(err)
	}
	rebind := NativeLyricOperation{OriginID: entries[0].ObjectID, TargetIDs: []string{entries[4].ObjectID}, Changes: []NativeLyricChange{{TrackID: entries[0].ObjectID, ExpectedFactsRevision: 2, LyricID: entries[4].ObjectID}}}
	if err = s.ApplyNativeLyricBatch(ctx, rebind, store.AdminAudit{}); err == nil {
		t.Fatal("different transaction reused stale lyric validation")
	}
	if _, err = db.Exec(`UPDATE sealed_tree_placements SET sealed=? WHERE object_index=?`, original, idx); err != nil {
		t.Fatal(err)
	}
	if err = s.ApplyNativeLyricBatch(ctx, rebind, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	f, revision, err := s.GetFacts(ctx, entries[0].ObjectID)
	if err != nil || revision != 3 || f.Lyric == nil || f.Lyric.LyricID != entries[4].ObjectID {
		t.Fatal("second lyric was not revalidated", err)
	}
}
