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

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestMasterLocalLyricDeletionDetachesAllExplicitLinksAtomically(t *testing.T) {
	ctx := context.Background()
	db, tree, root, _, _ := fencedFixture(t)
	for _, stmt := range []string{
		`CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT,role TEXT,private_key TEXT,created_at INTEGER)`,
		`INSERT INTO node_identity VALUES(1,'ffffffffffffffffffffffffffffffff','Master','sealed-fixture',1)`,
		`CREATE TABLE cluster_storage_members(member_id TEXT,member_kind TEXT,transport TEXT,relationship_id TEXT,used_bytes INTEGER)`,
		`INSERT INTO cluster_storage_members VALUES('ffffffffffffffffffffffffffffffff','MasterLocal','Local',NULL,1000)`,
		`CREATE TABLE IF NOT EXISTS sealed_tree_owner_fence(singleton INTEGER PRIMARY KEY,fence_tag TEXT)`,
		`INSERT INTO sealed_tree_owner_fence VALUES(1,'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee')`,
		`CREATE TABLE admin_audit_log(session_id_hash TEXT,action TEXT,target_count INTEGER,source_summary TEXT,result TEXT,detail TEXT,client_ip TEXT,user_agent TEXT,request_id TEXT,trace_id TEXT,created_at TEXT)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	music := Entry{ParentID: tree.rootID, ObjectID: strings.Repeat("1", 64), Kind: "directory", Name: "music"}
	album := Entry{ParentID: music.ObjectID, ObjectID: strings.Repeat("2", 64), Kind: "directory", Name: "album"}
	lyrics := Entry{ParentID: tree.rootID, ObjectID: strings.Repeat("3", 64), Kind: "directory", Name: "lyrics"}
	for _, entry := range []Entry{music, album, lyrics} {
		if err := tree.CreateDirectoryWithFacts(ctx, entry, Facts{ObjectID: entry.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	lyric := Entry{ParentID: lyrics.ObjectID, ObjectID: strings.Repeat("4", 64), Kind: "lyric", Name: "shared.lrc"}
	one := Entry{ParentID: album.ObjectID, ObjectID: strings.Repeat("5", 64), Kind: "audio", Name: "one.mp3"}
	two := Entry{ParentID: album.ObjectID, ObjectID: strings.Repeat("6", 64), Kind: "audio", Name: "hidden.mp3"}
	metadata, err := mediacrypto.NewMetadata(1)
	if err != nil {
		t.Fatal(err)
	}
	content := bytes.Repeat([]byte{7}, int(metadata.CiphertextSize))
	digest := sha256.Sum256(content)
	pub, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	publish := func(entries ...Entry) {
		t.Helper()
		for _, entry := range entries {
			p := Placement{ObjectID: entry.ObjectID, NativeObjectID: entry.ObjectID, OwnerID: strings.Repeat("f", 32), Bytes: int64(len(content)), SHA256: hex.EncodeToString(digest[:]), State: "active", Encryption: &metadata}
			facts := Facts{ObjectID: entry.ObjectID}
			if entry == two {
				facts.Visibility = &VisibilityFact{Hidden: 1, UpdatedAt: "hidden"}
			}
			prepared, err := tree.PrepareFileWithFreshLocators(ctx, entry, p, facts)
			if err != nil {
				t.Fatal(err)
			}
			if err = tree.PublishPending(ctx, prepared.OperationID, pub, bytes.NewReader(content)); err != nil {
				t.Fatal(err)
			}
		}
	}
	publish(lyric, one, two)
	target := store.SelectedMediaDeleteTarget{Path: "lyrics/shared.lrc", ResourceID: lyric.ObjectID}
	if err = tree.ApplyNativeTrackLyricPath(ctx, "music/album/one.mp3", target.Path, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	stale, err := tree.PreflightMasterLocalLyricDeletion(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if err = tree.ApplyNativeTrackLyricPath(ctx, "music/album/hidden.mp3", target.Path, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	queue := func(proof *MasterLocalLyricDeletePreflight) (store.SelectedMediaDeleteItem, error) {
		var item store.SelectedMediaDeleteItem
		err := tree.WithCoordinatedMutation(ctx, db, func(m *CoordinatedMutation) error {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			defer tx.Rollback()
			item, _, err = m.QueueMasterLocalLyricDeletionTx(ctx, tx, target, proof, store.AdminAudit{})
			if err != nil {
				return err
			}
			return tx.Commit()
		})
		return item, err
	}
	if _, err = queue(stale); !errors.Is(err, ErrFenceChanged) {
		t.Fatal("stale reverse-link census was accepted", err)
	}
	proof, err := tree.PreflightMasterLocalLyricDeletion(ctx, target)
	if err != nil || len(proof.changes) != 2 {
		t.Fatal("hidden explicit association was omitted", err)
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	const publishedFacts = `SELECT object_index,revision,encryption_id,sealed FROM sealed_tree_facts ORDER BY object_index LIMIT ?`
	proofs := map[string]*MasterLocalLyricDeletePreflight{target.ResourceID: proof}
	scratch := make([]byte, factsPayloadBytes)
	remaining, changes := 0, 0
	if err = tree.scanMasterLocalLyricReferencesBatch(ctx, tx, publishedFacts, false, proofs, scratch, &remaining, &changes); !errors.Is(err, ErrMasterLocalLyricDeleteCatalogLimit) {
		t.Fatal("incomplete catalog census did not report its own limit", err)
	}
	remaining, changes = MaxLyricScopeEntries, MaxNativeLyricPatchTracks
	if err = tree.scanMasterLocalLyricReferencesBatch(ctx, tx, publishedFacts, false, proofs, scratch, &remaining, &changes); !errors.Is(err, ErrMasterLocalLyricDeleteLimit) {
		t.Fatal("association change limit was conflated with catalog size", err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TRIGGER refuse_lyric_delete_audit BEFORE INSERT ON admin_audit_log BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = queue(proof); err == nil {
		t.Fatal("detachment committed without its encrypted audit")
	}
	for _, entry := range []Entry{one, two} {
		facts, _, err := tree.GetFacts(ctx, entry.ObjectID)
		if err != nil || facts.Lyric == nil || facts.Lyric.LyricID != lyric.ObjectID {
			t.Fatal("failed queue partially detached lyrics", err)
		}
	}
	if _, err = db.Exec(`DROP TRIGGER refuse_lyric_delete_audit`); err != nil {
		t.Fatal(err)
	}
	item, err := queue(proof)
	if err != nil || item.State != store.SelectedMediaDeletePending {
		t.Fatal("failed to commit associations and pending deletion", err)
	}
	for _, entry := range []Entry{one, two} {
		facts, _, err := tree.GetFacts(ctx, entry.ObjectID)
		if err != nil || facts.Lyric != nil || facts.LyricResolution == nil || facts.LyricResolution.State != "default" || facts.LyricResolution.Origin != "native" {
			t.Fatal("deleted lyric did not leave an authenticated fallback", err)
		}
	}
	if err = tree.ApplyNativeTrackLyricPath(ctx, "music/album/one.mp3", target.Path, store.AdminAudit{}); err == nil {
		t.Fatal("new association bypassed the committed deletion intent")
	}
	if _, err = tree.PreflightMasterLocalLyricDeletion(ctx, store.SelectedMediaDeleteTarget{Path: "lyrics/default.lrc", ResourceID: lyric.ObjectID}); !errors.Is(err, ErrInvalid) {
		t.Fatal("built-in default lyric was not protected", err)
	}
	other := Entry{ParentID: lyrics.ObjectID, ObjectID: strings.Repeat("7", 64), Kind: "lyric", Name: "other.lrc"}
	third := Entry{ParentID: lyrics.ObjectID, ObjectID: strings.Repeat("8", 64), Kind: "lyric", Name: "third.lrc"}
	publish(other, third)
	if err = tree.ApplyNativeTrackLyricPath(ctx, "music/album/one.mp3", "lyrics/other.lrc", store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = tree.ApplyNativeTrackLyricPath(ctx, "music/album/hidden.mp3", "lyrics/third.lrc", store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	targets := []store.SelectedMediaDeleteTarget{{Path: "lyrics/other.lrc", ResourceID: other.ObjectID}, {Path: "lyrics/third.lrc", ResourceID: third.ObjectID}}
	batch, err := tree.PreflightMasterLocalLyricDeletions(ctx, targets)
	if err != nil || len(batch.proofs) != 2 {
		t.Fatal("failed to share a complete multi-lyric preflight", err)
	}
	err = tree.WithCoordinatedMutation(ctx, db, func(m *CoordinatedMutation) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		admission, err := m.AdmitMasterLocalLyricDeletionsTx(ctx, tx, batch)
		if err != nil {
			return err
		}
		for _, target := range targets {
			if item, _, err := m.QueueMasterLocalLyricDeletionAdmittedTx(ctx, tx, target, admission, store.AdminAudit{}); err != nil || item.State != store.SelectedMediaDeletePending {
				return errors.Join(err, errors.New("multi-lyric batch did not queue"))
			}
		}
		return tx.Commit()
	})
	if err != nil {
		t.Fatal("earlier lyric queue invalidated the batch's next admitted lyric", err)
	}
	for _, entry := range []Entry{one, two} {
		facts, _, err := tree.GetFacts(ctx, entry.ObjectID)
		if err != nil || facts.Lyric != nil || facts.LyricResolution == nil || facts.LyricResolution.State != "default" {
			t.Fatal("multi-lyric batch did not detach all references", err)
		}
	}
}
