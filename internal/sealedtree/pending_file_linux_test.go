//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestPendingFileRecoversPublishedBlobAndCommitsAtomically(t *testing.T) {
	ctx := context.Background()
	db, s, _ := sqliteFixture(t)
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	pub, _ := NewBlobPublisher(root)
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "audio", Name: "秘密歌曲.mp3"}
	loc := fixturePlacement(t, entry.ObjectID)
	content := []byte("isolated synthetic audio bytes")
	sum := sha256.Sum256(content)
	loc.Bytes = int64(len(content))
	loc.SHA256 = hex.EncodeToString(sum[:])
	op, err := s.PrepareFile(ctx, entry, loc)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Get(ctx, entry.ObjectID); err == nil {
		t.Fatal("pending object became visible")
	}
	if err = pub.Publish(ctx, op, loc.BlobID, loc.Bytes, loc.SHA256, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	// Simulates a restart after hard-link publication and before SQL commit.
	if err = s.PublishPending(ctx, op, pub, bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	// A lost response after commit can be acknowledged without republishing.
	if err = s.PublishPending(ctx, op, pub, bytes.NewReader(nil)); err != nil {
		t.Fatalf("completed operation retry failed: %v", err)
	}
	got, _, err := s.Get(ctx, entry.ObjectID)
	if err != nil || got != entry {
		t.Fatalf("missing committed entry: %v", err)
	}
	placed, err := s.GetPlacement(ctx, entry.ObjectID)
	if err != nil || placed.BlobID != loc.BlobID {
		t.Fatalf("placement: %v", err)
	}
	var pending, reserved int
	if err = db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_pending_files`).Scan(&pending); err != nil || pending != 0 {
		t.Fatal("pending not cleared")
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_operation_ids WHERE operation_id=?`, op).Scan(&reserved); err != nil || reserved != 1 {
		t.Fatal("operation ID reservation lost")
	}
	if _, err = db.Exec(`UPDATE sealed_tree_operation_ids SET receipt_mac=? WHERE operation_id=?`, strings.Repeat("0", 64), op); err != nil {
		t.Fatal(err)
	}
	if err = s.PublishPending(ctx, op, pub, bytes.NewReader(nil)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("forged commit receipt accepted: %v", err)
	}
	if _, err = s.Check(ctx); !errors.Is(err, ErrInvalid) {
		t.Fatalf("forged receipt passed integrity scan: %v", err)
	}
}

func TestPendingAliasMappingRollbackAndReplay(t *testing.T) {
	ctx := context.Background()
	db, s, _ := sqliteFixture(t)
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	pub, err := NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("b", 64), Kind: "audio", Name: "synthetic"}
	content := []byte("synthetic bytes")
	sum := sha256.Sum256(content)
	placement := fixturePlacement(t, entry.ObjectID)
	placement.Bytes, placement.SHA256 = int64(len(content)), hex.EncodeToString(sum[:])
	op, err := s.PrepareFileWithFacts(ctx, entry, placement, Facts{ObjectID: entry.ObjectID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TRIGGER reject_alias BEFORE INSERT ON sealed_tree_aliases BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if err = s.PublishPending(ctx, op, pub, bytes.NewReader(content)); err == nil {
		t.Fatal("failed alias transaction committed")
	}
	var records, mappings, pending int
	if err = db.QueryRow(`SELECT (SELECT COUNT(*) FROM sealed_tree_records),(SELECT COUNT(*) FROM sealed_tree_aliases),(SELECT COUNT(*) FROM sealed_tree_pending_files)`).Scan(&records, &mappings, &pending); err != nil || records != 0 || mappings != 0 || pending != 1 {
		t.Fatal("alias failure left partial visible state", err)
	}
	if _, err = db.Exec(`DROP TRIGGER reject_alias`); err != nil {
		t.Fatal(err)
	}
	if err = s.PublishPending(ctx, op, pub, bytes.NewReader(nil)); err != nil {
		t.Fatal("retry did not recover original blob and alias", err)
	}
	got, err := s.GetPlacement(ctx, entry.ObjectID)
	if err != nil || got.BlobID != placement.BlobID || got.ReadAlias != placement.ReadAlias {
		t.Fatal("recovered mapping changed", err)
	}
}

func TestPendingFileFailureDoesNotExposeMetadata(t *testing.T) {
	ctx := context.Background()
	_, s, _ := sqliteFixture(t)
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	pub, _ := NewBlobPublisher(root)
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("c", 64), Kind: "audio", Name: "秘密.mp3"}
	loc := fixturePlacement(t, entry.ObjectID)
	content := []byte("expected")
	sum := sha256.Sum256(content)
	loc.Bytes = int64(len(content))
	loc.SHA256 = hex.EncodeToString(sum[:])
	op, err := s.PrepareFile(ctx, entry, loc)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.PublishPending(ctx, op, pub, bytes.NewReader([]byte("bad"))); !errors.Is(err, ErrBlobIncomplete) {
		t.Fatalf("expected failure: %v", err)
	}
	if _, _, err = s.Get(ctx, entry.ObjectID); err == nil {
		t.Fatal("failed payload became visible")
	}
	if err = s.PublishPending(ctx, op, pub, bytes.NewReader(content)); !errors.Is(err, ErrBlobIncomplete) {
		t.Fatalf("damaged stage reused: %v", err)
	}
}

func TestPendingFilePublishesFactsAtomicallyAndRecoversAfterSQLFailure(t *testing.T) {
	ctx := context.Background()
	db, s, _ := sqliteFixture(t)
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	pub, _ := NewBlobPublisher(root)
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("6", 64), Kind: "audio", Name: "隐私歌曲.mp3"}
	facts := fixtureFacts(entry.ObjectID)
	loc := fixturePlacement(t, entry.ObjectID)
	content := []byte("synthetic protected bytes")
	sum := sha256.Sum256(content)
	loc.Bytes = int64(len(content))
	loc.SHA256 = hex.EncodeToString(sum[:])
	op, err := s.PrepareFileWithFacts(ctx, entry, loc, facts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Check(ctx); err != nil {
		t.Fatal("pending facts not authenticated", err)
	}
	if _, err = db.Exec(`CREATE TRIGGER reject_facts BEFORE INSERT ON sealed_tree_facts BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if err = s.PublishPending(ctx, op, pub, bytes.NewReader(content)); err == nil {
		t.Fatal("failed fact transaction accepted")
	}
	if _, _, err = s.Get(ctx, entry.ObjectID); err == nil {
		t.Fatal("name visible after failed fact transaction")
	}
	if _, err = db.Exec(`DROP TRIGGER reject_facts`); err != nil {
		t.Fatal(err)
	}
	if err = s.PublishPending(ctx, op, pub, bytes.NewReader(nil)); err != nil {
		t.Fatal("replay after SQL failure failed", err)
	}
	got, revision, err := s.GetFacts(ctx, entry.ObjectID)
	if err != nil || revision != 1 || !reflect.DeepEqual(got, facts) {
		t.Fatal("facts not committed with object", err)
	}
	var n int
	if err = db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_pending_facts`).Scan(&n); err != nil || n != 0 {
		t.Fatal("pending facts not cleared", err)
	}
}

func TestPendingFactsRemovalFailsAuthentication(t *testing.T) {
	ctx := context.Background()
	db, s, _ := sqliteFixture(t)
	entry := Entry{ParentID: s.rootID, ObjectID: strings.Repeat("7", 64), Kind: "audio", Name: "hidden.mp3"}
	op, err := s.PrepareFileWithFacts(ctx, entry, fixturePlacement(t, entry.ObjectID), fixtureFacts(entry.ObjectID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`DELETE FROM sealed_tree_pending_facts WHERE operation_id=?`, op); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Check(ctx); !errors.Is(err, ErrInvalid) {
		t.Fatal("removed pending facts accepted", err)
	}
}
