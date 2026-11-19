//go:build linux

package sealedtree

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

func hideIntentFixture(t *testing.T) (*SQLStore, Entry, Placement, RevocationIntent) {
	t.Helper()
	s, entry, placement := revocationFixture(t)
	ctx := context.Background()
	intent, err := s.BeginOpaqueRevocation(ctx, entry.ObjectID, strings.Repeat("1", 32), strings.Repeat("2", 32), "hide", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	return s, entry, placement, intent
}

func ackHideFixture(t *testing.T, s *SQLStore, entry Entry, intent RevocationIntent) {
	t.Helper()
	receipt := revocationReceipt(intent)
	payload, err := receipt.Payload()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := protocol.Sign(protocol.Encode(bytes.Repeat([]byte{7}, 32)), payload)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RecordOpaqueRevocationAck(context.Background(), entry.ObjectID, receipt, sig); err != nil {
		t.Fatal(err)
	}
}

func TestOpaqueHideRequiresOwnerAndRecoversAtomicCommit(t *testing.T) {
	ctx := context.Background()
	s, entry, placement, intent := hideIntentFixture(t)
	if err := s.FinishOpaqueHide(ctx, entry.ObjectID, intent.OperationID, "2026-01-01"); !errors.Is(err, ErrConflict) {
		t.Fatal("hide without owner ACK", err)
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status, at, e := s.RecoverOpaqueHideWithLease(ctx, lease, entry.ObjectID, intent.OperationID); e != nil || status != "pending" || at != "" {
		t.Fatal("pending recovery", e)
	}
	lease.Release()
	ackHideFixture(t, s, entry, intent)
	if _, err = s.db.Exec(`UPDATE node_relationships SET credential='changed' WHERE relationship_id=?`, intent.RelationshipID); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishOpaqueHide(ctx, entry.ObjectID, intent.OperationID, "2026-01-01"); !errors.Is(err, ErrConflict) {
		t.Fatal("replacement owner accepted", err)
	}
	if _, err = s.db.Exec(`UPDATE node_relationships SET credential='synthetic-credential' WHERE relationship_id=?`, intent.RelationshipID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`CREATE TRIGGER fail_hide BEFORE DELETE ON sealed_tree_revocations BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishOpaqueHide(ctx, entry.ObjectID, intent.OperationID, "2026-01-01"); err == nil {
		t.Fatal("failed transaction committed")
	}
	if _, err = s.db.Exec(`DROP TRIGGER fail_hide`); err != nil {
		t.Fatal(err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status, at, e := s.RecoverOpaqueHideWithLease(ctx, lease, entry.ObjectID, intent.OperationID); e != nil || status != "pending" || at != "" {
		t.Fatal("failed hide not pending", e)
	}
	lease.Release()
	group := s.listingGroup(entry.ParentID, false)
	key := s.listingKey(group, listingSentinel)
	var beforeRevision int64
	if err = s.db.QueryRow(`SELECT group_revision FROM sealed_tree_listing WHERE index_key=?`, key).Scan(&beforeRevision); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishOpaqueHide(ctx, entry.ObjectID, intent.OperationID, "2026-01-01"); err != nil {
		t.Fatal(err)
	}
	var afterRevision int64
	if err = s.db.QueryRow(`SELECT group_revision FROM sealed_tree_listing WHERE index_key=?`, key).Scan(&afterRevision); err != nil || afterRevision != beforeRevision+1 {
		t.Fatal("completed hide did not invalidate all-items scope", err)
	}
	if err = s.FinishOpaqueHide(ctx, entry.ObjectID, intent.OperationID, "2026-01-01"); err != nil {
		t.Fatal("committed retry", err)
	}
	if err = s.FinishOpaqueHide(ctx, entry.ObjectID, intent.OperationID, "2026-01-02"); !errors.Is(err, ErrConflict) {
		t.Fatal("changed retry accepted", err)
	}
	facts, rev, err := s.GetFacts(ctx, entry.ObjectID)
	if err != nil || facts.HiddenProof == nil || facts.Revocation != nil || facts.Visibility.Hidden != 1 {
		t.Fatal("hidden proof missing", err)
	}
	if _, err = s.SetFacts(ctx, Facts{ObjectID: entry.ObjectID}, rev); !errors.Is(err, ErrConflict) {
		t.Fatal("generic unhide removed proof", err)
	}
	lease, err = s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if status, at, e := s.RecoverOpaqueHideWithLease(ctx, lease, entry.ObjectID, intent.OperationID); e != nil || status != "hidden" || at != "2026-01-01" {
		t.Fatal("committed recovery", e)
	}
	if _, e := s.ReadVisibleObjectByAliasWithLease(ctx, lease, placement.ReadAlias); !errors.Is(e, ErrHidden) {
		t.Fatal("old alias still visible", e)
	}
	entries, next, e := s.ListVisibleWithLease(ctx, lease, s.rootID, "", 5)
	if e != nil || len(entries) != 0 || next != "" {
		t.Fatal("hidden object listed", e)
	}
}

func TestOpaqueHidePreservesLongFacts(t *testing.T) {
	ctx := context.Background()
	s, entry, _ := revocationFixture(t)
	facts := fixtureFacts(entry.ObjectID)
	facts.Visibility.Hidden = 0
	facts.Playback.LegacyMediaPath = strings.Repeat("p", 900)
	facts.Lyric.LegacyMediaPath = strings.Repeat("q", 900)
	facts.Lyric.LegacyLyricPath = strings.Repeat("r", 900)
	stamp := strings.Repeat("t", 100)
	facts.Object.CreatedAt = stamp
	facts.Object.UpdatedAt = stamp
	facts.Visibility.UpdatedAt = stamp
	facts.Playback.CreatedAt = stamp
	facts.Playback.UpdatedAt = stamp
	facts.Lyric.CreatedAt = stamp
	facts.Lyric.UpdatedAt = stamp
	if _, err := s.SetFacts(ctx, facts, 1); err != nil {
		t.Fatal("fixture facts cannot be preserved", err)
	}
	intent, err := s.BeginOpaqueRevocation(ctx, entry.ObjectID, strings.Repeat("1", 32), strings.Repeat("2", 32), "hide", 2, 1)
	if err != nil {
		t.Fatal("long facts could not start hide", err)
	}
	ackHideFixture(t, s, entry, intent)
	if err = s.FinishOpaqueHide(ctx, entry.ObjectID, intent.OperationID, "2026-01-01"); err != nil {
		t.Fatal("long facts hide", err)
	}
	got, _, err := s.GetFacts(ctx, entry.ObjectID)
	if err != nil || !reflect.DeepEqual(got.Object, facts.Object) || !reflect.DeepEqual(got.Playback, facts.Playback) || !reflect.DeepEqual(got.Lyric, facts.Lyric) {
		t.Fatal("long facts changed", err)
	}
}

func TestOpaqueHideCrashBeforeCommitKeepsPending(t *testing.T) {
	const childEnv = "FC_HIDE_CRASH_CHILD"
	if os.Getenv(childEnv) == "1" {
		ctx := context.Background()
		db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(os.Getenv("FC_HIDE_DB"))+"?_pragma=busy_timeout(10000)")
		if err != nil {
			os.Exit(10)
		}
		tree, err := New(bytes.Repeat([]byte{0x42}, 32), bytes.Repeat([]byte{0x91}, 32))
		if err != nil {
			os.Exit(11)
		}
		s, err := OpenSQLite(ctx, db, tree, strings.Repeat("a", 64))
		if err != nil {
			os.Exit(12)
		}
		root, err := os.OpenRoot(os.Getenv("FC_HIDE_DIR"))
		if err != nil {
			os.Exit(13)
		}
		if _, err = OpenFence(ctx, s, root, os.Getenv("FC_HIDE_DIR")); err != nil {
			os.Exit(14)
		}
		err = s.finishOpaqueHide(ctx, os.Getenv("FC_HIDE_OBJECT"), os.Getenv("FC_HIDE_OPERATION"), "2026-01-01", func() { os.Exit(0) })
		if err != nil {
			os.Exit(15)
		}
		os.Exit(16)
	}
	ctx := context.Background()
	s, entry, _, intent := hideIntentFixture(t)
	ackHideFixture(t, s, entry, intent)
	var seq int
	var name, dbPath string
	if err := s.db.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &dbPath); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestOpaqueHideCrashBeforeCommitKeepsPending$")
	child.Env = append(os.Environ(), childEnv+"=1", "FC_HIDE_DB="+dbPath, "FC_HIDE_DIR="+s.fence.directory, "FC_HIDE_OBJECT="+entry.ObjectID, "FC_HIDE_OPERATION="+intent.OperationID)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("child: %v: %s", err, output)
	}
	lease, err := s.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state, at, e := s.RecoverOpaqueHideWithLease(ctx, lease, entry.ObjectID, intent.OperationID); e != nil || state != "pending" || at != "" {
		t.Fatal("crashed transaction lost pending", e)
	}
	lease.Release()
	if err = s.FinishOpaqueHide(ctx, entry.ObjectID, intent.OperationID, "2026-01-01"); err != nil {
		t.Fatal("retry after crash", err)
	}
}
