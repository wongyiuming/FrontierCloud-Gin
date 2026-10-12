package business_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestPeerMigrationRecordingCleanupGrantQuotaAndTombstone(t *testing.T) {
	db, raw, peer, rel, h, l, obj := peerMigrationFixture(t, true)
	ctx := context.Background()
	id, user := hashPath(t.Name() + "record")[:32], hashPath(t.Name() + "user")[:32]
	v := store.Recording{ID: id, UserID: user, Filename: "voice.webm", ContentType: "audio/webm", Bytes: 7}
	if e := db.Recordings().ReserveOwnedRecording(ctx, rel, v, 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	sha := strings.Repeat("2", 64)
	if e := db.Recordings().CompleteOwnedRecording(ctx, rel, store.RecordingReceipt{ID: id, Bytes: 7, SHA256: sha}, 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { raw.Exec("DELETE FROM karaoke_recordings WHERE recording_id=?", id) })
	o := store.MigrationObject{ID: id, ObjectID: id, Resource: "recording", Kind: "recording", Parent: user, Path: rel + "/" + user + "/" + id + ".bin", TargetPath: h.TargetRelationship + "/" + user + "/" + id + ".bin", Bytes: 7, Version: strings.Repeat("1", 64), ETag: sha, Recording: &store.RecordingProof{ID: id, UserID: user, Filename: v.Filename, ContentType: v.ContentType, Bytes: 7, SHA256: sha, CreatedAt: time.Now().Unix()}}
	obj.Object = o
	obj.Proof = store.MigrationDiskProof{ID: id, Version: o.Version, Bytes: 7, SHA256: sha}
	if e := peer.RegisterPeerMigration(ctx, rel, h, l, "queued", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e := peer.RegisterPeerMigrationObject(ctx, rel, l, obj, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e := peer.StagePeerRecordingDeletion(ctx, rel, l, id); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("missing cleanup grant admitted", e)
	}
	if _, e := db.Recordings().StageOwnedRecordingDeletion(ctx, rel, user, id); !errors.Is(e, store.ErrNodeState) && !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("ordinary delete bypassed scope", e)
	}
	now := time.Now().Unix()
	g := store.MigrationCleanupGrant{TaskID: l.TaskID, MasterID: h.MasterID, SourceID: h.SourceID, TargetID: h.TargetID, PlanSHA: h.PlanSHA, UnitID: hashPath("recording:" + user), UnitVersion: hashPath("record-unit"), Object: o, SHA256: sha, CommittedAt: now - 3601, CleanupAfter: now - 1, TargetVerifiedAt: now}
	if e := peer.PreparePeerMigrationCleanup(ctx, rel, l, g, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e := peer.StagePeerRecordingDeletion(ctx, rel, l, id); e != nil {
		t.Fatal(e)
	}
	for range 2 {
		if e := peer.CompletePeerRecordingDeletion(ctx, rel, l.TaskID, id, 20*store.GiB, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
	}
	row, e := db.Recordings().Recording(ctx, id)
	if e != nil || row.State != "deleted" || row.Bytes != 7 || *row.SHA256 != sha {
		t.Fatal("recording tombstone", row, e)
	}
	var used int64
	var phase string
	if e = raw.QueryRow("SELECT used_bytes FROM cluster_storage_members WHERE member_id=?", h.SourceID).Scan(&used); e != nil || used != 7 {
		t.Fatal("recording refund touched unrelated media", used, e)
	}
	if e = raw.QueryRow("SELECT state FROM migration_storage_journal WHERE task_id=? AND logical_id=?", l.TaskID, id).Scan(&phase); e != nil || phase != "deleted" {
		t.Fatal(phase, e)
	}
}
