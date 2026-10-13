package business_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
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

func TestPeerMigrationRecordingShadowCancellationTombstoneAndQuota(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "encrypted"}[encrypted], func(t *testing.T) {
			db, raw, peer, rel, h, l, v := peerMigrationFixture(t, false)
			ctx := context.Background()
			id, user := hashPath(t.Name() + "record")[:32], hashPath(t.Name() + "user")[:32]
			snapshot := store.RecordingMetadata{Title: "original footer", Lyrics: []store.RecordingLyric{{Time: 1, Text: "line"}}}
			h.Bytes = 8192
			proof := &store.RecordingProof{ID: id, UserID: user, Filename: "voice.webm", ContentType: "audio/webm", Bytes: h.Bytes, SHA256: strings.Repeat("2", 64), CreatedAt: time.Now().Unix() - 1}
			if encrypted {
				meta, e := mediacrypto.NewMetadata(8)
				if e != nil {
					t.Fatal(e)
				}
				snapshot.Lyrics = []store.RecordingLyric{}
				snapshot.EncryptedLyrics = &store.RecordingEncryptedLyrics{Encryption: meta, Ciphertext: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, int(meta.CiphertextSize)))}
				proof.EncryptedLyricsEncryption = &meta
				proof.MetadataSHA256 = store.RecordingMetadataSHA256(snapshot)
			}
			v.Object = store.MigrationObject{ID: id, ObjectID: id, Resource: "recording", Kind: "recording", Parent: user, Path: h.SourceRelationship + "/" + user + "/" + id + ".bin", TargetPath: h.TargetRelationship + "/" + user + "/" + id + ".bin", Bytes: h.Bytes, Version: strings.Repeat("1", 64), ETag: proof.SHA256, Recording: proof}
			v.Proof = store.MigrationDiskProof{ID: id, Version: v.Object.Version, Bytes: h.Bytes, SHA256: proof.SHA256}
			t.Cleanup(func() {
				raw.Exec("DELETE FROM karaoke_recordings WHERE recording_id=?", id)
				raw.Exec("DELETE FROM media_encryption WHERE object_kind='recording_lyric' AND object_id=?", id)
			})
			if e := peer.RegisterPeerMigration(ctx, rel, h, l, "queued", 20*store.GiB, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			if e := peer.RegisterPeerMigrationObject(ctx, rel, l, v, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			if e := peer.VerifyPeerMigrationObject(ctx, rel, l, id, h.Bytes, proof.SHA256); e != nil {
				t.Fatal(e)
			}
			if e := peer.CompletePeerRecordingPublication(ctx, rel, l, id, store.RecordingReceipt{ID: id, Bytes: h.Bytes, SHA256: proof.SHA256, Metadata: &snapshot}, 20*store.GiB, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			l.Epoch++
			if e := peer.RegisterPeerMigration(ctx, rel, h, l, "cancelling", 20*store.GiB, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			roster, e := store.MigrationUnitObjectsSHA([]store.MigrationPeerObject{v})
			if e != nil {
				t.Fatal(e)
			}
			g := store.MigrationShadowGrant{Unit: store.MigrationUnitFinishGrant{Header: h, Unit: store.MigrationUnit{ID: hashPath("recording:" + user), Resource: "recording", Parent: user, State: "cancelled", ObjectCount: 1, Bytes: h.Bytes}, UnitVersion: hashPath("shadow-record-unit"), ObjectsSHA: roster}, Object: v.Object, SourceProof: store.MigrationCleanupProof{MigrationDiskProof: v.Proof, VerifiedAt: time.Now().Unix()}}
			if _, e = peer.StagePeerRecordingDeletion(ctx, rel, l, id); !errors.Is(e, store.ErrMigrationState) {
				t.Fatal("shadow without durable grant", e)
			}
			wrong := g
			wrong.Unit.Unit.CommittedAt = 1
			if e = peer.PreparePeerMigrationShadowDeletion(ctx, rel, l, wrong, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
				t.Fatal("committed record shadow deletion", e)
			}
			if e = peer.PreparePeerMigrationShadowDeletion(ctx, rel, l, g, store.NodeAudit{}); e != nil {
				t.Fatal(e)
			}
			if _, e = db.Recordings().StageOwnedRecordingDeletion(ctx, rel, user, id); !errors.Is(e, store.ErrMigrationState) && !errors.Is(e, store.ErrNodeState) {
				t.Fatal("ordinary delete bypassed task", e)
			}
			if _, e = raw.Exec("UPDATE karaoke_recordings SET filename='changed.webm' WHERE recording_id=?", id); e != nil {
				t.Fatal(e)
			}
			if _, e = peer.StagePeerRecordingDeletion(ctx, rel, l, id); !errors.Is(e, store.ErrMigrationState) {
				t.Fatal("changed recording accepted", e)
			}
			if _, e = raw.Exec("UPDATE karaoke_recordings SET filename=? WHERE recording_id=?", proof.Filename, id); e != nil {
				t.Fatal(e)
			}
			if _, e = peer.StagePeerRecordingDeletion(ctx, rel, l, id); e != nil {
				t.Fatal(e)
			}
			trigger := "CREATE TRIGGER block_shadow_record_refund BEFORE INSERT ON node_audit WHEN NEW.action='recording-deleted' BEGIN SELECT RAISE(ABORT,'record audit unavailable'); END"
			if db.Backend() == "mysql" {
				trigger = "CREATE TRIGGER block_shadow_record_refund BEFORE INSERT ON node_audit FOR EACH ROW BEGIN IF NEW.action='recording-deleted' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='record audit unavailable'; END IF; END"
			}
			if _, e = raw.Exec(trigger); e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { raw.Exec("DROP TRIGGER IF EXISTS block_shadow_record_refund") })
			if e = peer.CompletePeerRecordingDeletion(ctx, rel, l.TaskID, id, 20*store.GiB, store.NodeAudit{}); e == nil {
				t.Fatal("audit failure ignored")
			}
			var used, reserved int64
			if e = raw.QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", h.TargetID).Scan(&used, &reserved); e != nil || used != h.Bytes || reserved != 0 {
				t.Fatal("refund escaped rollback", used, reserved, e)
			}
			if _, e = raw.Exec("DROP TRIGGER block_shadow_record_refund"); e != nil {
				t.Fatal(e)
			}
			if _, e = raw.Exec("UPDATE migration_runners SET expires_at=0 WHERE task_id=?", h.TaskID); e != nil {
				t.Fatal(e)
			}
			for range 2 {
				if e = peer.CompletePeerRecordingDeletion(ctx, rel, l.TaskID, id, 20*store.GiB, store.NodeAudit{}); e != nil {
					t.Fatal(e)
				}
			}
			row, e := db.Recordings().Recording(ctx, id)
			if e != nil || row.State != "deleted" || row.MemberID != h.TargetID || row.Bytes != h.Bytes || *row.SHA256 != proof.SHA256 {
				t.Fatal("record tombstone binding", row, e)
			}
			if e = raw.QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", h.TargetID).Scan(&used, &reserved); e != nil || used != 0 || reserved != 0 {
				t.Fatal("duplicate/retained refund", used, reserved, e)
			}
			var users int
			if e = raw.QueryRow("SELECT COUNT(*) FROM karaoke_users WHERE user_id=?", user).Scan(&users); e != nil || users != 0 {
				t.Fatal("user copied to Storage", users, e)
			}
			if encrypted {
				var retired int
				if e = raw.QueryRow("SELECT COUNT(*) FROM media_encryption WHERE object_kind='recording_lyric' AND object_id=? AND file_id=? AND descriptor_json IS NULL", id, proof.EncryptedLyricsEncryption.FileID).Scan(&retired); e != nil || retired != 1 {
					t.Fatal("encrypted descriptor tombstone lost", retired, e)
				}
			}
		})
	}
}
