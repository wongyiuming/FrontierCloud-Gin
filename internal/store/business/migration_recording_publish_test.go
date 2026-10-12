package business_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"strings"
	"testing"
	"time"
)

func TestPeerMigrationRecordingPublicationRollbackReplayAndAccountBoundary(t *testing.T) {
	db, raw, repo, rel, h, l, v := peerMigrationFixture(t, false)
	ctx := context.Background()
	id, user := hashPath(t.Name() + "record")[:32], hashPath(t.Name() + "user")[:32]
	v.Object = store.MigrationObject{ID: id, ObjectID: id, Resource: "recording", Kind: "recording", Parent: user, Path: h.SourceRelationship + "/" + user + "/" + id + ".bin", TargetPath: h.TargetRelationship + "/" + user + "/" + id + ".bin", Bytes: 7, Version: strings.Repeat("1", 64), ETag: strings.Repeat("2", 64)}
	v.Object.Recording = &store.RecordingProof{ID: id, UserID: user, Filename: "voice.webm", ContentType: "audio/webm", Bytes: 7, SHA256: v.Object.ETag, CreatedAt: time.Now().Unix() - 1}
	v.Proof = store.MigrationDiskProof{ID: id, Version: v.Object.Version, Bytes: 7, SHA256: v.Object.ETag}
	t.Cleanup(func() {
		raw.Exec("DELETE FROM karaoke_recordings WHERE recording_id=?", id)
		raw.Exec("DELETE FROM karaoke_users WHERE user_id=?", user)
	})
	if e := repo.RegisterPeerMigration(ctx, rel, h, l, "queued", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e := repo.RegisterPeerMigrationObject(ctx, rel, l, v, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	receipt := store.RecordingReceipt{ID: id, Bytes: 7, SHA256: v.Proof.SHA256, Metadata: &store.RecordingMetadata{Title: "original footer", Lyrics: []store.RecordingLyric{{Time: 1, Text: "original lyric"}}}}
	publish := func() error {
		return repo.CompletePeerRecordingPublication(ctx, rel, l, id, receipt, 20*store.GiB, store.NodeAudit{})
	}
	if e := publish(); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("unverified publication", e)
	}
	if e := repo.VerifyPeerMigrationObject(ctx, rel, l, id, 7, receipt.SHA256); e != nil {
		t.Fatal(e)
	}
	trigger := "CREATE TRIGGER block_record_migration BEFORE UPDATE ON migration_storage_journal BEGIN SELECT RAISE(ABORT,'publication unavailable'); END"
	if db.Backend() == "mysql" {
		trigger = "CREATE TRIGGER block_record_migration BEFORE UPDATE ON migration_storage_journal FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='publication unavailable'"
	}
	if _, e := raw.Exec(trigger); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { raw.Exec("DROP TRIGGER IF EXISTS block_record_migration") })
	if e := publish(); e == nil {
		t.Fatal("injected fault ignored")
	}
	if found, e := db.Recordings().Recording(ctx, id); e != nil || found != nil {
		t.Fatal("failed transaction exposed recording", found, e)
	}
	var used, reserved int64
	raw.QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", h.TargetID).Scan(&used, &reserved)
	if used != 0 || reserved != 7 {
		t.Fatal(used, reserved)
	}
	if _, e := raw.Exec("DROP TRIGGER block_record_migration"); e != nil {
		t.Fatal(e)
	}
	for range 2 {
		if e := publish(); e != nil {
			t.Fatal(e)
		}
	}
	got, e := db.Recordings().Recording(ctx, id)
	if e != nil || got.ID != id || got.UserID != user || got.MemberID != h.TargetID || got.State != "ready" || got.Filename != "voice.webm" || got.Title != "original footer" || len(got.Lyrics) != 1 {
		t.Fatal(got, e)
	}
	raw.QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", h.TargetID).Scan(&used, &reserved)
	if used != 7 || reserved != 0 {
		t.Fatal("duplicate quota charge", used, reserved)
	}
	var users int
	if e = raw.QueryRow("SELECT COUNT(*) FROM karaoke_users WHERE user_id=?", user).Scan(&users); e != nil || users != 0 {
		t.Fatal("copied an account", users, e)
	}
	// A previously deleted account must never be revived by resource migration.
	now := time.Now().Unix()
	if _, e = raw.Exec("INSERT INTO karaoke_users("+"user_id,username,username_key,password_hash,status,quota_bytes,used_bytes,created_at,updated_at"+") VALUES (?,?,?,'!','deleted',0,0,?,?)", user, user, user, now, now); e != nil {
		t.Fatal(e)
	}
	if e = publish(); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("deleted account bypassed", e)
	}
}

func TestPeerMigrationRecordingEncryptedReverseKeepsOriginalDescriptor(t *testing.T) {
	db, raw, repo, rel, h, l, v := peerMigrationFixture(t, false)
	ctx := context.Background()
	id, user := hashPath(t.Name() + "record")[:32], hashPath(t.Name() + "user")[:32]
	meta, e := mediacrypto.NewMetadata(8)
	if e != nil {
		t.Fatal(e)
	}
	snapshot := store.RecordingMetadata{Title: "opaque snapshot", Lyrics: []store.RecordingLyric{}, EncryptedLyrics: &store.RecordingEncryptedLyrics{Encryption: meta, Ciphertext: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, int(meta.CiphertextSize)))}}
	h.Bytes = 8192
	proof := &store.RecordingProof{ID: id, UserID: user, Filename: "voice.webm", ContentType: "audio/webm", Bytes: h.Bytes, SHA256: strings.Repeat("2", 64), CreatedAt: time.Now().Unix() - 1, EncryptedLyricsEncryption: &meta, MetadataSHA256: store.RecordingMetadataSHA256(snapshot)}
	v.Object = store.MigrationObject{ID: id, ObjectID: id, Resource: "recording", Kind: "recording", Parent: user, Path: h.SourceRelationship + "/" + user + "/" + id + ".bin", TargetPath: h.TargetRelationship + "/" + user + "/" + id + ".bin", Bytes: h.Bytes, Version: strings.Repeat("1", 64), ETag: proof.SHA256, Recording: proof}
	v.Proof = store.MigrationDiskProof{ID: id, Version: v.Object.Version, Bytes: h.Bytes, SHA256: proof.SHA256}
	t.Cleanup(func() {
		raw.Exec("DELETE FROM karaoke_recordings WHERE recording_id=?", id)
		raw.Exec("DELETE FROM media_encryption WHERE object_kind='recording_lyric' AND object_id=?", id)
	})
	if _, e = raw.Exec("INSERT INTO karaoke_recordings(recording_id,user_id,storage_member_id,filename,content_type,size_bytes,sha256,state,title,lyrics,created_at,updated_at) VALUES (?,?,?,?,?,?,?,'deleted','','[]',?,?)", id, user, h.TargetID, proof.Filename, proof.ContentType, proof.Bytes, proof.SHA256, proof.CreatedAt, proof.CreatedAt); e != nil {
		t.Fatal(e)
	}
	if _, e = raw.Exec("INSERT INTO media_encryption(object_kind,object_id,file_id,descriptor_json,created_at) VALUES ('recording_lyric',?,?,NULL,?)", id, meta.FileID, proof.CreatedAt); e != nil {
		t.Fatal(e)
	}
	if e = repo.RegisterPeerMigration(ctx, rel, h, l, "queued", 20*store.GiB, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e = repo.RegisterPeerMigrationObject(ctx, rel, l, v, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if e = repo.VerifyPeerMigrationObject(ctx, rel, l, id, h.Bytes, proof.SHA256); e != nil {
		t.Fatal(e)
	}
	bad := snapshot
	bad.Title = "changed"
	if e = repo.CompletePeerRecordingPublication(ctx, rel, l, id, store.RecordingReceipt{ID: id, Bytes: h.Bytes, SHA256: proof.SHA256, Metadata: &bad}, 20*store.GiB, store.NodeAudit{}); !errors.Is(e, store.ErrMigrationState) {
		t.Fatal("changed encrypted snapshot accepted", e)
	}
	for range 2 {
		if e = repo.CompletePeerRecordingPublication(ctx, rel, l, id, store.RecordingReceipt{ID: id, Bytes: h.Bytes, SHA256: proof.SHA256, Metadata: &snapshot}, 20*store.GiB, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
	}
	row, e := db.Recordings().Recording(ctx, id)
	if e != nil || row.EncryptedLyrics == nil || row.EncryptedLyrics.Encryption != meta || row.State != "ready" {
		t.Fatal(row, e)
	}
	var descriptor string
	var count int
	if e = raw.QueryRow("SELECT descriptor_json FROM media_encryption WHERE object_kind='recording_lyric' AND object_id=?", id).Scan(&descriptor); e != nil {
		t.Fatal(e)
	}
	var actual mediacrypto.Metadata
	if e = json.Unmarshal([]byte(descriptor), &actual); e != nil || actual != meta {
		t.Fatal("descriptor changed", e)
	}
	raw.QueryRow("SELECT COUNT(*) FROM media_encryption WHERE file_id=?", meta.FileID).Scan(&count)
	if count != 1 {
		t.Fatal("file ID duplicated", count)
	}
}
