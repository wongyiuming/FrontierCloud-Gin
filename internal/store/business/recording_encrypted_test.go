package business_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestRecordingEncryptedSnapshotAtomicReceiptAndGlobalNonceTombstones(t *testing.T) {
	db := database(t)
	ctx := context.Background()
	raw := db.(interface{ Database() *sql.DB }).Database()
	n, err := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: strings.Repeat("a", 32), Role: "Standalone", PrivateKey: "fixture", CreatedAt: time.Now().Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: "https://snapshot.test", Allocation: 5 * store.GiB, PhysicalFree: 10 * store.GiB}, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	user := store.KaraokeUser{ID: "ac" + strings.Repeat("1", 30), Username: "snapshot-recordings", NameKey: "snapshot-recordings", PasswordHash: "fixture", Quota: 1024 * 1024}
	ids := []string{"ac" + strings.Repeat("2", 30), "ac" + strings.Repeat("3", 30), "ac" + strings.Repeat("4", 30)}
	mediaID := strings.Repeat("c", 64)
	audit := store.KaraokeAudit{IP: "192.0.2.204"}
	t.Cleanup(func() {
		raw.Exec("DELETE FROM karaoke_recordings WHERE user_id=?", user.ID)
		raw.Exec("DELETE FROM karaoke_users WHERE user_id=?", user.ID)
		for _, id := range ids {
			raw.Exec("DELETE FROM media_encryption WHERE object_kind='recording_lyric' AND object_id=?", id)
		}
		raw.Exec("DELETE FROM media_encryption WHERE object_kind='media' AND object_id=?", mediaID)
		raw.Exec("DELETE FROM karaoke_audit_log WHERE client_ip=?", audit.IP)
		raw.Exec("DELETE FROM karaoke_registration_daily WHERE client_ip=?", audit.IP)
		for _, table := range []string{"cluster_storage_members", "cluster_compute_members", "cluster_backup_members"} {
			raw.Exec("DELETE FROM "+table+" WHERE member_id=?", n.ID)
		}
		raw.Exec("UPDATE node_identity SET `role`=?,endpoint=? WHERE singleton=1", n.Role, n.Endpoint)
	})
	if err = db.Karaoke().RegisterUser(ctx, user, audit.IP, "20261010", audit); err != nil {
		t.Fatal(err)
	}
	plain := []byte(`[{"time":1,"text":"NEVER-PERSIST-PLAINTEXT"}]`)
	meta, err := mediacrypto.NewMetadata(int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(bytes.Repeat([]byte{0x4c}, 32))
	aead, _ := cipher.NewGCM(block)
	nonce, _ := meta.ChunkNonce(0)
	encrypted := &store.RecordingEncryptedLyrics{Encryption: meta, Ciphertext: base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plain, meta.ChunkAAD(0)))}
	v := store.Recording{ID: ids[0], UserID: user.ID, Filename: "snapshot.webm", ContentType: "audio/webm", Bytes: 1024, Title: "immutable", Lyrics: []store.RecordingLyric{}, EncryptedLyrics: encrypted}
	v, _, err = db.Recordings().ReserveRecording(ctx, v, 10*store.GiB, audit)
	if err != nil {
		t.Fatal(err)
	}
	var persisted string
	if err = raw.QueryRow("SELECT lyrics FROM karaoke_recordings WHERE recording_id=?", v.ID).Scan(&persisted); err != nil || strings.Contains(persisted, "NEVER-PERSIST-PLAINTEXT") {
		t.Fatal("snapshot plaintext persisted", err)
	}
	var descriptor string
	if err = raw.QueryRow("SELECT descriptor_json FROM media_encryption WHERE object_kind='recording_lyric' AND object_id=?", v.ID).Scan(&descriptor); err != nil || !strings.Contains(descriptor, meta.FileID) {
		t.Fatal("reservation did not register key", err)
	}
	metadata := store.RecordingMetadataFor(v)
	receipt := store.RecordingReceipt{ID: v.ID, Bytes: 1024, SHA256: strings.Repeat("b", 64), Metadata: &metadata}
	for _, bad := range []*store.RecordingMetadata{nil, {Title: "overwrite", Lyrics: []store.RecordingLyric{{Time: 0, Text: "NEVER-PERSIST-PLAINTEXT"}}}, {Title: "overwrite", Lyrics: []store.RecordingLyric{}, EncryptedLyrics: encrypted}} {
		changed := receipt
		changed.Metadata = bad
		if err = db.Recordings().FinalizeRecording(ctx, user.ID, v.ID, changed, audit); err == nil {
			t.Fatal("invalid receipt committed")
		}
	}
	row, err := db.Recordings().Recording(ctx, v.ID)
	if err != nil || row.State != "pending" || row.SHA256 != nil {
		t.Fatal("invalid receipt mutated state", row, err)
	}
	if err = db.Recordings().FinalizeRecording(ctx, user.ID, v.ID, receipt, audit); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Recordings().StageRecordingDeletion(ctx, user.ID, v.ID, false, audit); err != nil {
		t.Fatal(err)
	}
	if err = db.Recordings().CompleteRecordingDeletion(ctx, user.ID, v.ID, audit); err != nil {
		t.Fatal(err)
	}
	v.ID = ids[1]
	if _, _, err = db.Recordings().ReserveRecording(ctx, v, 10*store.GiB, audit); err == nil {
		t.Fatal("deleted snapshot nonce reused")
	}
	account, err := db.Karaoke().UserByID(ctx, user.ID)
	if err != nil || account.Used != 0 {
		t.Fatal("failed nonce reservation changed quota", account, err)
	}
	meta2, err := mediacrypto.NewMetadata(int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	encrypted2 := *encrypted
	encrypted2.Encryption = meta2
	v.EncryptedLyrics = &encrypted2
	if _, _, err = db.Recordings().ReserveRecording(ctx, v, 10*store.GiB, audit); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Recordings().StageRecordingDeletion(ctx, user.ID, v.ID, true, audit); err != nil {
		t.Fatal(err)
	}
	if err = db.Recordings().CompleteRecordingDeletion(ctx, user.ID, v.ID, audit); err != nil {
		t.Fatal(err)
	}
	v.ID = ids[2]
	if _, _, err = db.Recordings().ReserveRecording(ctx, v, 10*store.GiB, audit); err == nil {
		t.Fatal("cancelled snapshot nonce reused")
	}
	meta3, err := mediacrypto.NewMetadata(int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = raw.Exec("INSERT INTO media_encryption(object_kind,object_id,file_id,descriptor_json,created_at) VALUES ('media',?,?,NULL,?)", mediaID, meta3.FileID, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	encrypted2.Encryption = meta3
	if _, _, err = db.Recordings().ReserveRecording(ctx, v, 10*store.GiB, audit); err == nil {
		t.Fatal("media namespace file ID reused by snapshot")
	}
}
