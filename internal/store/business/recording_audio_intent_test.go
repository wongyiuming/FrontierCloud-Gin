package business

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
	_ "modernc.org/sqlite"
)

func TestRecordingAudioIntentAuthenticatesPrivateStateAndRollback(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+t.TempDir()+"/recordings.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	statements, err := migrations.RecordingAudioStatements("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	statements = append(statements, `CREATE TABLE sealed_tree_capacity_ids(encryption_id CHAR(64) PRIMARY KEY)`, `CREATE TABLE sealed_tree_capacity_meta(singleton INTEGER PRIMARY KEY,verifier TEXT NOT NULL)`)
	for _, stmt := range statements {
		if _, err = db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	r := New(db, "sqlite")
	key := bytes.Repeat([]byte{9}, 32)
	if _, err = db.Exec(`INSERT INTO sealed_tree_capacity_meta VALUES(1,?)`, opaqueCapacityVerifier(key)); err != nil {
		t.Fatal(err)
	}
	meta, err := mediacrypto.NewMetadata(32)
	if err != nil {
		t.Fatal(err)
	}
	lyricMeta, err := mediacrypto.NewMetadata(5)
	if err != nil {
		t.Fatal(err)
	}
	// This test exercises structural ciphertext authentication; the browser's
	// AEAD encryption and end-to-end plaintext are verified elsewhere.
	snapshot := store.RecordingEncryptedLyrics{Encryption: lyricMeta, Ciphertext: "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	if !store.ValidRecordingEncryptedLyrics(snapshot) {
		t.Fatal("invalid synthetic lyric ciphertext")
	}
	lyrics, _ := json.Marshal(snapshot)
	lyricHash, titleHash := sha256.Sum256(lyrics), sha256.Sum256([]byte("私有录音"))
	v := recordingAudioIntent{
		UserID: strings.Repeat("1", 32), RecordingID: strings.Repeat("2", 32), MasterID: strings.Repeat("3", 32), MemberID: strings.Repeat("4", 32),
		OperationID: strings.Repeat("5", 64), BlobID: strings.Repeat("6", 64), Digest: strings.Repeat("7", 64), Bytes: meta.CiphertextSize,
		Binding:      "recording-audio:v1:" + strings.Repeat("1", 32) + ":" + strings.Repeat("8", 64) + ":" + strings.Repeat("2", 32),
		OwnerBinding: strings.Repeat("9", 64), ContentType: "audio/webm",
		Encryption: meta, TitleDigest: hex.EncodeToString(titleHash[:]), LyricsDigest: hex.EncodeToString(lyricHash[:]), State: "pending",
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.insertRecordingAudioIntentTx(ctx, tx, key, v, "私有录音", lyrics); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, found, err := r.readRecordingAudioIntentTx(ctx, db, key, v.RecordingID); err != nil || found {
		t.Fatal("rollback left a recording intent", err)
	}
	var tombstones int
	if err = db.QueryRow(`SELECT COUNT(*) FROM sealed_tree_capacity_ids`).Scan(&tombstones); err != nil || tombstones != 0 {
		t.Fatal("rollback left encryption-ID reservations", err)
	}
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.insertRecordingAudioIntentTx(ctx, tx, key, v, "私有录音", lyrics); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got, title, foundLyrics, found, err := r.readRecordingAudioIntentTx(ctx, db, key, v.RecordingID)
	if err != nil || !found || got != v || title != "私有录音" || !bytes.Equal(foundLyrics, lyrics) {
		t.Fatal("authenticated intent did not round-trip", err)
	}
	var sealed, sealedTitle []byte
	if err = db.QueryRow(`SELECT sealed,sealed_title FROM sealed_recording_audio`).Scan(&sealed, &sealedTitle); err != nil || bytes.Contains(sealed, []byte(v.RecordingID)) || bytes.Contains(sealedTitle, []byte("私有录音")) {
		t.Fatal("recording identity or title leaked in sealed records", err)
	}
	if _, _, _, _, err = r.readRecordingAudioIntentTx(ctx, db, bytes.Repeat([]byte{8}, 32), v.RecordingID); err == nil {
		t.Fatal("wrong key was accepted")
	}
	if _, err = db.Exec(`UPDATE sealed_recording_audio SET sealed_title=zeroblob(1085)`); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err = r.readRecordingAudioIntentTx(ctx, db, key, v.RecordingID); err == nil {
		t.Fatal("tampered title ciphertext was accepted")
	}
	if _, err = db.Exec(`UPDATE sealed_recording_audio SET sealed_title=?`, sealedTitle); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE sealed_recording_audio SET lyric_ciphertext=?`, []byte("tampered")); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err = r.readRecordingAudioIntentTx(ctx, db, key, v.RecordingID); err == nil {
		t.Fatal("tampered lyric ciphertext was accepted")
	}
}
