package recording

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func encryptedMetadataFixture(t *testing.T, size int64) store.RecordingMetadata {
	t.Helper()
	meta, err := mediacrypto.NewMetadata(size)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(bytes.Repeat([]byte{0x51}, 32))
	aead, _ := cipher.NewGCM(block)
	plain := bytes.Repeat([]byte{'s'}, int(size))
	var encrypted []byte
	for offset, index := 0, uint32(0); offset < len(plain); index++ {
		end := min(len(plain), offset+int(meta.ChunkSize))
		nonce, _ := meta.ChunkNonce(index)
		encrypted = append(encrypted, aead.Seal(nil, nonce, plain[offset:end], meta.ChunkAAD(index))...)
		offset = end
	}
	return store.RecordingMetadata{Title: "immutable opaque snapshot", Lyrics: []store.RecordingLyric{}, EncryptedLyrics: &store.RecordingEncryptedLyrics{Encryption: meta, Ciphertext: base64.StdEncoding.EncodeToString(encrypted)}}
}

func encryptedFooter(t *testing.T, v store.RecordingMetadata) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"version": 1, "title": v.Title, "lyrics": v.Lyrics, "encrypted_lyrics": v.EncryptedLyrics})
	if err != nil {
		t.Fatal(err)
	}
	return trailer(string(raw))
}

func TestEncryptedSnapshotFooterStrictSizeAndNoPlaintext(t *testing.T) {
	metadata := encryptedMetadataFixture(t, store.MaxEncryptedRecordingLyricPlaintext)
	if !store.ValidRecordingMetadata(metadata) {
		t.Fatal("maximum snapshot exceeds existing metadata budget")
	}
	data := encryptedFooter(t, metadata)
	decoded := Metadata(bytes.NewReader(data), int64(len(data)))
	if decoded == nil || decoded.EncryptedLyrics == nil || decoded.EncryptedLyrics.Ciphertext != metadata.EncryptedLyrics.Ciphertext || len(decoded.Lyrics) != 0 {
		t.Fatal("opaque snapshot footer not preserved")
	}
	raw, _ := json.Marshal(map[string]any{"version": 1, "title": metadata.Title, "lyrics": metadata.Lyrics, "encrypted_lyrics": metadata.EncryptedLyrics})
	for _, bad := range []string{
		strings.Replace(string(raw), `"lyrics":[]`, `"lyrics":[{"time":0,"text":"PRIVATE PLAINTEXT"}]`, 1),
		strings.Replace(string(raw), `"version":1`, `"version":1,"preparation_token":"must-not-persist"`, 1),
		strings.Replace(string(raw), `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(string(raw), metadata.EncryptedLyrics.Ciphertext, metadata.EncryptedLyrics.Ciphertext+`\n`, 1),
	} {
		blob := trailer(bad)
		if Metadata(bytes.NewReader(blob), int64(len(blob))) != nil {
			t.Fatal("ambiguous, plaintext or noncanonical snapshot footer admitted")
		}
	}
	oversize := encryptedMetadataFixture(t, store.MaxEncryptedRecordingLyricPlaintext+1)
	if store.ValidRecordingMetadata(oversize) {
		t.Fatal("snapshot plaintext cap relaxed")
	}
}

func TestEncryptedRecordingStageRejectsPlaintextFooterBeforePublicationAndRecovers(t *testing.T) {
	s, db, user, relationship := storageFixture(t)
	ctx := context.Background()
	metadata := encryptedMetadataFixture(t, 350)
	data := encryptedFooter(t, metadata)
	id := strings.Repeat("e", 32)
	v, _, err := db.Recordings().ReserveRecording(ctx, store.Recording{ID: id, UserID: user.ID, Filename: "opaque.webm", ContentType: "audio/webm", Bytes: int64(len(data)), Title: metadata.Title, Lyrics: metadata.Lyrics, EncryptedLyrics: metadata.EncryptedLyrics}, 10*store.GiB, store.KaraokeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := s.Lock(id)
	if err != nil {
		t.Fatal(err)
	}
	bad := trailer(`{"version":1,"title":"plaintext overwrite","lyrics":[{"time":0,"text":"PRIVATE PLAINTEXT"}]}`)
	bad = append(bytes.Repeat([]byte{'x'}, len(data)-len(bad)), bad...)
	if _, err = s.Upload(ctx, relationship, v, bytes.NewReader(bad), store.NodeAudit{}); !errors.Is(err, store.ErrRecordingState) {
		t.Fatal("plaintext footer did not fail before publication", err)
	}
	name, _ := Path(relationship, user.ID, id)
	if _, err = s.root.Stat(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid snapshot became published", err)
	}
	if _, err = s.root.Stat(".recording-" + id + ".part"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid private stage retained", err)
	}
	receipt, err := s.Upload(ctx, relationship, v, bytes.NewReader(data), store.NodeAudit{})
	unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if err = db.Recordings().FinalizeRecording(ctx, user.ID, id, receipt, store.KaraokeAudit{}); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Recordings().StageRecordingDeletion(ctx, user.ID, id, false, store.KaraokeAudit{}); err != nil {
		t.Fatal(err)
	}
	unlock, err = s.Lock(id)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Delete(ctx, relationship, user.ID, id, store.KaraokeAudit{}, store.NodeAudit{})
	unlock()
	if err != nil {
		t.Fatal(err)
	}
	var raw any
	if err = db.Database().QueryRow("SELECT descriptor_json FROM media_encryption WHERE object_kind='recording_lyric' AND object_id=?", id).Scan(&raw); err != nil || raw != nil {
		t.Fatal("physical cleanup removed nonce tombstone", raw, err)
	}
}
