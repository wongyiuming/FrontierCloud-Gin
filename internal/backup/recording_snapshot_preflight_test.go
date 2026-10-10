package backup

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func recordingSnapshotBackupRecords(t *testing.T) []map[string]any {
	t.Helper()
	records := preflightRecords()
	meta, err := mediacrypto.NewMetadata(44)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(bytes.Repeat([]byte{0x91}, 32))
	aead, _ := cipher.NewGCM(block)
	nonce, _ := meta.ChunkNonce(0)
	ciphertext := aead.Seal(nil, nonce, bytes.Repeat([]byte{'l'}, 44), meta.ChunkAAD(0))
	metadata := store.RecordingMetadata{Title: "private snapshot", Lyrics: []store.RecordingLyric{}, EncryptedLyrics: &store.RecordingEncryptedLyrics{Encryption: meta, Ciphertext: base64.StdEncoding.EncodeToString(ciphertext)}}
	lyrics, err := store.EncodeRecordingLyrics(metadata)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, _ := json.Marshal(meta)
	row := preflightRow(records, "karaoke_recordings")
	row["title"] = metadata.Title
	row["lyrics"] = string(lyrics)
	row["size_bytes"] = 1024
	user := preflightRow(records, "karaoke_users")
	user["quota_bytes"], user["used_bytes"] = 2048, 1024
	preflightRow(records, "cluster_storage_members")["used_bytes"] = 1124
	registry := map[string]any{"kind": "row", "table": "media_encryption", "value": map[string]any{"object_kind": "recording_lyric", "object_id": row["recording_id"], "file_id": meta.FileID, "descriptor_json": string(descriptor), "created_at": 1}}
	key := map[string]any{"kind": "row", "table": "media_crypto_keys", "value": map[string]any{"singleton": 1, "key_id": strings.Repeat("f", 64), "created_at": 1}}
	return append(records[:len(records)-1], registry, key, map[string]any{"kind": "end"})
}

func TestEncryptedRecordingColdBackupPreflightTypedIdentityAndOpaqueConsistency(t *testing.T) {
	records := recordingSnapshotBackupRecords(t)
	data := encodedPreflight(records)
	report, err := Preflight(context.Background(), bytes.NewReader(data), expectedPreflight(data), t.TempDir())
	if err != nil || !report.LogicalValid || report.RestoreReady {
		t.Fatal("valid opaque snapshot backup rejected or restoration overclaimed", report, err)
	}
	for _, test := range []struct {
		name   string
		mutate func([]map[string]any)
	}{
		{"wrong_namespace", func(r []map[string]any) { preflightRow(r, "media_encryption")["object_kind"] = "media" }},
		{"orphan_registry", func(r []map[string]any) { preflightRow(r, "media_encryption")["object_id"] = strings.Repeat("a", 32) }},
		{"missing_descriptor", func(r []map[string]any) { preflightRow(r, "media_encryption")["descriptor_json"] = nil }},
		{"replaced_plaintext", func(r []map[string]any) {
			preflightRow(r, "karaoke_recordings")["lyrics"] = `[{"time":0,"text":"PLAINTEXT"}]`
		}},
		{"different_descriptor", func(r []map[string]any) {
			v := preflightRow(r, "media_encryption")
			meta, _ := mediacrypto.NewMetadata(44)
			raw, _ := json.Marshal(meta)
			v["file_id"], v["descriptor_json"] = meta.FileID, string(raw)
		}},
		{"noncanonical_base64", func(r []map[string]any) {
			v := preflightRow(r, "karaoke_recordings")
			v["lyrics"] = strings.Replace(v["lyrics"].(string), `"ciphertext":"`, `"ciphertext":"\n`, 1)
		}},
		{"undercharged_snapshot", func(r []map[string]any) {
			v := preflightRow(r, "karaoke_recordings")
			v["size_bytes"] = 1
			preflightRow(r, "karaoke_users")["used_bytes"] = 1
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			records := recordingSnapshotBackupRecords(t)
			test.mutate(records)
			data := encodedPreflight(records)
			if _, err := Preflight(context.Background(), bytes.NewReader(data), expectedPreflight(data), t.TempDir()); err == nil {
				t.Fatal("inconsistent opaque snapshot admitted")
			}
		})
	}
}
