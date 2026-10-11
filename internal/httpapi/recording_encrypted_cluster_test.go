package httpapi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recording"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func recordingCipherSnapshot(t *testing.T) (store.RecordingMetadata, []byte, []byte) {
	t.Helper()
	plain := []byte(`[{"time":1.25,"text":"PRIVATE-LYRIC-SNAPSHOT 雪花❄"}]`)
	meta, err := mediacrypto.NewMetadata(int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x73}, 32)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	nonce, _ := meta.ChunkNonce(0)
	ciphertext := aead.Seal(nil, nonce, plain, meta.ChunkAAD(0))
	return store.RecordingMetadata{Title: "private snapshot", Lyrics: []store.RecordingLyric{}, EncryptedLyrics: &store.RecordingEncryptedLyrics{Encryption: meta, Ciphertext: base64.StdEncoding.EncodeToString(ciphertext)}}, plain, key
}

func recordingOpaqueFooter(t *testing.T, metadata store.RecordingMetadata) []byte {
	t.Helper()
	value := map[string]any{"version": 1, "title": metadata.Title, "lyrics": metadata.Lyrics, "encrypted_lyrics": metadata.EncryptedLyrics}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	result := append([]byte("opaque-recording-audio"), raw...)
	result = binary.BigEndian.AppendUint64(result, uint64(len(raw)))
	return append(result, []byte(recording.TrailerMagic)...)
}

// Actual signed node capabilities and the Primary/Direct/Relay recording
// handlers verify opaque browser-equivalent AES-GCM snapshots end to end.
func TestEncryptedRecordingClusterOpaqueFooterHashLifecycle(t *testing.T) {
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	master := nativeRecordingFixture(t, "https://encrypted-record-master.test", "Master", transport)
	direct := nativeRecordingFixture(t, "https://encrypted-record-direct.test", "Follower", transport)
	relay := nativeRecordingFixture(t, "https://encrypted-record-relay.test", "Follower", transport)
	relationships := map[string]string{}
	for index, follower := range []*recordingNode{&direct, &relay} {
		pack, err := follower.control.CreatePair(ctx, store.NodeAudit{})
		if err != nil {
			t.Fatal(err)
		}
		id, err := master.control.ImportPair(ctx, pack, store.NodeAudit{})
		if err != nil {
			t.Fatal(err)
		}
		relationships[follower.id] = id
		cfg := store.ResourceConfiguration{}
		cfg.Storage.Enabled = true
		cfg.Storage.Allocation = 5 * store.GiB
		if err = master.db.Pool().ConfigureMember(ctx, follower.id, cfg, store.NodeAudit{}); err != nil {
			t.Fatal(err)
		}
		mode := "Direct"
		if index == 1 {
			mode = "Relay"
		}
		if err = master.db.Nodes().SetRelationshipMode(ctx, id, mode, false, store.NodeAudit{}); err != nil {
			t.Fatal(err)
		}
		rel, err := master.db.Nodes().Relationship(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if err = master.control.Tick(ctx, rel); err != nil {
			t.Fatal(err)
		}
	}
	user := store.KaraokeUser{ID: strings.Repeat("f", 32), Username: "opaque-recordings", NameKey: "opaque-recordings", PasswordHash: "fixture", Quota: 1024 * 1024}
	if err := master.db.Karaoke().RegisterUser(ctx, user, "192.0.2.203", "20261010", store.KaraokeAudit{}); err != nil {
		t.Fatal(err)
	}
	manager := recording.NewManager(master.db.Recordings(), master.db.Karaoke(), master.db.Nodes(), master.db.Pool(), master.control, master.volume)
	for _, site := range []struct {
		name  string
		owner *recordingNode
	}{{"primary", &master}, {"direct", &direct}, {"relay", &relay}} {
		t.Run(site.name, func(t *testing.T) {
			if _, err := master.db.Database().Exec("UPDATE cluster_storage_members SET writable=CASE WHEN member_id=? THEN 1 ELSE 0 END", site.owner.id); err != nil {
				t.Fatal(err)
			}
			metadata, plain, key := recordingCipherSnapshot(t)
			data := recordingOpaqueFooter(t, metadata)
			ticket, err := manager.Ticket(ctx, user, int64(len(data)), "audio/webm", metadata, store.KaraokeAudit{})
			if err != nil {
				t.Fatal(err)
			}
			if ticket.Capability != nil && len(*ticket.Capability) > 4096 {
				t.Fatal("snapshot ciphertext entered capability headers")
			}
			upload := func(body []byte) error {
				if site.name != "direct" {
					_, err := manager.Upload(ctx, user.ID, ticket.ID, bytes.NewReader(body), store.KaraokeAudit{})
					return err
				}
				r := httptest.NewRequest("PUT", ticket.URL, bytes.NewReader(body))
				r.Header.Set("X-Recording-Capability", *ticket.Capability)
				r.Header.Set("Origin", "https://encrypted-record-master.test")
				w := httptest.NewRecorder()
				direct.router.ServeHTTP(w, r)
				if w.Code != 200 {
					return &recordingHTTPFailure{w.Code, w.Body.String()}
				}
				return nil
			}
			// Alter only a valid base64 ciphertext character, preserving body size.
			tampered := append([]byte{}, data...)
			at := bytes.Index(tampered, []byte(metadata.EncryptedLyrics.Ciphertext))
			if at < 0 {
				t.Fatal("ciphertext missing")
			}
			if tampered[at] == 'A' {
				tampered[at] = 'B'
			} else {
				tampered[at] = 'A'
			}
			if err = upload(tampered); err == nil {
				t.Fatal("tampered footer published")
			}
			if err = upload(data); err != nil {
				t.Fatal(err)
			}
			if err = manager.Finalize(ctx, user.ID, ticket.ID, store.KaraokeAudit{}); err != nil {
				t.Fatal(err)
			}
			row, err := master.db.Recordings().Recording(ctx, ticket.ID)
			if err != nil || row.EncryptedLyrics == nil || len(row.Lyrics) != 0 {
				t.Fatal(row, err)
			}
			actualRelationship := site.owner.id
			if site.name != "primary" {
				actualRelationship = relationships[site.owner.id]
			}
			path, _ := recording.Path(actualRelationship, user.ID, ticket.ID)
			stored, err := os.ReadFile(filepath.Join(site.owner.dir, "recordings", filepath.FromSlash(path)))
			if err != nil || !bytes.Equal(stored, data) || bytes.Contains(stored, []byte("PRIVATE-LYRIC-SNAPSHOT")) {
				t.Fatal("stored snapshot leaked or changed", err)
			}
			var persisted string
			if err = master.db.Database().QueryRow("SELECT lyrics FROM karaoke_recordings WHERE recording_id=?", ticket.ID).Scan(&persisted); err != nil || strings.Contains(persisted, "PRIVATE-LYRIC-SNAPSHOT") {
				t.Fatal("SQL snapshot leaked", err)
			}
			meta := recording.Metadata(bytes.NewReader(stored), int64(len(stored)))
			if !store.RecordingReceiptMetadataMatches(*row, meta) {
				t.Fatal("opaque footer mismatch")
			}
			block, _ := aes.NewCipher(key)
			aead, _ := cipher.NewGCM(block)
			nonce, _ := meta.EncryptedLyrics.Encryption.ChunkNonce(0)
			ciphertext, _ := base64.StdEncoding.Strict().DecodeString(meta.EncryptedLyrics.Ciphertext)
			decoded, err := aead.Open(nil, nonce, ciphertext, meta.EncryptedLyrics.Encryption.ChunkAAD(0))
			if err != nil || !bytes.Equal(decoded, plain) {
				t.Fatal("snapshot did not decrypt", err)
			}
			sha := sha256.Sum256(stored)
			receipt := store.RecordingReceipt{ID: ticket.ID, Bytes: int64(len(stored)), SHA256: hex.EncodeToString(sha[:]), Metadata: &store.RecordingMetadata{Title: row.Title, Lyrics: []store.RecordingLyric{{Time: 0, Text: "FORGED PLAINTEXT"}}}}
			if err = master.db.Recordings().FinalizeRecording(ctx, user.ID, ticket.ID, receipt, store.KaraokeAudit{}); err == nil {
				t.Fatal("ready receipt replaced snapshot with plaintext")
			}
			if err = manager.Delete(ctx, user.ID, ticket.ID, false, store.KaraokeAudit{}); err != nil {
				t.Fatal(err)
			}
			var descriptor any
			if err = master.db.Database().QueryRow("SELECT descriptor_json FROM media_encryption WHERE object_kind='recording_lyric' AND object_id=?", ticket.ID).Scan(&descriptor); err != nil || descriptor != nil {
				t.Fatal("missing retired nonce tombstone", descriptor, err)
			}
			if _, err = manager.Ticket(ctx, user, int64(len(data)), "audio/webm", metadata, store.KaraokeAudit{}); err == nil {
				t.Fatal("retired file ID reused")
			}
			fresh, _, _ := recordingCipherSnapshot(t)
			unused, err := manager.Ticket(ctx, user, int64(len(data)), "audio/webm", fresh, store.KaraokeAudit{})
			if err != nil {
				t.Fatal(err)
			}
			if err = manager.Delete(ctx, user.ID, unused.ID, true, store.KaraokeAudit{}); err != nil {
				t.Fatal(err)
			}
			if _, err = manager.Ticket(ctx, user, int64(len(data)), "audio/webm", fresh, store.KaraokeAudit{}); err == nil {
				t.Fatal("cancelled snapshot file ID reused")
			}
		})
	}
}

type recordingHTTPFailure struct {
	status int
	detail string
}

func (e *recordingHTTPFailure) Error() string { return e.detail }
