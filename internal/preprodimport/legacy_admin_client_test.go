package preprodimport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

func TestLegacyAdminEnvelopeUsesPinnedTLSAndExactMedia(t *testing.T) {
	m, err := mediacrypto.New(bytes.Repeat([]byte{7}, 32))
	if err != nil { t.Fatal(err) }
	meta, err := mediacrypto.NewMetadata(4097)
	if err != nil { t.Fatal(err) }
	mediaID := strings.Repeat("1", 64)
	name := "music/专辑/歌曲.mp3"
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.Header.Get("Cookie") != "admin=synthetic; csrf=synthetic" || r.Header.Get("X-CSRF-Token") != "synthetic" {
			w.WriteHeader(http.StatusUnauthorized); return
		}
		if r.URL.Path == "/api/v1/media/admin/crypto/session" {
			var body struct{ PublicKey string `json:"public_key"` }
			if json.NewDecoder(r.Body).Decode(&body) != nil { w.WriteHeader(400); return }
			grant, e := m.NewSession("admin:fixture", body.PublicKey)
			if e != nil { w.WriteHeader(401); return }
			_ = json.NewEncoder(w).Encode(grant); return
		}
		if r.URL.Path == "/api/v1/media/admin/crypto/key" {
			var body struct{ SessionID, FilePath, ResourceID, ObjectID string }
			var wire map[string]string
			if json.NewDecoder(r.Body).Decode(&wire) != nil { w.WriteHeader(400); return }
			body.SessionID, body.FilePath, body.ResourceID, body.ObjectID = wire["session_id"], wire["file_path"], wire["resource_id"], wire["object_id"]
			if body.FilePath != name || body.ResourceID != mediaID || body.ObjectID != mediaID { w.WriteHeader(404); return }
			envelope, e := m.Wrap("admin:fixture", body.SessionID, meta)
			if e != nil { w.WriteHeader(401); return }
			_ = json.NewEncoder(w).Encode(map[string]any{"encryption":meta, "key_envelope":envelope, "source_url":"/private/path"}); return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()
	spki := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	got, err := fetchLegacyAdminEnvelope(ctx, server.Client(), server.URL, "admin=synthetic; csrf=synthetic", "synthetic", hex.EncodeToString(spki[:]), name, mediaID, meta)
	if err != nil { t.Fatal(err) }
	key, err := got.receiver.open(got.grant, got.metadata, meta, got.envelope, time.Now())
	if err != nil { t.Fatal(err) }
	defer clear(key)
	want, err := m.FileKey(meta)
	if err != nil || !bytes.Equal(key, want) { t.Fatal("unwrapped wrong file key", err) }
	clear(want)
	before := requests.Load()
	if _, err = fetchLegacyAdminEnvelope(ctx, server.Client(), server.URL, "admin=synthetic", "synthetic", hex.EncodeToString(spki[:]), "lyrics/专辑/歌词.lrc", mediaID, meta); err == nil || requests.Load() != before { t.Fatal("lyric request not rejected before network") }
	before = requests.Load()
	if _, err = fetchLegacyAdminEnvelope(ctx, server.Client(), server.URL, "admin=synthetic; csrf=synthetic", "synthetic", strings.Repeat("0", 64), name, mediaID, meta); err == nil || requests.Load() != before { t.Fatal("wrong TLS pin sent admin credentials") }
	if _, err = fetchLegacyAdminEnvelope(ctx, server.Client(), server.URL, "admin=synthetic; csrf=synthetic", "synthetic", hex.EncodeToString(spki[:]), name, strings.Repeat("2", 64), meta); err == nil { t.Fatal("wrong media identity accepted") }
}
