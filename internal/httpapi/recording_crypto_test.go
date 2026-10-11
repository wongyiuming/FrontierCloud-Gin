package httpapi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/karaoke"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recording"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"golang.org/x/crypto/hkdf"
)

// Account authorization and business persistence are real in the always-on
// test; the separately gated variant exercises the same path with real Redis.
type recordingCryptoCache struct {
	karaoke.Cache
	sessions map[string]map[string]string
}

func (c *recordingCryptoCache) SaveSession(_ context.Context, key, user, csrf, fp string) error {
	c.sessions[key] = map[string]string{"user_id": user, "csrf": csrf, "password_fp": fp, "generation": "0"}
	return nil
}
func (c *recordingCryptoCache) Session(_ context.Context, key string) (map[string]string, error) {
	return c.sessions[key], nil
}
func (c *recordingCryptoCache) UseSession(_ context.Context, key, user, csrf, fp string) (bool, error) {
	v := c.sessions[key]
	return v != nil && v["user_id"] == user && v["csrf"] == csrf && v["password_fp"] == fp, nil
}
func (c *recordingCryptoCache) Delete(_ context.Context, key string) error {
	delete(c.sessions, key)
	return nil
}

func TestRecordingEncryptedLyricsHTTPAuthorizationIndependentHistoryAndOpaquePersistence(t *testing.T) {
	testRecordingEncryptedLyricsHTTP(t, &recordingCryptoCache{sessions: map[string]map[string]string{}})
}

func TestRecordingEncryptedLyricsHTTPRealRedis(t *testing.T) {
	raw := os.Getenv("FRONTIERCLOUD_TEST_REDIS_URL")
	if raw == "" {
		t.Skip("disposable Redis not configured")
	}
	opts, err := redis.ParseURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(opts)
	defer client.Close()
	testRecordingEncryptedLyricsHTTP(t, karaoke.NewRedisCache(client))
}

func testRecordingEncryptedLyricsHTTP(t *testing.T, cache karaoke.Cache) {
	t.Helper()
	ctx := context.Background()
	const origin = "https://record-crypto.test"
	const base = "/api/v1/karaoke/account/recordings"
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	master := nativeRecordingFixture(t, origin, "Master", transport)
	resolver, _ := network.New(nil)
	accounts := RegisterKaraokeAccounts(master.router, karaoke.New(master.db.Karaoke(), master.db.Nodes(), cache), master.public, nil, resolver)
	manager := recording.NewManager(master.db.Recordings(), master.db.Karaoke(), master.db.Nodes(), master.db.Pool(), master.control, master.volume)
	RegisterKaraokeRecordings(master.router, accounts, manager, master.volume)
	users := []store.KaraokeUser{{ID: strings.Repeat("d", 32), Username: "encrypted-record-owner", NameKey: "encrypted-record-owner", PasswordHash: "fixture", Quota: 4 * store.GiB}, {ID: strings.Repeat("e", 32), Username: "encrypted-record-other", NameKey: "encrypted-record-other", PasswordHash: "fixture", Quota: 4 * store.GiB}}
	tokens, csrf := []string{strings.Repeat("a", 43), strings.Repeat("b", 43)}, strings.Repeat("f", 32)
	for i, u := range users {
		if err := master.db.Karaoke().RegisterUser(ctx, u, "192.0.2.182", "20261010", store.KaraokeAudit{}); err != nil {
			t.Fatal(err)
		}
		key := "karaoke:session:" + karaokeSessionHash(tokens[i])
		if err := cache.SaveSession(ctx, key, u.ID, csrf, karaokeSessionHash(u.PasswordHash)); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cache.Delete(ctx, key) })
	}
	var browserCookie *http.Cookie
	perform := func(method, target string, payload []byte, account int, withCSRF bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, origin+target, bytes.NewReader(payload))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		if account >= 0 {
			r.AddCookie(&http.Cookie{Name: "__Host-karaoke_session", Value: tokens[account]})
			r.AddCookie(&http.Cookie{Name: "__Host-karaoke_csrf", Value: csrf})
		}
		if withCSRF {
			r.Header.Set("X-Karaoke-CSRF", csrf)
		}
		if browserCookie != nil {
			r.AddCookie(browserCookie)
		}
		w := httptest.NewRecorder()
		master.router.ServeHTTP(w, r)
		return w
	}
	jsonRequest := func(target string, payload any, account int, withCSRF bool) *httptest.ResponseRecorder {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		return perform("POST", target, raw, account, withCSRF)
	}
	client, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	w := jsonRequest("/api/v1/media/crypto/session", gin.H{"public_key": base64.StdEncoding.EncodeToString(client.PublicKey().Bytes())}, -1, false)
	var grant mediacrypto.SessionGrant
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &grant) != nil {
		t.Fatal("handshake", w.Code, w.Body.String())
	}
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == mediaCryptoCookie {
			browserCookie = cookie
		}
	}
	if browserCookie == nil {
		t.Fatal("missing browser binding")
	}
	serverRaw, _ := base64.StdEncoding.DecodeString(grant.PublicKey)
	server, err := ecdh.P256().NewPublicKey(serverRaw)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := client.ECDH(server)
	if err != nil {
		t.Fatal(err)
	}
	salt, _ := base64.StdEncoding.DecodeString(grant.Salt)
	wrapKey := make([]byte, 32)
	if _, err = io.ReadFull(hkdf.New(sha256.New, shared, salt, []byte("frontiercloud:browser-wrap:v1:"+grant.SessionID)), wrapKey); err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(wrapKey)
	wrapAEAD, _ := cipher.NewGCM(block)
	unwrap := func(meta mediacrypto.Metadata, envelope mediacrypto.KeyEnvelope) []byte {
		if envelope.ExpiresAt != grant.ExpiresAt {
			t.Fatal("snapshot renewed session expiry")
		}
		iv, _ := base64.StdEncoding.DecodeString(envelope.IV)
		wrapped, _ := base64.StdEncoding.DecodeString(envelope.WrappedKey)
		key, err := wrapAEAD.Open(nil, iv, wrapped, []byte("frontiercloud:key-envelope:v1:"+grant.SessionID+":"+meta.FileID))
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	// Publish genuine Master pool media and link a genuine opaque local LRC.
	upload, err := master.public.media.ReserveMasterUpload(ctx, "source.mp3", "music/artist", "", "primary", 10, 255, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = master.public.media.UploadMasterBytes(ctx, upload.ID, strings.NewReader("ID3source!"), store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	lyricMeta, _ := mediacrypto.NewMetadata(20)
	lyricBytes := bytes.Repeat([]byte{17}, int(lyricMeta.CiphertextSize))
	stage, err := master.public.media.Stage(ctx, bytes.NewReader(lyricBytes), lyricMeta.CiphertextSize)
	if err != nil {
		t.Fatal(err)
	}
	lyricPath, err := master.public.media.PublishEncrypted(ctx, stage, "source.lrc", "", "", true, 255, store.AdminAudit{}, &lyricMeta)
	stage.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = master.public.media.ReplaceLyrics(ctx, "track", upload.Path, []string{lyricPath}, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	getHandle := func(category string) string {
		w := perform("GET", "/api/v1/media/catalog/media?"+url.Values{"media_type": {"music"}, "path": {category}, "playback_session_id": {"recording-crypto"}}.Encode(), nil, -1, false)
		var result struct{ Entries []media.Track }
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || len(result.Entries) != 1 {
			t.Fatal("source catalog", w.Code, w.Body.String())
		}
		return result.Entries[0].KaraokeID
	}
	source := getHandle("music/artist")
	// Cross the AES chunk boundary and keep recognizable private text in memory.
	var lyricLines []store.RecordingLyric
	for i := range 600 {
		lyricLines = append(lyricLines, store.RecordingLyric{Time: float64(i), Text: strings.Repeat("private-recording-lyric-", 80)})
	}
	lyricsPlain, _ := json.Marshal(lyricLines)
	prepareBody := gin.H{"media": source, "session_id": grant.SessionID, "plaintext_size": len(lyricsPlain)}
	for _, v := range []struct {
		account int
		csrf    bool
		code    int
	}{{-1, false, 401}, {0, false, 403}} {
		w = jsonRequest(base+"/crypto/prepare", prepareBody, v.account, v.csrf)
		if w.Code != v.code {
			t.Fatal("unauthorized prepare", w.Code, w.Body.String())
		}
	}
	w = jsonRequest(base+"/crypto/prepare", gin.H{"media": source, "session_id": grant.SessionID, "plaintext_size": store.MaxEncryptedRecordingLyricPlaintext + 1}, 0, true)
	if w.Code != 413 {
		t.Fatal("snapshot size limit", w.Code)
	}
	var prep struct {
		Encryption mediacrypto.Metadata    `json:"encryption"`
		Envelope   mediacrypto.KeyEnvelope `json:"key_envelope"`
		Token      string                  `json:"preparation_token"`
	}
	w = jsonRequest(base+"/crypto/prepare", prepareBody, 0, true)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &prep) != nil || prep.Encryption.FileID == lyricMeta.FileID || prep.Encryption.NoncePrefix == lyricMeta.NoncePrefix {
		t.Fatal("independent snapshot prepare", w.Code, w.Body.String())
	}
	key := unwrap(prep.Encryption, prep.Envelope)
	block, _ = aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	var ciphertext []byte
	for i := uint32(0); int64(i)*mediacrypto.ChunkSize < prep.Encryption.PlaintextSize; i++ {
		start := int64(i) * mediacrypto.ChunkSize
		end := min(start+mediacrypto.ChunkSize, prep.Encryption.PlaintextSize)
		nonce, _ := prep.Encryption.ChunkNonce(i)
		ciphertext = append(ciphertext, aead.Seal(nil, nonce, lyricsPlain[start:end], prep.Encryption.ChunkAAD(i))...)
	}
	snapshot := &store.RecordingEncryptedLyrics{Encryption: prep.Encryption, Ciphertext: base64.StdEncoding.EncodeToString(ciphertext)}
	metadata := store.RecordingMetadata{Title: "private encrypted history", Lyrics: []store.RecordingLyric{}, EncryptedLyrics: snapshot}
	footer, _ := json.Marshal(gin.H{"version": 1, "title": metadata.Title, "lyrics": metadata.Lyrics, "encrypted_lyrics": snapshot})
	data := append([]byte("audio123"), footer...)
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(footer)))
	data = append(data, length[:]...)
	data = append(data, recording.TrailerMagic...)
	ticketBody := gin.H{"media": source, "size_bytes": len(data), "content_type": "audio/webm", "title": metadata.Title, "lyrics": []store.RecordingLyric{}, "encrypted_lyrics": snapshot, "preparation_token": prep.Token}
	badSnapshot := *snapshot
	badSnapshot.Ciphertext = snapshot.Ciphertext[:len(snapshot.Ciphertext)-4]
	ticketBody["encrypted_lyrics"] = &badSnapshot
	w = jsonRequest(base+"/ticket", ticketBody, 0, true)
	if w.Code != 400 {
		t.Fatal("wrong ciphertext length accepted", w.Code)
	}
	badSnapshot = *snapshot
	changedMeta, _ := mediacrypto.NewMetadata(snapshot.Encryption.PlaintextSize)
	badSnapshot.Encryption = changedMeta
	ticketBody["encrypted_lyrics"] = &badSnapshot
	w = jsonRequest(base+"/ticket", ticketBody, 0, true)
	if w.Code != 401 {
		t.Fatal("unauthorized descriptor replacement", w.Code)
	}
	ticketBody["encrypted_lyrics"] = snapshot
	ticketBody["lyrics"] = []store.RecordingLyric{{Time: 1, Text: "private plaintext"}}
	w = jsonRequest(base+"/ticket", ticketBody, 0, true)
	if w.Code != 400 {
		t.Fatal("plaintext alongside encrypted snapshot", w.Code)
	}
	ticketBody["lyrics"] = []store.RecordingLyric{}
	savedCookie := browserCookie
	browserCookie = nil
	w = jsonRequest(base+"/ticket", ticketBody, 0, true)
	if w.Code != 401 {
		t.Fatal("preparation escaped browser binding", w.Code)
	}
	browserCookie = savedCookie
	delete(ticketBody, "media")
	w = jsonRequest(base+"/ticket", ticketBody, 0, true)
	if w.Code != 400 {
		t.Fatal("unrelated encrypted snapshot accepted", w.Code)
	}
	ticketBody["media"] = source
	if _, err = master.public.media.ReplaceLyrics(ctx, "track", upload.Path, nil, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	w = jsonRequest(base+"/crypto/prepare", prepareBody, 0, true)
	if w.Code != 409 {
		t.Fatal("plaintext source prepared encryption", w.Code)
	}
	w = jsonRequest(base+"/ticket", ticketBody, 0, true)
	if w.Code != 400 {
		t.Fatal("plaintext source accepted encrypted authorization", w.Code)
	}
	if _, err = master.public.media.ReplaceLyrics(ctx, "track", upload.Path, []string{lyricPath}, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	w = jsonRequest(base+"/ticket", gin.H{"media": source, "size_bytes": 8, "content_type": "audio/webm", "lyrics": []store.RecordingLyric{{Time: 1, Text: "private plaintext"}}}, 0, true)
	if w.Code != 400 {
		t.Fatal("encrypted source accepted plaintext", w.Code, w.Body.String())
	}
	w = jsonRequest(base+"/ticket", ticketBody, 1, true)
	if w.Code != 401 {
		t.Fatal("cross-account preparation", w.Code, w.Body.String())
	}
	goodToken := ticketBody["preparation_token"]
	ticketBody["preparation_token"] = prep.Token + "tampered"
	w = jsonRequest(base+"/ticket", ticketBody, 0, true)
	if w.Code != 401 {
		t.Fatal("tampered preparation", w.Code)
	}
	ticketBody["preparation_token"] = goodToken
	// A second visible audio source sharing the lyric keeps public lyric
	// access valid, but must not revive a stale hidden source's Karaoke token.
	peer, err := master.public.media.ReserveMasterUpload(ctx, "peer.mp3", "music/peer", "", "primary", 10, 255, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = master.public.media.UploadMasterBytes(ctx, peer.ID, strings.NewReader("ID3source!"), store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	if _, err = master.public.media.ReplaceLyrics(ctx, "track", peer.Path, []string{lyricPath}, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	peerSource := getHandle("music/peer")
	if err = master.public.media.Hide(ctx, []string{"music/artist"}, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	w = jsonRequest("/api/v1/media/crypto/key", gin.H{"session_id": grant.SessionID, "file_path": lyricPath}, -1, false)
	if w.Code != 200 {
		t.Fatal("shared visible lyric rejected", w.Code)
	}
	for _, target := range []string{base + "/crypto/prepare", base + "/ticket"} {
		body := prepareBody
		if strings.HasSuffix(target, "/ticket") {
			body = ticketBody
		}
		w = jsonRequest(target, body, 0, true)
		if w.Code != 404 {
			t.Fatal("hidden original source authorized encrypted snapshot", target, w.Code)
		}
	}
	w = jsonRequest(base+"/crypto/prepare", gin.H{"media": peerSource, "session_id": grant.SessionID, "plaintext_size": len(lyricsPlain)}, 0, true)
	var peerPrep struct {
		Encryption mediacrypto.Metadata    `json:"encryption"`
		Envelope   mediacrypto.KeyEnvelope `json:"key_envelope"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &peerPrep) != nil {
		t.Fatal("visible shared source could not prepare snapshot", w.Code)
	}
	unwrap(peerPrep.Encryption, peerPrep.Envelope)
	if err = master.public.media.Hide(ctx, []string{"music/artist"}, false, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	w = jsonRequest(base+"/ticket", ticketBody, 0, true)
	var ticket recording.Ticket
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &ticket) != nil {
		t.Fatal("encrypted ticket", w.Code, w.Body.String())
	}
	w = jsonRequest(base+"/ticket", ticketBody, 0, true)
	if w.Code != 400 {
		t.Fatal("snapshot file/nonce identity reused")
	}
	w = perform("PUT", ticket.URL, data, 0, true)
	if w.Code != 200 {
		t.Fatal("opaque upload", w.Code, w.Body.String())
	}
	w = jsonRequest(base+"/"+ticket.ID+"/finalize", gin.H{}, 0, true)
	if w.Code != 200 {
		t.Fatal("opaque finalize", w.Code, w.Body.String())
	}
	row, err := master.db.Recordings().Recording(ctx, ticket.ID)
	if err != nil || row == nil || len(row.Lyrics) != 0 || row.EncryptedLyrics == nil || *row.EncryptedLyrics != *snapshot {
		t.Fatal("snapshot persistence", err)
	}
	var persisted string
	if err = master.db.Database().QueryRow("SELECT lyrics FROM karaoke_recordings WHERE recording_id=?", ticket.ID).Scan(&persisted); err != nil || strings.Contains(persisted, "private-recording-lyric") {
		t.Fatal("plaintext persisted", err)
	}
	file, _, release, err := master.volume.Open(ctx, master.id, users[0].ID, ticket.ID)
	if err != nil {
		t.Fatal("recording file", err)
	}
	fileBytes, err := io.ReadAll(file)
	release()
	if err != nil || !bytes.Equal(fileBytes, data) || bytes.Contains(fileBytes, []byte("private-recording-lyric")) {
		t.Fatal("plaintext reached recording file")
	}
	keyBody := gin.H{"session_id": grant.SessionID}
	keyPath := base + "/" + ticket.ID + "/lyrics-key"
	for _, v := range []struct {
		account int
		csrf    bool
		code    int
	}{{-1, false, 401}, {0, false, 403}, {1, true, 404}} {
		w = jsonRequest(keyPath, keyBody, v.account, v.csrf)
		if w.Code != v.code {
			t.Fatal("unauthorized snapshot key", w.Code, w.Body.String())
		}
	}
	if err = master.public.media.Hide(ctx, []string{"music/artist"}, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	w = jsonRequest(keyPath, keyBody, 0, true)
	if w.Code != 200 {
		t.Fatal("historical owner snapshot depends on hidden source", w.Code)
	}
	if _, err = master.public.media.Delete(ctx, []string{lyricPath}, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	w = jsonRequest(keyPath, keyBody, 0, true)
	var keyResult struct {
		Snapshot *store.RecordingEncryptedLyrics `json:"encrypted_lyrics"`
		Envelope mediacrypto.KeyEnvelope         `json:"key_envelope"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &keyResult) != nil || keyResult.Snapshot == nil || *keyResult.Snapshot != *snapshot || !bytes.Equal(unwrap(snapshot.Encryption, keyResult.Envelope), key) {
		t.Fatal("historical key depends on deleted LRC", w.Code, w.Body.String())
	}
	block, _ = aes.NewCipher(unwrap(snapshot.Encryption, keyResult.Envelope))
	aead, _ = cipher.NewGCM(block)
	var recovered []byte
	for i := uint32(0); int64(i)*mediacrypto.ChunkSize < snapshot.Encryption.PlaintextSize; i++ {
		start := int64(i) * (mediacrypto.ChunkSize + 16)
		plainSize := min(mediacrypto.ChunkSize, snapshot.Encryption.PlaintextSize-int64(i)*mediacrypto.ChunkSize)
		nonce, _ := snapshot.Encryption.ChunkNonce(i)
		plain, err := aead.Open(nil, nonce, ciphertext[start:start+plainSize+16], snapshot.Encryption.ChunkAAD(i))
		if err != nil {
			t.Fatal(err)
		}
		recovered = append(recovered, plain...)
	}
	if !bytes.Equal(recovered, lyricsPlain) {
		t.Fatal("browser lost historical lyrics")
	}
	master.public.crypto.RevokeBinding("browser:" + browserCookie.Value)
	w = jsonRequest(keyPath, keyBody, 0, true)
	if w.Code != 401 {
		t.Fatal("revoked snapshot grant", w.Code)
	}
	if err = master.db.Karaoke().MutateUser(ctx, users[0].ID, "ban", 0, store.KaraokeAudit{}); err != nil {
		t.Fatal(err)
	}
	w = jsonRequest(keyPath, keyBody, 0, true)
	if w.Code != 403 {
		t.Fatal("blocked owner retained key authorization", w.Code, w.Body.String())
	}
}
