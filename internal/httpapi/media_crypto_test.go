package httpapi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestMediaCryptoStartupRejectsWrongPremasterAndStorageLoadsNoKey(t *testing.T) {
	publicRouter, db, dir, public := publicFixture(t, false)
	keyPath := filepath.Join(dir, "media-keys", "media-premaster.key")
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	wrong := append([]byte(nil), key...)
	wrong[0] ^= 1
	if err = os.WriteFile(keyPath, wrong, 0600); err != nil {
		t.Fatal(err)
	}
	if err = public.registerMediaCrypto(gin.New()); !errors.Is(err, mediacrypto.ErrPremaster) {
		t.Fatal("startup accepted wrong valid-size premaster", err)
	}
	if err = os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if err = public.registerMediaCrypto(gin.New()); err == nil {
		t.Fatal("durable key identity allowed key regeneration")
	}
	if err = os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	if err = public.registerMediaCrypto(gin.New()); err != nil {
		t.Fatal("correct restored key rejected", err)
	}
	if _, err = db.Database().Exec("UPDATE node_identity SET role='Follower' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	public.media.ConfigureCluster(db.Nodes(), db.Pool(), nil)
	// The original Standalone manager and public routes remain in the running
	// process after promotion. Current durable role must override that snapshot.
	afterPromotion := &Admin{public: public}
	publicRouter.POST("/promoted-admin/session", afterPromotion.cryptoSession)
	publicRouter.POST("/promoted-admin/prepare", afterPromotion.cryptoPrepare)
	publicRouter.POST("/promoted-admin/key", afterPromotion.cryptoKey)
	for _, target := range []string{"/api/v1/media/crypto/session", "/api/v1/media/crypto/key", "/promoted-admin/session", "/promoted-admin/prepare", "/promoted-admin/key"} {
		w := httptest.NewRecorder()
		request := httptest.NewRequest("POST", target, bytes.NewBufferString(`{}`))
		request.RemoteAddr = "127.0.0.1:12345"
		request.Header.Set("Content-Type", "application/json")
		publicRouter.ServeHTTP(w, request)
		if w.Code != 409 || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
			t.Fatal("promoted Follower retained key authorization", target, w.Code, w.Body.String())
		}
	}
	storage := &Public{settings: public.settings, media: public.media}
	storage.settings.DataRoot = t.TempDir()
	router := gin.New()
	if err = storage.registerMediaCrypto(router); err != nil {
		t.Fatal(err)
	}
	if storage.crypto != nil {
		t.Fatal("storage initialized master crypto manager")
	}
	if _, err = os.Stat(filepath.Join(storage.settings.DataRoot, "media-keys")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("storage generated premaster material", err)
	}
	a := &Admin{public: storage}
	router.POST("/admin/session", a.cryptoSession)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/admin/session", bytes.NewBufferString(`{}`)))
	if w.Code != 409 {
		t.Fatal("storage key API did not fail closed", w.Code)
	}
}

func TestEncryptedUploadExplicitChoiceSessionReuseRangeAndVisibility(t *testing.T) {
	router, db, dir, p := publicFixture(t, false)
	resolver, err := network.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	auditSettings := p.settings
	auditSettings.SecretsDirectory = t.TempDir()
	if err := os.WriteFile(filepath.Join(auditSettings.SecretsDirectory, "admin_key"), []byte("crypto-audit-fixture-key"), 0600); err != nil {
		t.Fatal(err)
	}
	auth, err := admin.New(auditSettings, nil, db.Admin())
	if err != nil {
		t.Fatal(err)
	}
	a := &Admin{settings: p.settings, public: p, auth: auth, network: resolver}
	g := router.Group("/api/v1/media/admin", func(c *gin.Context) { c.Set("admin_session", admin.Session{Hash: "crypto-admin-session"}); c.Next() })
	g.POST("/crypto/session", a.cryptoSession)
	g.POST("/crypto/prepare", a.cryptoPrepare)
	g.POST("/crypto/key", a.cryptoKey)
	g.GET("/crypto/bytes", a.cryptoBytes)
	g.POST("/upload/item", func(c *gin.Context) { a.upload(c, false) })
	g.GET("/download/plan", a.downloadPlan)
	perform := func(target string, payload any, cookie *http.Cookie) *httptest.ResponseRecorder {
		encoded, _ := json.Marshal(payload)
		r := httptest.NewRequest("POST", target, bytes.NewReader(encoded))
		r.RemoteAddr = "127.0.0.1:12345"
		r.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	client, _ := ecdh.P256().GenerateKey(rand.Reader)
	handshake := map[string]any{"public_key": base64.StdEncoding.EncodeToString(client.PublicKey().Bytes())}
	w := perform("/api/v1/media/admin/crypto/session", handshake, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var sessionGrant mediacrypto.SessionGrant
	json.Unmarshal(w.Body.Bytes(), &sessionGrant)
	limit := a.settings.AdminMaxUploadBytes
	a.settings.AdminMaxUploadBytes = 64
	for _, boundary := range []struct {
		size int64
		code int
	}{{48, 200}, {49, 413}, {64, 413}, {65, 413}} {
		w = perform("/api/v1/media/admin/crypto/prepare", gin.H{"session_id": sessionGrant.SessionID, "plaintext_size": boundary.size}, nil)
		if w.Code != boundary.code {
			t.Fatal("preparation ignored authenticated ciphertext upload size", boundary.size, w.Code)
		}
	}
	a.settings.AdminMaxUploadBytes = limit
	var preparations []struct {
		Encryption  mediacrypto.Metadata    `json:"encryption"`
		Preparation string                  `json:"preparation_token"`
		Envelope    mediacrypto.KeyEnvelope `json:"key_envelope"`
	}
	for _, size := range []int64{3, mediacrypto.ChunkSize + 9} {
		w = perform("/api/v1/media/admin/crypto/prepare", gin.H{"session_id": sessionGrant.SessionID, "plaintext_size": size}, nil)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var prep struct {
			Encryption  mediacrypto.Metadata    `json:"encryption"`
			Preparation string                  `json:"preparation_token"`
			Envelope    mediacrypto.KeyEnvelope `json:"key_envelope"`
		}
		json.Unmarshal(w.Body.Bytes(), &prep)
		if prep.Envelope.ExpiresAt != sessionGrant.ExpiresAt {
			t.Fatal("file renewed session expiry")
		}
		preparations = append(preparations, prep)
	}
	prep := preparations[1]
	key, _ := p.crypto.FileKey(prep.Encryption)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	plain := bytes.Repeat([]byte{'Q'}, int(prep.Encryption.PlaintextSize))
	copy(plain, []byte("ID3"))
	var ciphertext []byte
	for i := uint32(0); int64(i)*mediacrypto.ChunkSize < prep.Encryption.PlaintextSize; i++ {
		nonce, _ := prep.Encryption.ChunkNonce(i)
		start := int64(i) * mediacrypto.ChunkSize
		end := min(start+mediacrypto.ChunkSize, prep.Encryption.PlaintextSize)
		ciphertext = append(ciphertext, aead.Seal(nil, nonce, plain[start:end], prep.Encryption.ChunkAAD(i))...)
	}
	upload := func(mode, token string) *httptest.ResponseRecorder {
		var body bytes.Buffer
		form := multipart.NewWriter(&body)
		form.WriteField("target_dir", "music/artist")
		if mode != "" {
			form.WriteField("storage_mode", mode)
		}
		if mode == "encrypted" {
			encoded, _ := json.Marshal(prep.Encryption)
			form.WriteField("encryption", string(encoded))
			form.WriteField("preparation_token", token)
		}
		f, _ := form.CreateFormFile("file", "encrypted.mp3")
		f.Write(ciphertext)
		form.Close()
		r := httptest.NewRequest("POST", "/api/v1/media/admin/upload/item", &body)
		r.Header.Set("Content-Type", form.FormDataContentType())
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	if w = upload("", ""); w.Code != 400 {
		t.Fatal("missing mode accepted", w.Code, w.Body.String())
	}
	if w = upload("encrypted", prep.Preparation+"corrupt"); w.Code != 401 {
		t.Fatal("tampered preparation accepted", w.Code, w.Body.String())
	}
	if w = upload("encrypted", prep.Preparation); w.Code != 200 {
		t.Fatal("encrypted upload", w.Code, w.Body.String())
	}
	stored, err := os.ReadFile(filepath.Join(dir, "media/music/artist/encrypted.mp3"))
	if err != nil || !bytes.Equal(stored, ciphertext) {
		t.Fatal("cipher bytes changed", err)
	}
	if bytes.Equal(stored, plain) {
		t.Fatal("plaintext reached storage")
	}
	if w = upload("encrypted", prep.Preparation); w.Code == 200 {
		t.Fatal("reused file/nonce identity accepted")
	}
	w = perform("/api/v1/media/crypto/session", handshake, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var publicGrant mediacrypto.SessionGrant
	json.Unmarshal(w.Body.Bytes(), &publicGrant)
	var cookie *http.Cookie
	for _, v := range w.Result().Cookies() {
		if v.Name == mediaCryptoCookie {
			cookie = v
		}
	}
	if cookie == nil {
		t.Fatal("browser binding absent")
	}
	query := gin.H{"session_id": publicGrant.SessionID, "file_path": "music/artist/encrypted.mp3"}
	w = perform("/api/v1/media/crypto/key", query, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "wrapped_key") {
		t.Fatal("decrypt envelope", w.Code, w.Body.String())
	}
	if w = perform("/api/v1/media/crypto/key", query, nil); w.Code != 401 {
		t.Fatal("unbound key issued", w.Code)
	}
	r := httptest.NewRequest("GET", "/api/v1/media/stream?file_path=music%2Fartist%2Fencrypted.mp3", nil)
	r.Header.Set("Range", "bytes=1048580-1048600")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, r)
	if w.Code != 206 || !bytes.Equal(w.Body.Bytes(), ciphertext[1048580:1048601]) || w.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatal("ciphertext Range", w.Code, w.Header())
	}
	paths, _ := json.Marshal([]string{"music/artist"})
	w = request(router, "GET", "/api/v1/media/admin/download/plan?"+url.Values{"paths": {string(paths)}}.Encode(), "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "plaintext_size") {
		t.Fatal("download plan", w.Code, w.Body.String())
	}
	if err := db.Media().SetHidden(context.Background(), []string{"music/artist/encrypted.mp3"}, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	w = perform("/api/v1/media/crypto/key", query, cookie)
	if w.Code == 200 {
		t.Fatal("hidden-file key issued")
	}
	w = perform("/api/v1/media/crypto/revoke", gin.H{}, cookie)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if _, err = p.crypto.Wrap("browser:"+cookie.Value, publicGrant.SessionID, prep.Encryption); err == nil {
		t.Fatal("revoked browser still authorized")
	}
}

func TestCryptoCrossOriginRequestsAndWorkerPolicy(t *testing.T) {
	router, _, _, _ := publicFixture(t, false)
	r := httptest.NewRequest("POST", "http://example.com/api/v1/media/crypto/session", strings.NewReader(`{"public_key":"invalid"}`))
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://attacker.test")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cross-origin handshake admitted", w.Code)
	}
	w = request(router, "GET", "/media-crypto-sw.js", "")
	if w.Code != 200 || w.Header().Get("Service-Worker-Allowed") != "/" || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("worker route policy", w.Code, w.Header())
	}
}

func TestCryptoStartupRejectsWrongPremasterEvenWithoutMedia(t *testing.T) {
	_, _, dir, p := publicFixture(t, false)
	keyPath := filepath.Join(dir, "media-keys", "media-premaster.key")
	original, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile(keyPath, original, 0600) })
	wrong := bytes.Repeat([]byte{0x71}, 32)
	if bytes.Equal(wrong, original) {
		wrong[0] ^= 1
	}
	if err = os.WriteFile(keyPath, wrong, 0600); err != nil {
		t.Fatal(err)
	}
	_, err = RegisterPublic(New(pass, pass), p.settings, p.media)
	if !errors.Is(err, mediacrypto.ErrPremaster) {
		t.Fatal("wrong premaster admitted at startup", err)
	}
	if err = os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	_, err = RegisterPublic(New(pass, pass), p.settings, p.media)
	if err == nil {
		t.Fatal("registered premaster regenerated after loss")
	}
	if _, err = os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing premaster was replaced", err)
	}
}
