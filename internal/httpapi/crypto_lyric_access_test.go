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
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestPublicLyricKeyAndCipherRangeRecheckSourceAccessHTTP(t *testing.T) {
	for _, master := range []bool{false, true} {
		name := "Standalone"
		if master {
			name = "Master"
		}
		t.Run(name, func(t *testing.T) {
			router, db, _, public := publicFixture(t, false)
			ctx := context.Background()
			if master {
				err := public.media.WithPromotion(ctx, "Master", func(promotion store.NodePromotion) error {
					promotion.Endpoint, promotion.Allocation = "https://lyric-master.test", 10*store.GiB
					_, err := db.Nodes().PromoteIdentity(ctx, promotion, store.NodeAudit{})
					return err
				})
				if err != nil {
					t.Fatal(err)
				}
				public.media.ConfigureCluster(db.Nodes(), db.Pool(), nil)
			}
			plain := []byte("[00:01] lyrics must stay in browsers\n")
			meta, err := mediacrypto.NewMetadata(int64(len(plain)))
			if err != nil {
				t.Fatal(err)
			}
			key, err := public.crypto.FileKey(meta)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := aes.NewCipher(key)
			aead, _ := cipher.NewGCM(block)
			nonce, _ := meta.ChunkNonce(0)
			ciphertext := aead.Seal(nil, nonce, plain, meta.ChunkAAD(0))
			stage, err := public.media.Stage(ctx, bytes.NewReader(ciphertext), meta.CiphertextSize)
			if err != nil {
				t.Fatal(err)
			}
			lyric, err := public.media.PublishEncrypted(ctx, stage, "restricted.lrc", "", "", true, 255, store.AdminAudit{}, &meta)
			stage.Close()
			if err != nil {
				t.Fatal(err)
			}
			post := func(target string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
				raw, _ := json.Marshal(body)
				r := httptest.NewRequest("POST", target, bytes.NewReader(raw))
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
			w := post("/api/v1/media/crypto/session", gin.H{"public_key": base64.StdEncoding.EncodeToString(client.PublicKey().Bytes())}, nil)
			var grant mediacrypto.SessionGrant
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &grant) != nil {
				t.Fatal("public handshake", w.Code)
			}
			var binding *http.Cookie
			for _, cookie := range w.Result().Cookies() {
				if cookie.Name == mediaCryptoCookie {
					binding = cookie
				}
			}
			if binding == nil {
				t.Fatal("public binding absent")
			}
			check := func(allowed bool) {
				t.Helper()
				w := post("/api/v1/media/crypto/key", gin.H{"session_id": grant.SessionID, "file_path": lyric}, binding)
				if !allowed {
					if w.Code != 404 || bytes.Contains(w.Body.Bytes(), []byte("wrapped_key")) {
						t.Fatal("key authorization retained old source visibility", w.Code)
					}
				} else {
					var issued struct {
						Envelope mediacrypto.KeyEnvelope `json:"key_envelope"`
					}
					if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &issued) != nil || issued.Envelope.ExpiresAt != grant.ExpiresAt {
						t.Fatal("current source key/session expiry", w.Code)
					}
				}
				for _, method := range []string{"GET", "HEAD"} {
					r := httptest.NewRequest(method, "/api/v1/media/crypto/bytes?"+url.Values{"file_path": {lyric}}.Encode(), nil)
					r.Header.Set("Range", "bytes=5-12")
					w = httptest.NewRecorder()
					router.ServeHTTP(w, r)
					if !allowed {
						if w.Code != 404 || bytes.Contains(w.Body.Bytes(), ciphertext[5:13]) {
							t.Fatal("ciphertext accessible after source permission changed", method, w.Code)
						}
					} else if w.Code != 206 || w.Header().Get("Content-Type") != "application/octet-stream" || method == "GET" && !bytes.Equal(w.Body.Bytes(), ciphertext[5:13]) || method == "HEAD" && w.Body.Len() != 0 {
						t.Fatal("visible lyric cipher Range/HEAD", method, w.Code, w.Header())
					}
				}
			}
			bind := func(track string, lyrics ...string) {
				t.Helper()
				if _, err := public.media.ReplaceLyrics(ctx, "track", track, lyrics, store.AdminAudit{}); err != nil {
					t.Fatal(err)
				}
			}
			check(false)
			bind("music/artist/song.mp3", lyric)
			check(true)
			if err := public.media.Hide(ctx, []string{"music/artist"}, true, store.AdminAudit{}); err != nil {
				t.Fatal(err)
			}
			check(false)
			bind("music/nested/album/音乐.mp3", lyric)
			check(true)
			bind("music/nested/album/音乐.mp3")
			check(false)
			if err := public.media.Hide(ctx, []string{"music/artist"}, false, store.AdminAudit{}); err != nil {
				t.Fatal(err)
			}
			check(true)
		})
	}
}
