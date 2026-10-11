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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/admin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestEncryptedPreparePlaintextLimitMatchesLocalAndMasterUpload(t *testing.T) {
	for _, role := range []string{"Standalone", "Master"} {
		t.Run(role, func(t *testing.T) {
			ctx := context.Background()
			transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
			router, db, dir, public, nodes := clusterFixture(t, "https://master.test", transport, false)
			if role == "Master" {
				if _, err := nodes.Promote(ctx, role, "https://master.test", 10*store.GiB, store.NodeAudit{}); err != nil {
					t.Fatal(err)
				}
			}
			resolver, err := network.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			a := &Admin{public: public, settings: public.settings, network: resolver}
			group := router.Group("/size-admin", func(c *gin.Context) {
				c.Set("admin_session", admin.Session{Hash: "size-boundary-session"})
				c.Next()
			})
			group.POST("/session", a.cryptoSession)
			group.POST("/prepare", a.cryptoPrepare)
			group.POST("/item", func(c *gin.Context) { a.upload(c, false) })
			group.POST("/reserve", a.reserveUpload)
			group.PUT("/upload/session/:upload/bytes", a.uploadBytes)
			// UploadTicket uses the normal public Admin URL.
			router.PUT("/api/v1/media/admin/upload/session/:upload/bytes", func(c *gin.Context) {
				c.Set("admin_session", admin.Session{Hash: "size-boundary-session"})
				a.uploadBytes(c)
			})
			post := func(route string, payload any) *httptest.ResponseRecorder {
				t.Helper()
				encoded, err := json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				return request(router, "POST", "/size-admin/"+route, string(encoded))
			}
			client, err := ecdh.P256().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			response := post("session", gin.H{"public_key": base64.StdEncoding.EncodeToString(client.PublicKey().Bytes())})
			var session mediacrypto.SessionGrant
			if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &session) != nil {
				t.Fatal(response.Code, response.Body.String())
			}
			for _, cap := range []int64{64, mediacrypto.ChunkSize + 1} {
				a.settings.AdminMaxUploadBytes = cap
				for _, size := range []int64{cap, cap + 1} {
					response = post("prepare", gin.H{"session_id": session.SessionID, "plaintext_size": size})
					if size > cap {
						if response.Code != 413 {
							t.Fatal("oversize plaintext was accepted", cap, response.Code, response.Body.String())
						}
						continue
					}
					var prep struct {
						Encryption mediacrypto.Metadata `json:"encryption"`
						Token      string               `json:"preparation_token"`
					}
					if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &prep) != nil || prep.Encryption.PlaintextSize != cap || prep.Encryption.CiphertextSize <= cap {
						t.Fatal("maximum legal plaintext could not be prepared", cap, response.Code, response.Body.String())
					}
					key, err := public.crypto.FileKey(prep.Encryption)
					if err != nil {
						t.Fatal(err)
					}
					block, err := aes.NewCipher(key)
					if err != nil {
						t.Fatal(err)
					}
					aead, err := cipher.NewGCM(block)
					if err != nil {
						t.Fatal(err)
					}
					plain := bytes.Repeat([]byte{'q'}, int(cap))
					var encrypted []byte
					for i := uint32(0); int64(i)*mediacrypto.ChunkSize < cap; i++ {
						nonce, err := prep.Encryption.ChunkNonce(i)
						if err != nil {
							t.Fatal(err)
						}
						start := int64(i) * mediacrypto.ChunkSize
						encrypted = append(encrypted, aead.Seal(nil, nonce, plain[start:min(start+mediacrypto.ChunkSize, cap)], prep.Encryption.ChunkAAD(i))...)
					}
					filename := fmt.Sprintf("size-%d.mp3", cap)
					name := "music/artist/" + filename
					if role == "Standalone" {
						var body bytes.Buffer
						form := multipart.NewWriter(&body)
						encoded, _ := json.Marshal(prep.Encryption)
						for field, value := range map[string]string{"target_dir": "music/artist", "storage_mode": "encrypted", "encryption": string(encoded), "preparation_token": prep.Token} {
							if err := form.WriteField(field, value); err != nil {
								t.Fatal(err)
							}
						}
						file, err := form.CreateFormFile("file", filename)
						if err != nil {
							t.Fatal(err)
						}
						if _, err = file.Write(encrypted); err != nil {
							t.Fatal(err)
						}
						if err = form.Close(); err != nil {
							t.Fatal(err)
						}
						req := httptest.NewRequest("POST", "/size-admin/item", &body)
						req.Header.Set("Content-Type", form.FormDataContentType())
						response = httptest.NewRecorder()
						router.ServeHTTP(response, req)
					} else {
						response = post("reserve", gin.H{"site_type": "primary", "target_dir": "music/artist", "filename": filename, "size_bytes": len(encrypted), "storage_mode": "encrypted", "encryption": prep.Encryption, "preparation_token": prep.Token})
						var ticket media.UploadTicket
						if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &ticket) != nil {
							t.Fatal("ciphertext reservation rejected", response.Code, response.Body.String())
						}
						req := httptest.NewRequest("PUT", ticket.URL, bytes.NewReader(encrypted))
						response = httptest.NewRecorder()
						router.ServeHTTP(response, req)
						if response.Code == 200 {
							var storedHash string
							if err := db.Database().QueryRow("SELECT etag FROM global_media_objects WHERE media_id=?", ticket.MediaID).Scan(&storedHash); err != nil {
								t.Fatal(err)
							}
							digest := sha256.Sum256(encrypted)
							if strings.Trim(storedHash, "\"") != hex.EncodeToString(digest[:]) {
								t.Fatal("receipt hash differs from actual ciphertext", storedHash)
							}
						}
					}
					if response.Code != 200 {
						t.Fatal("legal ciphertext overhead was rejected by upload", cap, response.Code, response.Body.String())
					}
					stored, err := os.ReadFile(filepath.Join(dir, "media", filepath.FromSlash(name)))
					if err != nil || !bytes.Equal(stored, encrypted) || bytes.Equal(stored, plain) {
						t.Fatal("uploaded ciphertext was altered or downgraded", err)
					}
				}
			}
			// Configured limits never expand the storage format's hard ciphertext ceiling.
			a.settings.AdminMaxUploadBytes = mediacrypto.MaxCiphertextSize
			response = post("prepare", gin.H{"session_id": session.SessionID, "plaintext_size": mediacrypto.MaxPlaintextSize + 1})
			if response.Code == 200 {
				t.Fatal("global ciphertext storage ceiling was expanded")
			}
		})
	}
}
