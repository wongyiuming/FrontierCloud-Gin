package httpapi

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

// encryptedAdminUploadFixture prepares exactly the descriptor, signature and
// ciphertext used by the browser upload protocol. Crypto HTTP admission itself
// is covered independently by the session and prepare route tests.
func encryptedAdminUploadFixture(t *testing.T, public *Public, sessionHash string, plaintext []byte, request gin.H) (gin.H, []byte) {
	t.Helper()
	meta, err := mediacrypto.NewMetadata(int64(len(plaintext)))
	if err != nil {
		t.Fatal(err)
	}
	key, err := public.crypto.FileKey(meta)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := meta.ChunkNonce(0)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(plaintext)) > meta.ChunkSize {
		t.Fatal("encrypted upload fixture requires one chunk")
	}
	preparation, err := public.crypto.SignPreparation("admin:"+sessionHash, meta)
	if err != nil {
		t.Fatal(err)
	}
	request["storage_mode"], request["size_bytes"] = "encrypted", meta.CiphertextSize
	request["encryption"], request["preparation_token"] = meta, preparation
	return request, aead.Seal(nil, nonce, plaintext, meta.ChunkAAD(0))
}
