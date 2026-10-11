package updater

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"golang.org/x/crypto/hkdf"
)

// Only the disposable test driver performs cryptography. Runtime nodes receive
// ciphertext and issue wrapped grants through the same browser HTTP contract.
type fleetBrowserCrypto struct {
	grant mediacrypto.SessionGrant
	wrap  cipher.AEAD
}

type fleetPreparedCrypto struct {
	Encryption  mediacrypto.Metadata    `json:"encryption"`
	Preparation string                  `json:"preparation_token"`
	Envelope    mediacrypto.KeyEnvelope `json:"key_envelope"`
}

type fleetEncryptedFixture struct {
	name     string
	metadata mediacrypto.Metadata
	plain    []byte
}

func fleetCryptoDecode(t *testing.T, value map[string]any, destination any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal("invalid crypto response encoding")
	}
	if err = json.Unmarshal(encoded, destination); err != nil {
		t.Fatal("invalid crypto response shape")
	}
}

func newFleetBrowserCrypto(t *testing.T, ctx context.Context, master *fleetSite) *fleetBrowserCrypto {
	t.Helper()
	private, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("driver ECDH key creation failed")
	}
	code, response, err := master.request(ctx, "POST", "/api/v1/media/admin/crypto/session", map[string]any{"public_key": base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())})
	if err != nil || code != 200 {
		t.Fatal("real fleet browser ECDH authorization failed", code, err)
	}
	var grant mediacrypto.SessionGrant
	fleetCryptoDecode(t, response, &grant)
	encoded, err := base64.StdEncoding.Strict().DecodeString(grant.PublicKey)
	if err != nil {
		t.Fatal("invalid server ECDH public key encoding")
	}
	server, err := ecdh.P256().NewPublicKey(encoded)
	if err != nil {
		t.Fatal("invalid server ECDH public key")
	}
	shared, err := private.ECDH(server)
	if err != nil {
		t.Fatal("driver ECDH agreement failed")
	}
	defer clear(shared)
	salt, err := base64.StdEncoding.Strict().DecodeString(grant.Salt)
	if err != nil || len(salt) != 32 || grant.SessionID == "" || grant.ExpiresAt <= time.Now().Unix() {
		t.Fatal("invalid bounded browser session grant")
	}
	key := make([]byte, 32)
	defer clear(key)
	if _, err = io.ReadFull(hkdf.New(sha256.New, shared, salt, []byte("frontiercloud:browser-wrap:v1:"+grant.SessionID)), key); err != nil {
		t.Fatal("driver HKDF derivation failed")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal("invalid derived wrapping key")
	}
	wrap, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal("driver wrapping cipher creation failed")
	}
	return &fleetBrowserCrypto{grant, wrap}
}

func (browser *fleetBrowserCrypto) unwrap(t *testing.T, metadata mediacrypto.Metadata, envelope mediacrypto.KeyEnvelope) cipher.AEAD {
	t.Helper()
	if err := metadata.Validate(); err != nil || envelope.ExpiresAt != browser.grant.ExpiresAt || envelope.ExpiresAt <= time.Now().Unix() {
		t.Fatal("file grant changed descriptor or renewed authorization expiry")
	}
	iv, err := base64.StdEncoding.Strict().DecodeString(envelope.IV)
	if err != nil || len(iv) != browser.wrap.NonceSize() {
		t.Fatal("invalid key envelope nonce")
	}
	wrapped, err := base64.StdEncoding.Strict().DecodeString(envelope.WrappedKey)
	if err != nil {
		t.Fatal("invalid key envelope ciphertext")
	}
	key, err := browser.wrap.Open(nil, iv, wrapped, []byte("frontiercloud:key-envelope:v1:"+browser.grant.SessionID+":"+metadata.FileID))
	if err != nil || len(key) != 32 {
		t.Fatal("driver could not authenticate the actual HTTP wrapped file key")
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal("invalid unwrapped file key")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal("driver content cipher creation failed")
	}
	return aead
}

func (browser *fleetBrowserCrypto) prepare(t *testing.T, ctx context.Context, master *fleetSite, plaintext []byte) (fleetPreparedCrypto, []byte) {
	t.Helper()
	code, response, err := master.request(ctx, "POST", "/api/v1/media/admin/crypto/prepare", map[string]any{"session_id": browser.grant.SessionID, "plaintext_size": len(plaintext)})
	if err != nil || code != 200 {
		t.Fatal("actual HTTP encrypted upload preparation failed", code, err)
	}
	var prepared fleetPreparedCrypto
	fleetCryptoDecode(t, response, &prepared)
	if prepared.Encryption.PlaintextSize != int64(len(plaintext)) || prepared.Preparation == "" {
		t.Fatal("upload preparation did not bind plaintext size or authorization")
	}
	aead := browser.unwrap(t, prepared.Encryption, prepared.Envelope)
	ciphertext := make([]byte, 0, prepared.Encryption.CiphertextSize)
	for start, index := int64(0), uint32(0); start < int64(len(plaintext)); start, index = start+mediacrypto.ChunkSize, index+1 {
		nonce, err := prepared.Encryption.ChunkNonce(index)
		if err != nil {
			t.Fatal("invalid prepared content nonce")
		}
		end := min(start+mediacrypto.ChunkSize, int64(len(plaintext)))
		ciphertext = aead.Seal(ciphertext, nonce, plaintext[start:end], prepared.Encryption.ChunkAAD(index))
	}
	if int64(len(ciphertext)) != prepared.Encryption.CiphertextSize {
		t.Fatal("driver ciphertext length does not match descriptor")
	}
	return prepared, ciphertext
}

func (browser *fleetBrowserCrypto) decryptGrant(t *testing.T, ctx context.Context, master *fleetSite, name string, expected mediacrypto.Metadata) cipher.AEAD {
	t.Helper()
	code, response, err := master.request(ctx, "POST", "/api/v1/media/admin/crypto/key", map[string]any{"session_id": browser.grant.SessionID, "file_path": name})
	if err != nil || code != 200 {
		t.Fatal("actual HTTP media decrypt grant failed", code, err)
	}
	var grant fleetPreparedCrypto
	fleetCryptoDecode(t, response, &grant)
	if grant.Encryption != expected {
		t.Fatal("playback grant descriptor differs from uploaded media")
	}
	return browser.unwrap(t, grant.Encryption, grant.Envelope)
}

func fleetCipherChunk(t *testing.T, ctx context.Context, sites []*fleetSite, target string, metadata mediacrypto.Metadata, index uint32) []byte {
	t.Helper()
	if strings.HasPrefix(target, "/") {
		target = sites[0].origin + target
	}
	start := int64(index) * (mediacrypto.ChunkSize + 16)
	size := min(mediacrypto.ChunkSize, metadata.PlaintextSize-int64(index)*mediacrypto.ChunkSize) + 16
	for redirects := 0; redirects < 2; redirects++ {
		parsed, err := url.Parse(target)
		if err != nil {
			t.Fatal("invalid private ciphertext URL")
		}
		var owner *fleetSite
		for _, candidate := range sites {
			if parsed.Scheme+"://"+parsed.Host == candidate.origin {
				owner = candidate
				break
			}
		}
		if owner == nil {
			t.Fatal("ciphertext delivery left private fleet")
		}
		request, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			t.Fatal("invalid private ciphertext request")
		}
		request.Header.Set("Origin", sites[0].origin)
		request.Header.Set("Range", "bytes="+strconv.FormatInt(start, 10)+"-"+strconv.FormatInt(start+size-1, 10))
		response, err := owner.client.Do(request)
		if err != nil {
			t.Fatal("verified private ciphertext transport failed")
		}
		if response.StatusCode == 307 && redirects == 0 {
			target = response.Header.Get("Location")
			response.Body.Close()
			continue
		}
		chunk, err := io.ReadAll(io.LimitReader(response.Body, size+1))
		response.Body.Close()
		expected := "bytes " + strconv.FormatInt(start, 10) + "-" + strconv.FormatInt(start+size-1, 10) + "/" + strconv.FormatInt(metadata.CiphertextSize, 10)
		if err != nil || response.StatusCode != 206 || int64(len(chunk)) != size || response.Header.Get("Content-Range") != expected || response.Header.Get("Content-Type") != "application/octet-stream" || !strings.Contains(response.Header.Get("Cache-Control"), "no-store") {
			t.Fatal("real Nginx ciphertext chunk lost Range/type/cache policy", owner.runtime, owner.database, response.StatusCode, len(chunk), response.Header.Get("Content-Type"), response.Header.Get("Cache-Control"), err)
		}
		if response.Header.Get("X-Media-Resource-ID") != "" || response.Header.Get("X-Media-Owner-ID") != "" {
			t.Fatal("ciphertext edge disclosed internal placement metadata")
		}
		if owner != sites[0] && (response.Header.Get("Access-Control-Allow-Origin") != sites[0].origin || !strings.Contains(response.Header.Get("Access-Control-Expose-Headers"), "Content-Range")) {
			t.Fatal("direct ciphertext edge lost paired browser Range CORS")
		}
		return chunk
	}
	t.Fatal("unexpected private ciphertext redirect chain")
	return nil
}

func fleetDecryptCiphertext(t *testing.T, ctx context.Context, sites []*fleetSite, target string, metadata mediacrypto.Metadata, aead cipher.AEAD, expected []byte) {
	t.Helper()
	var decrypted []byte
	for index := uint32(0); int64(index)*metadata.ChunkSize < metadata.PlaintextSize; index++ {
		chunk := fleetCipherChunk(t, ctx, sites, target, metadata, index)
		nonce, err := metadata.ChunkNonce(index)
		if err != nil {
			t.Fatal("prepared encrypted chunk nonce became invalid")
		}
		plaintext, err := aead.Open(nil, nonce, chunk, metadata.ChunkAAD(index))
		if err != nil {
			t.Fatal("real stored ciphertext failed browser-equivalent authentication")
		}
		decrypted = append(decrypted, plaintext...)
	}
	if !bytes.Equal(decrypted, expected) {
		t.Fatal("real native matrix storage changed encrypted media")
	}
}
