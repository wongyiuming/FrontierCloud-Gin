package preprodimport

// This isolated compatibility primitive follows the P-256 admin key envelope
// present in source commit 64901e2f. It is not a transport, an authorization,
// a source signature, or a vault-commit permit. The caller must authenticate
// the source connection and operator independently, bind the returned
// metadata to a trusted source snapshot and keep the resulting key in trusted
// memory only until a separately authorized vault transaction commits.
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"golang.org/x/crypto/hkdf"
)

type legacyReceiver struct{ private *ecdh.PrivateKey }

func newLegacyReceiver() (*legacyReceiver, string, error) {
	private, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", invalid("legacy receiver")
	}
	return &legacyReceiver{private}, base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()), nil
}

// open checks the exact snapshot descriptor, the source session deadline and
// the original envelope AAD. Metadata and a valid GCM tag authenticate this
// response only to the established session, not to a source signing key.
func (r *legacyReceiver) open(grant mediacrypto.SessionGrant, response, expected mediacrypto.Metadata, envelope mediacrypto.KeyEnvelope, now time.Time) ([]byte, error) {
	if r == nil || r.private == nil || now.IsZero() || expected.Validate() != nil || response.Validate() != nil || response != expected || grant.ExpiresAt <= now.Unix() || grant.ExpiresAt-now.Unix() > int64(mediacrypto.SessionLifetime/time.Second) || grant.ExpiresIn <= 0 || grant.ExpiresIn > int64(mediacrypto.SessionLifetime/time.Second) || envelope.ExpiresAt != grant.ExpiresAt {
		return nil, invalid("legacy grant")
	}
	id, err := hex.DecodeString(grant.SessionID)
	if err != nil || len(id) != 16 || hex.EncodeToString(id) != grant.SessionID {
		return nil, invalid("legacy session")
	}
	pubBytes, err := base64.StdEncoding.Strict().DecodeString(grant.PublicKey)
	if err != nil {
		return nil, invalid("legacy source key")
	}
	pub, err := ecdh.P256().NewPublicKey(pubBytes)
	if err != nil {
		return nil, invalid("legacy source key")
	}
	shared, err := r.private.ECDH(pub)
	if err != nil {
		return nil, invalid("legacy agreement")
	}
	defer clear(shared)
	salt, err := base64.StdEncoding.Strict().DecodeString(grant.Salt)
	if err != nil || len(salt) != 32 {
		return nil, invalid("legacy salt")
	}
	key := make([]byte, 32)
	defer clear(key)
	if _, err = io.ReadFull(hkdf.New(sha256.New, shared, salt, []byte("frontiercloud:browser-wrap:v1:"+grant.SessionID)), key); err != nil {
		return nil, invalid("legacy derivation")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, invalid("legacy cipher")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, invalid("legacy cipher")
	}
	iv, err := base64.StdEncoding.Strict().DecodeString(envelope.IV)
	if err != nil || len(iv) != aead.NonceSize() {
		return nil, invalid("legacy nonce")
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(envelope.WrappedKey)
	if err != nil || len(ciphertext) != 32+aead.Overhead() {
		return nil, invalid("legacy envelope")
	}
	plain, err := aead.Open(nil, iv, ciphertext, []byte("frontiercloud:key-envelope:v1:"+grant.SessionID+":"+expected.FileID))
	if err != nil || len(plain) != 32 {
		clear(plain)
		return nil, invalid("legacy envelope")
	}
	return plain, nil
}
