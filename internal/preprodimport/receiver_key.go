package preprodimport

// The preproduction import receiver is derived from the preproduction
// Master's existing random node identity, never from production media keys.
// Domain separation keeps it distinct from the Ed25519 signing key. A node
// identity change requires a new receiver and independent source pairing.
import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
)

func receiverFromMasterSeed(seed []byte) (*ecdh.PrivateKey, error) {
	if len(seed) != 32 {
		return nil, invalid("receiver seed")
	}
	zero := make([]byte, 32)
	if hmac.Equal(seed, zero) {
		return nil, invalid("receiver seed")
	}
	extract := hmac.New(sha256.New, []byte("frontiercloud:preprod-receiver:hkdf-extract:v1"))
	extract.Write(seed)
	prk := extract.Sum(nil)
	defer clear(prk)
	expand := hmac.New(sha256.New, prk)
	expand.Write([]byte("frontiercloud:preprod-receiver:x25519:v1\x01"))
	raw := expand.Sum(nil)
	defer clear(raw)
	return ecdh.X25519().NewPrivateKey(raw)
}
