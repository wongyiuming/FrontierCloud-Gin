package vault

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

// S3Binding describes only opaque identifiers. These tags are not an upload
// authorization and are not installed in product startup by this primitive.
type S3Binding struct {
	BlobID, MemberID, MediaID, SessionID string
}

func s3HexID(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// S3BindingTags returns domain-separated keyed values without exporting the
// Master vault key. The first may authenticate an immutable provider key; the
// second may authenticate provider ownership metadata. Correct vault identity,
// durable intent, recovery and authorization are separate required gates.
func (v *Vault) S3BindingTags(binding S3Binding) (keyTag, ownerTag string, err error) {
	if v == nil || !s3HexID(binding.BlobID, 64) || !s3HexID(binding.MemberID, 32) || !s3HexID(binding.MediaID, 64) || !s3HexID(binding.SessionID, 32) || binding.BlobID == binding.MediaID {
		return "", "", errors.New("invalid S3 binding")
	}
	var zero [32]byte
	if subtle.ConstantTimeCompare(v.key[:], zero[:]) == 1 {
		return "", "", errors.New("invalid S3 vault")
	}
	compute := func(domain string) string {
		mac := hmac.New(sha256.New, v.key[:])
		_, _ = mac.Write([]byte(domain))
		for _, value := range []string{binding.BlobID, binding.MemberID, binding.MediaID, binding.SessionID} {
			var length [4]byte
			binary.BigEndian.PutUint32(length[:], uint32(len(value)))
			_, _ = mac.Write(length[:])
			_, _ = mac.Write([]byte(value))
		}
		return hex.EncodeToString(mac.Sum(nil))
	}
	return compute("frontiercloud:s3:key-binding:v1\x00"), compute("frontiercloud:s3:owner-binding:v1\x00"), nil
}

// VerifyS3BindingTags refuses malformed or substituted tags in constant time.
func (v *Vault) VerifyS3BindingTags(binding S3Binding, keyTag, ownerTag string) bool {
	if !s3HexID(keyTag, 64) || !s3HexID(ownerTag, 64) {
		return false
	}
	wantKey, wantOwner, err := v.S3BindingTags(binding)
	if err != nil {
		return false
	}
	keyMatch := subtle.ConstantTimeCompare([]byte(wantKey), []byte(keyTag))
	ownerMatch := subtle.ConstantTimeCompare([]byte(wantOwner), []byte(ownerTag))
	return keyMatch&ownerMatch == 1
}
