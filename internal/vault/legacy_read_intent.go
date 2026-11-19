package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
)

// LegacyReadIntentIndexes returns opaque domain-separated indexes, not an
// authorization or evidence of a current relationship.
func (v *Vault) LegacyReadIntentIndexes(operation, challenge string) (string, string, error) {
	var zero [32]byte
	if v == nil || subtle.ConstantTimeCompare(v.key[:], zero[:]) == 1 || !s3HexID(operation, 32) || !s3HexID(challenge, 64) {
		return "", "", ErrInvalidToken
	}
	tag := func(domain, value string) string {
		m := hmac.New(sha256.New, v.key[:])
		_, _ = m.Write([]byte(domain))
		_, _ = m.Write([]byte(value))
		return hex.EncodeToString(m.Sum(nil))
	}
	return tag("frontiercloud:legacy-read-intent:operation:v1\x00", operation), tag("frontiercloud:legacy-read-intent:challenge:v1\x00", challenge), nil
}

// LegacyReadHeadIndexes identifies the single sealed current pointer for a
// relationship without exposing the relationship ID in its SQL key.
func (v *Vault) LegacyReadHeadIndexes(relationship string) (string, string, error) {
	var zero [32]byte
	if v == nil || subtle.ConstantTimeCompare(v.key[:], zero[:]) == 1 || !s3HexID(relationship, 32) {
		return "", "", ErrInvalidToken
	}
	tag := func(domain string) string {
		m := hmac.New(sha256.New, v.key[:])
		_, _ = m.Write([]byte(domain))
		_, _ = m.Write([]byte(relationship))
		return hex.EncodeToString(m.Sum(nil))
	}
	return tag("frontiercloud:legacy-read-intent:head-index:v1\x00"), tag("frontiercloud:legacy-read-intent:head-tag:v1\x00"), nil
}

func (v *Vault) LegacyReadAnchorIndexes(relationship string) (string, string, error) {
	var zero [32]byte
	if v == nil || subtle.ConstantTimeCompare(v.key[:], zero[:]) == 1 || !s3HexID(relationship, 32) {
		return "", "", ErrInvalidToken
	}
	tag := func(domain string) string {
		m := hmac.New(sha256.New, v.key[:])
		_, _ = m.Write([]byte(domain))
		_, _ = m.Write([]byte(relationship))
		return hex.EncodeToString(m.Sum(nil))
	}
	return tag("frontiercloud:legacy-read-intent:anchor-index:v1\x00"), tag("frontiercloud:legacy-read-intent:anchor-tag:v1\x00"), nil
}

func (v *Vault) legacyReadIntentAEAD(index, challengeTag string, revision int64) (cipher.AEAD, []byte, error) {
	var zero [32]byte
	if v == nil || subtle.ConstantTimeCompare(v.key[:], zero[:]) == 1 || !s3HexID(index, 64) || !s3HexID(challengeTag, 64) || revision <= 0 {
		return nil, nil, ErrInvalidToken
	}
	m := hmac.New(sha256.New, v.key[:])
	_, _ = m.Write([]byte("frontiercloud:legacy-read-intent:seal-key:v1\x00"))
	key := m.Sum(nil)
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, ErrInvalidToken
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, ErrInvalidToken
	}
	aad := append([]byte("frontiercloud:legacy-read-intent:record:v1\x00"), []byte(index)...)
	aad = append(aad, []byte(challengeTag)...)
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(revision))
	aad = append(aad, encoded[:]...)
	return aead, aad, nil
}

// SealLegacyReadIntent uses a fresh random nonce under a key dedicated to
// this table. The caller must enforce nonce uniqueness in the transaction.
func (v *Vault) SealLegacyReadIntent(index, challengeTag string, revision int64, plaintext []byte) ([]byte, []byte, error) {
	if len(plaintext) == 0 || len(plaintext) > 16*1024 {
		return nil, nil, ErrInvalidToken
	}
	aead, aad, err := v.legacyReadIntentAEAD(index, challengeTag, revision)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, plaintext, aad), nil
}

func (v *Vault) OpenLegacyReadIntent(index, challengeTag string, revision int64, nonce, ciphertext []byte) ([]byte, error) {
	aead, aad, err := v.legacyReadIntentAEAD(index, challengeTag, revision)
	if err != nil || len(nonce) != 12 || len(ciphertext) < 16 || len(ciphertext) > 16*1024+16 {
		return nil, ErrInvalidToken
	}
	out, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil || len(out) == 0 {
		return nil, ErrInvalidToken
	}
	return out, nil
}
