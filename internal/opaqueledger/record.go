// Package opaqueledger contains the shared, Master-only encrypted ledger
// record codec. It does not grant authority or commit any database operation.
package opaqueledger

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"regexp"
)

var ErrInvalid = errors.New("invalid opaque ledger record")
var hashID = regexp.MustCompile(`^[a-f0-9]{64}$`)

func ValidKey(key []byte) bool { return len(key) == 32 && !bytes.Equal(key, make([]byte, 32)) }

func MAC(key []byte, domain string, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte("frontiercloud:opaque-capacity:" + domain + ":v1\x00"))
	h.Write(data)
	return h.Sum(nil)
}

func Verifier(key []byte) string {
	return hex.EncodeToString(MAC(key, "verifier", nil))
}

// Seal uses a fresh random record key and nonce; index and encryption ID are
// authenticated. Callers must reserve the returned ID in their transaction.
func Seal(key []byte, index string, raw []byte) (string, []byte, error) {
	if !ValidKey(key) || !hashID.MatchString(index) || len(raw) == 0 || len(raw) > 1022 {
		return "", nil, ErrInvalid
	}
	plain := make([]byte, 1024)
	defer clear(plain)
	binary.BigEndian.PutUint16(plain[:2], uint16(len(raw)))
	copy(plain[2:], raw)
	random := make([]byte, 44)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return "", nil, err
	}
	derived := MAC(key, "cipher", random[:32])
	defer clear(derived)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return "", nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, err
	}
	id := hex.EncodeToString(MAC(key, "encryption-id", random))
	sealed := append([]byte{1}, random...)
	sealed = aead.Seal(sealed, random[32:], plain, []byte(index+":"+id))
	return id, sealed, nil
}

func Open(key []byte, index, id string, sealed []byte) ([]byte, error) {
	if !ValidKey(key) || len(sealed) != 1+44+1024+16 || sealed[0] != 1 || !hashID.MatchString(index) || !hashID.MatchString(id) {
		return nil, ErrInvalid
	}
	random := sealed[1:45]
	if subtle.ConstantTimeCompare([]byte(id), []byte(hex.EncodeToString(MAC(key, "encryption-id", random)))) != 1 {
		return nil, ErrInvalid
	}
	derived := MAC(key, "cipher", random[:32])
	defer clear(derived)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, ErrInvalid
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalid
	}
	plain, err := aead.Open(nil, random[32:], sealed[45:], []byte(index+":"+id))
	if err != nil {
		return nil, ErrInvalid
	}
	defer clear(plain)
	n := int(binary.BigEndian.Uint16(plain[:2]))
	if n == 0 || n > len(plain)-2 {
		return nil, ErrInvalid
	}
	for _, b := range plain[n+2:] {
		if b != 0 {
			return nil, ErrInvalid
		}
	}
	return append([]byte(nil), plain[2:n+2]...), nil
}
