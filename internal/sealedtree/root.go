package sealedtree

import (
	"crypto/rand"
	"encoding/hex"
	"io"
)

const rootPayloadBytes = 64

// SealRoot encrypts a random namespace root ID under the Master-derived tree
// key, so routine restart does not require an operator to provide a root ID.
// The key itself remains independently protected in the Master key store.
func (t *Tree) SealRoot(rootID string) ([]byte, error) {
	if t == nil || !t.ready || !hexID(rootID) {
		return nil, ErrInvalid
	}
	random := make([]byte, recordSaltBytes+nonceBytes)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return nil, ErrInvalid
	}
	aead, err := t.recordCipher(random[:recordSaltBytes], "root")
	if err != nil {
		return nil, err
	}
	sealed := append([]byte{recordVersion}, random...)
	sealed = aead.Seal(sealed, random[recordSaltBytes:], []byte(rootID), []byte("frontiercloud:sealed-tree:root:v1"))
	return sealed, nil
}

// OpenRoot authenticates and recovers the in-memory root identifier. Corrupt
// or mismatched key/salt values fail closed; no new root is generated.
func (t *Tree) OpenRoot(sealed []byte) (string, error) {
	if t == nil || !t.ready || len(sealed) != 1+recordSaltBytes+nonceBytes+rootPayloadBytes+16 || sealed[0] != recordVersion {
		return "", ErrInvalid
	}
	aead, err := t.recordCipher(sealed[1:1+recordSaltBytes], "root")
	if err != nil {
		return "", err
	}
	plain, err := aead.Open(nil, sealed[1+recordSaltBytes:1+recordSaltBytes+nonceBytes], sealed[1+recordSaltBytes+nonceBytes:], []byte("frontiercloud:sealed-tree:root:v1"))
	if err != nil {
		return "", ErrInvalid
	}
	defer clear(plain)
	rootID := string(plain)
	if !hexID(rootID) {
		return "", ErrInvalid
	}
	return rootID, nil
}

func rootEncryptionID(sealed []byte) (string, error) {
	if len(sealed) != 1+recordSaltBytes+nonceBytes+rootPayloadBytes+16 || sealed[0] != recordVersion {
		return "", ErrInvalid
	}
	return hex.EncodeToString(sealed[1 : 1+recordSaltBytes]), nil
}
