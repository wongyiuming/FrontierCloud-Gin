// Package snapshotcrypt protects the source snapshot in transit and at rest.
// Authentication of the source identity is a separate, required signature
// check against an independently provisioned pin after decryption.
package snapshotcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"golang.org/x/crypto/hkdf"
)

var errEnvelope = errors.New("invalid media source envelope")

func contextBytes(ephemeral, target []byte) []byte {
	return bytes.Join([][]byte{[]byte("frontiercloud:preprod-source-envelope:v1\x00"), ephemeral, target}, nil)
}

func makeAEAD(shared, context []byte) (cipher.AEAD, error) {
	salt := sha256.Sum256(context)
	key := make([]byte, 32)
	defer clear(key)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, salt[:], []byte("preprod-source-envelope-key-v1")), key); err != nil {
		return nil, errEnvelope
	}
	b, err := aes.NewCipher(key)
	if err != nil { return nil, errEnvelope }
	return cipher.NewGCM(b)
}

func Seal(s store.SignedMediaSourceSnapshot, target []byte) (store.EncryptedMediaSourceSnapshot, error) {
	var empty store.EncryptedMediaSourceSnapshot
	if len(target) != 32 || subtle.ConstantTimeCompare(target, s.Snapshot.TargetReceiver) != 1 {
		return empty, errEnvelope
	}
	public, err := ecdh.X25519().NewPublicKey(target)
	if err != nil { return empty, errEnvelope }
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil { return empty, errEnvelope }
	shared, err := ephemeral.ECDH(public)
	if err != nil { return empty, errEnvelope }
	defer clear(shared)
	eph := ephemeral.PublicKey().Bytes()
	context := contextBytes(eph, target)
	aead, err := makeAEAD(shared, context)
	if err != nil { return empty, err }
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > 16*1024*1024+4096 { return empty, errEnvelope }
	defer clear(raw)
	nonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil { return empty, errEnvelope }
	return store.EncryptedMediaSourceSnapshot{Version: 1, Ephemeral: eph, Nonce: nonce, Cipher: aead.Seal(nil, nonce, raw, context)}, nil
}

// Open only decrypts. The caller must verify the contained signature,
// identity, target, challenge, time and exact sections before use.
func Open(e store.EncryptedMediaSourceSnapshot, target *ecdh.PrivateKey) (store.SignedMediaSourceSnapshot, error) {
	var empty store.SignedMediaSourceSnapshot
	if target == nil || e.Version != 1 || len(e.Ephemeral) != 32 || len(e.Nonce) != 12 || len(e.Cipher) < 16 || len(e.Cipher) > 16*1024*1024+4096+16 {
		return empty, errEnvelope
	}
	public, err := ecdh.X25519().NewPublicKey(e.Ephemeral)
	if err != nil { return empty, errEnvelope }
	shared, err := target.ECDH(public)
	if err != nil { return empty, errEnvelope }
	defer clear(shared)
	context := contextBytes(e.Ephemeral, target.PublicKey().Bytes())
	aead, err := makeAEAD(shared, context)
	if err != nil { return empty, err }
	raw, err := aead.Open(nil, e.Nonce, e.Cipher, context)
	if err != nil { return empty, errEnvelope }
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var result store.SignedMediaSourceSnapshot
	if decoder.Decode(&result) != nil { return empty, errEnvelope }
	var extra any
	if decoder.Decode(&extra) != io.EOF || subtle.ConstantTimeCompare(result.Snapshot.TargetReceiver, target.PublicKey().Bytes()) != 1 {
		return empty, errEnvelope
	}
	return result, nil
}

// Object proofs use a separate AEAD domain from the database snapshot.
// The caller must authenticate the signed proof after opening it.
func SealObjectProof(raw, target []byte) (store.EncryptedMediaSourceSnapshot, error) {
	var empty store.EncryptedMediaSourceSnapshot
	if len(raw) == 0 || len(raw) > 1024*1024 || len(target) != 32 { return empty, errEnvelope }
	public, err := ecdh.X25519().NewPublicKey(target)
	if err != nil { return empty, errEnvelope }
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil { return empty, errEnvelope }
	shared, err := ephemeral.ECDH(public)
	if err != nil { return empty, errEnvelope }
	defer clear(shared)
	eph := ephemeral.PublicKey().Bytes()
	context := bytes.Join([][]byte{[]byte("frontiercloud:preprod-source-object-proof:v1\x00"), eph, target}, nil)
	aead, err := makeAEAD(shared, context)
	if err != nil { return empty, err }
	nonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil { return empty, errEnvelope }
	return store.EncryptedMediaSourceSnapshot{Version: 1, Ephemeral: eph, Nonce: nonce, Cipher: aead.Seal(nil, nonce, raw, context)}, nil
}

func OpenObjectProof(e store.EncryptedMediaSourceSnapshot, target *ecdh.PrivateKey) ([]byte, error) {
	if target == nil || e.Version != 1 || len(e.Ephemeral) != 32 || len(e.Nonce) != 12 || len(e.Cipher) < 16 || len(e.Cipher) > 1024*1024+16 { return nil, errEnvelope }
	public, err := ecdh.X25519().NewPublicKey(e.Ephemeral)
	if err != nil { return nil, errEnvelope }
	shared, err := target.ECDH(public)
	if err != nil { return nil, errEnvelope }
	defer clear(shared)
	context := bytes.Join([][]byte{[]byte("frontiercloud:preprod-source-object-proof:v1\x00"), e.Ephemeral, target.PublicKey().Bytes()}, nil)
	aead, err := makeAEAD(shared, context)
	if err != nil { return nil, err }
	raw, err := aead.Open(nil, e.Nonce, e.Cipher, context)
	if err != nil { return nil, errEnvelope }
	return raw, nil
}
