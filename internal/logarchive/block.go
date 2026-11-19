package logarchive

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

const magic = "FCLG1\x00"

var ErrBlock = errors.New("invalid encrypted log block")

// Header is retained on the Master, not as plaintext in the remote blob.
type Header struct {
	ID          string `json:"id"`
	MasterID    string `json:"master_id"`
	Kind        Kind   `json:"kind"`
	StartMillis int64  `json:"start_ms"`
	EndMillis   int64  `json:"end_ms"`
}

// Record belongs only to Master storage. Do not serialize it as a node upload
// request. Remote storage receives only the random ID and ciphertext bytes.
type Record struct {
	Header           Header
	CiphertextSHA256 string
	CiphertextBytes  int
	WrappedKey       string
}

type wrappedKey struct {
	HeaderSHA256 string `json:"header_sha256"`
	Key          string `json:"key"`
}

func identifier(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 16 && hex.EncodeToString(b) == s
}

func headerBytes(h Header) ([]byte, error) {
	if !identifier(h.ID) || !identifier(h.MasterID) || !validKind(h.Kind) || h.StartMillis <= 0 || h.EndMillis <= h.StartMillis {
		return nil, ErrBlock
	}
	return json.Marshal(h)
}

func hash(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }

// Seal never writes plaintext. The caller must persist the Master Record and
// publish only the returned ciphertext using the durable archive transaction.
func Seal(master *vault.Vault, masterID string, kind Kind, start, end time.Time, plain []byte) (Record, []byte, error) {
	if master == nil || len(plain) == 0 || len(plain) > MaxPlainBytes {
		return Record{}, nil, ErrBlock
	}
	var id [16]byte
	var key [32]byte
	if _, e := rand.Read(id[:]); e != nil {
		return Record{}, nil, e
	}
	if _, e := rand.Read(key[:]); e != nil {
		return Record{}, nil, e
	}
	defer clear(key[:])
	h := Header{ID: hex.EncodeToString(id[:]), MasterID: masterID, Kind: kind, StartMillis: start.UnixMilli(), EndMillis: end.UnixMilli()}
	aad, e := headerBytes(h)
	if e != nil {
		return Record{}, nil, e
	}
	block, e := aes.NewCipher(key[:])
	if e != nil {
		return Record{}, nil, e
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil {
		return Record{}, nil, e
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return Record{}, nil, e
	}
	payload := append([]byte(magic), nonce...)
	payload = gcm.Seal(payload, nonce, plain, aad)
	keyJSON, e := json.Marshal(wrappedKey{HeaderSHA256: hash(aad), Key: base64.RawURLEncoding.EncodeToString(key[:])})
	if e != nil {
		return Record{}, nil, e
	}
	sealed, e := master.Seal(string(keyJSON))
	if e != nil {
		return Record{}, nil, e
	}
	return Record{Header: h, CiphertextSHA256: hash(payload), CiphertextBytes: len(payload), WrappedKey: sealed}, payload, nil
}

// UnwrapForMaster requires the existing Master vault. The archive node has no
// wrapped key or corresponding vault. HTTP grant authentication and expiry are
// separate admission checks and must precede any browser delivery of this key.
func UnwrapForMaster(master *vault.Vault, record Record) ([32]byte, error) {
	var result [32]byte
	aad, e := headerBytes(record.Header)
	if e != nil || master == nil || len(record.WrappedKey) > 4096 {
		return result, ErrBlock
	}
	raw, e := master.Unseal(record.WrappedKey)
	if e != nil {
		return result, ErrBlock
	}
	var wrapped wrappedKey
	if json.Unmarshal([]byte(raw), &wrapped) != nil || wrapped.HeaderSHA256 != hash(aad) {
		return result, ErrBlock
	}
	key, e := base64.RawURLEncoding.DecodeString(wrapped.Key)
	if e != nil || len(key) != len(result) {
		return result, ErrBlock
	}
	copy(result[:], key)
	clear(key)
	return result, nil
}

// OpenForMaster is for the authenticated Master terminal path, never a remote
// node RPC. Plaintext exists only in the caller's bounded memory/output stream.
func OpenForMaster(master *vault.Vault, record Record, payload []byte) ([]byte, error) {
	if len(payload) != record.CiphertextBytes || len(payload) <= len(magic)+12+16 || len(payload) > MaxPlainBytes+len(magic)+12+16 || string(payload[:len(magic)]) != magic || hash(payload) != record.CiphertextSHA256 {
		return nil, ErrBlock
	}
	key, e := UnwrapForMaster(master, record)
	if e != nil {
		return nil, e
	}
	defer clear(key[:])
	block, e := aes.NewCipher(key[:])
	if e != nil {
		return nil, ErrBlock
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil {
		return nil, ErrBlock
	}
	aad, e := headerBytes(record.Header)
	if e != nil {
		return nil, ErrBlock
	}
	nonce := payload[len(magic) : len(magic)+gcm.NonceSize()]
	plain, e := gcm.Open(nil, nonce, payload[len(magic)+gcm.NonceSize():], aad)
	if e != nil {
		return nil, ErrBlock
	}
	return plain, nil
}
