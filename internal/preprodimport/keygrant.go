package preprodimport

// This file contains unconnected primitives for a future media-only import.
// It does not expose a production key exporter, change the runtime key
// resolver, or make a preproduction deployment safe to activate.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"golang.org/x/crypto/hkdf"
)

// keyScope is authorized one object at a time by the future source-side
// protocol, not by a caller-controlled browser request. It contains no paths.
type keyScope struct {
	Version         int                  `json:"version"`
	SourceNode      string               `json:"source_node"`
	SourceKeyID     string               `json:"source_key_id"`
	TargetNode      string               `json:"target_node"`
	Snapshot        string               `json:"snapshot"`
	MediaID         string               `json:"media_id"`
	SourceObjectID  string               `json:"source_object_id"`
	TargetOwnerID   string               `json:"target_owner_id"`
	TargetBlobID    string               `json:"target_blob_id"`
	TargetReadAlias string               `json:"target_read_alias"`
	ContentSHA256   string               `json:"content_sha256"`
	StoredBytes     int64                `json:"stored_bytes"`
	Challenge       string               `json:"challenge"`
	IssuedUnix      int64                `json:"issued_unix"`
	ExpiresUnix     int64                `json:"expires_unix"`
	Descriptor      mediacrypto.Metadata `json:"descriptor"`
}

func (s keyScope) valid(now time.Time) bool {
	n := now.Unix()
	return s.Version == 1 && id32.MatchString(s.SourceNode) && id64.MatchString(s.SourceKeyID) && id32.MatchString(s.TargetNode) && s.SourceNode != s.TargetNode &&
		id64.MatchString(s.Snapshot) && id64.MatchString(s.MediaID) && id64.MatchString(s.SourceObjectID) && id32.MatchString(s.TargetOwnerID) && id64.MatchString(s.TargetBlobID) && s.TargetBlobID != s.SourceObjectID && s.TargetBlobID != s.MediaID && id64.MatchString(s.TargetReadAlias) && s.TargetReadAlias != s.TargetBlobID && s.TargetReadAlias != s.SourceObjectID && s.TargetReadAlias != s.MediaID && id64.MatchString(s.ContentSHA256) && id64.MatchString(s.Challenge) &&
		s.IssuedUnix > 0 && s.IssuedUnix <= n && s.ExpiresUnix > n && s.ExpiresUnix > s.IssuedUnix && s.ExpiresUnix-s.IssuedUnix <= 300 && s.Descriptor.Validate() == nil && s.StoredBytes == s.Descriptor.CiphertextSize
}

type keyGrant struct {
	Ephemeral     []byte `json:"ephemeral"`
	ScopeHash     []byte `json:"scope_hash"`
	KeyCommitment []byte `json:"key_commitment"`
	Nonce         []byte `json:"nonce"`
	Cipher        []byte `json:"cipher"`
	Signature     []byte `json:"signature"`
}
type keyProof struct {
	Grant        keyGrant `json:"grant"`
	SourcePublic []byte   `json:"source_public"`
	TargetPublic []byte   `json:"target_public"`
}
type grantPayload struct {
	Scope keyScope `json:"scope"`
	Key   []byte   `json:"key"`
}
type vaultPayload struct {
	Scope keyScope `json:"scope"`
	Key   []byte   `json:"key"`
	Proof keyProof `json:"proof"`
}

func scopeDigest(s keyScope) ([]byte, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, invalid("scope encoding")
	}
	sum := sha256.Sum256(raw)
	return sum[:], nil
}

// File keys are 256-bit HMAC outputs; their resistance to guessing depends on
// a high-entropy premaster, whose provenance is an external hard gate. This
// commitment binds a scope and key; it does not protect weak root secrets.
func fileKeyCommitment(scopeHash, fileKey []byte) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("frontiercloud:preprod-file-key-commitment:v1\x00"))
	_, _ = h.Write(scopeHash)
	_, _ = h.Write(fileKey)
	return h.Sum(nil)
}

func grantContext(ephemeral, target []byte) []byte {
	return bytes.Join([][]byte{[]byte("frontiercloud:preprod-file-grant:v1\x00"), ephemeral, target}, nil)
}
func deriveGrantKey(shared, context []byte) ([]byte, error) {
	salt := sha256.Sum256(context)
	out := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, salt[:], []byte("preprod-file-grant-key-v1")), out); err != nil {
		clear(out)
		return nil, invalid("key derivation")
	}
	return out, nil
}
func grantSigned(g keyGrant, target []byte) []byte {
	return bytes.Join([][]byte{grantContext(g.Ephemeral, target), g.ScopeHash, g.KeyCommitment, g.Nonce, g.Cipher}, nil)
}
func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, invalid("cipher")
	}
	return cipher.NewGCM(b)
}

// sealFileKey is deliberately package-private. A future production exporter
// must first authorize an immutable source manifest and exact target identity;
// possession of this helper alone does not establish that authority.
func sealFileKey(scope keyScope, fileKey []byte, target *ecdh.PublicKey, signer ed25519.PrivateKey, now time.Time) (keyGrant, error) {
	var result keyGrant
	if !scope.valid(now) || len(fileKey) != 32 || target == nil || len(signer) != ed25519.PrivateKeySize {
		return result, invalid("grant input")
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return result, invalid("ephemeral key")
	}
	shared, err := ephemeral.ECDH(target)
	if err != nil {
		return result, invalid("target key")
	}
	defer clear(shared)
	result.Ephemeral = ephemeral.PublicKey().Bytes()
	result.ScopeHash, err = scopeDigest(scope)
	if err != nil {
		return keyGrant{}, err
	}
	result.KeyCommitment = fileKeyCommitment(result.ScopeHash, fileKey)
	context := grantContext(result.Ephemeral, target.Bytes())
	key, err := deriveGrantKey(shared, context)
	if err != nil {
		return keyGrant{}, err
	}
	defer clear(key)
	aead, err := gcm(key)
	if err != nil {
		return keyGrant{}, err
	}
	result.Nonce = make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, result.Nonce); err != nil {
		return keyGrant{}, invalid("nonce")
	}
	plain, err := json.Marshal(grantPayload{Scope: scope, Key: fileKey})
	if err != nil {
		return keyGrant{}, invalid("payload")
	}
	defer clear(plain)
	result.Cipher = aead.Seal(nil, result.Nonce, plain, context)
	result.Signature = ed25519.Sign(signer, grantSigned(result, target.Bytes()))
	return result, nil
}

// sealDerivedFileKey prevents a future trusted source path from accepting an
// arbitrary caller-provided key: it must derive the key from the matching
// source Manager and the exact signed descriptor. It still has no production
// authorization, snapshot admission or transport wiring.
func sealDerivedFileKey(scope keyScope, manager *mediacrypto.Manager, target *ecdh.PublicKey, signer ed25519.PrivateKey, now time.Time) (keyGrant, error) {
	if manager == nil || subtle.ConstantTimeCompare([]byte(scope.SourceKeyID), []byte(manager.KeyID())) != 1 {
		return keyGrant{}, invalid("source media key identity")
	}
	fileKey, err := manager.FileKey(scope.Descriptor)
	if err != nil {
		return keyGrant{}, invalid("source file key")
	}
	defer clear(fileKey)
	return sealFileKey(scope, fileKey, target, signer, now)
}

// openFileKey validates the independently supplied expected object scope and
// pinned source signer before releasing the derived file key into memory.
// It does not consume a replay token or persist data; those must be atomic.
func openFileKey(g keyGrant, expected keyScope, target *ecdh.PrivateKey, signer ed25519.PublicKey, now time.Time) ([]byte, error) {
	if target == nil || len(signer) != ed25519.PublicKeySize || len(g.Ephemeral) != 32 || len(g.ScopeHash) != 32 || len(g.KeyCommitment) != 32 || len(g.Nonce) != 12 || len(g.Cipher) < 16 || len(g.Cipher) > 4096 || len(g.Signature) != ed25519.SignatureSize || !expected.valid(now) {
		return nil, invalid("grant envelope")
	}
	expectedHash, err := scopeDigest(expected)
	if err != nil || subtle.ConstantTimeCompare(g.ScopeHash, expectedHash) != 1 {
		return nil, invalid("grant scope digest")
	}
	if !ed25519.Verify(signer, grantSigned(g, target.PublicKey().Bytes()), g.Signature) {
		return nil, invalid("grant signature")
	}
	public, err := ecdh.X25519().NewPublicKey(g.Ephemeral)
	if err != nil {
		return nil, invalid("ephemeral key")
	}
	shared, err := target.ECDH(public)
	if err != nil {
		return nil, invalid("shared key")
	}
	defer clear(shared)
	context := grantContext(g.Ephemeral, target.PublicKey().Bytes())
	key, err := deriveGrantKey(shared, context)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, g.Nonce, g.Cipher, context)
	if err != nil {
		return nil, invalid("grant authentication")
	}
	defer clear(plain)
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	var payload grantPayload
	defer func() { clear(payload.Key) }()
	if err = d.Decode(&payload); err != nil {
		return nil, invalid("grant payload")
	}
	var extra any
	if err = d.Decode(&extra); !errors.Is(err, io.EOF) || len(payload.Key) != 32 || payload.Scope != expected || subtle.ConstantTimeCompare(g.KeyCommitment, fileKeyCommitment(g.ScopeHash, payload.Key)) != 1 {
		return nil, invalid("grant scope")
	}
	return append([]byte(nil), payload.Key...), nil
}

// keyVaultRow contains keyed tags and authenticated ciphertext only. The
// master, transfer and tree secrets must be generated independently.
type keyVaultRow struct {
	ObjectTag string
	GrantTag  string
	FileTag   string
	Salt      []byte
	Nonce     []byte
	Cipher    []byte
}

const vaultPayloadBytes = 4096

// newVaultRoot is intentionally separate from media premaster and tree key
// derivation. Persisting, backing up and binding this secret to a target
// identity is a required future integration step, not implemented here.
func newVaultRoot() ([]byte, error) {
	root := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, root); err != nil || bytes.Equal(root, make([]byte, 32)) {
		clear(root)
		return nil, invalid("vault root generation")
	}
	return root, nil
}

func vaultTag(root []byte, label, value string) string {
	m := hmac.New(sha256.New, root)
	_, _ = m.Write([]byte("frontiercloud:preprod-key-vault:" + label + ":v1\x00" + value))
	return hex.EncodeToString(m.Sum(nil))
}

func verifyKeyProof(proof keyProof, scope keyScope, source ed25519.PublicKey, target []byte) error {
	g := proof.Grant
	if len(source) != ed25519.PublicKeySize || len(target) != 32 || len(proof.SourcePublic) != ed25519.PublicKeySize || len(proof.TargetPublic) != 32 || len(g.Ephemeral) != 32 || len(g.ScopeHash) != 32 || len(g.KeyCommitment) != 32 || len(g.Nonce) != 12 || len(g.Cipher) < 16 || len(g.Cipher) > 4096 || len(g.Signature) != ed25519.SignatureSize || subtle.ConstantTimeCompare(proof.SourcePublic, source) != 1 || subtle.ConstantTimeCompare(proof.TargetPublic, target) != 1 {
		return invalid("vault source proof")
	}
	hash, err := scopeDigest(scope)
	if err != nil || subtle.ConstantTimeCompare(g.ScopeHash, hash) != 1 || !ed25519.Verify(source, grantSigned(g, target), g.Signature) {
		return invalid("vault source signature")
	}
	return nil
}

func sealVaultKey(root []byte, scope keyScope, fileKey []byte, proof keyProof) (keyVaultRow, error) {
	var row keyVaultRow
	if len(root) != 32 || bytes.Equal(root, make([]byte, 32)) || len(fileKey) != 32 {
		return row, invalid("vault input")
	}
	if err := verifyKeyProof(proof, scope, ed25519.PublicKey(proof.SourcePublic), proof.TargetPublic); err != nil {
		return row, err
	}
	if subtle.ConstantTimeCompare(proof.Grant.KeyCommitment, fileKeyCommitment(proof.Grant.ScopeHash, fileKey)) != 1 {
		return row, invalid("vault key commitment")
	}
	row.ObjectTag = vaultTag(root, "object", scope.MediaID)
	row.GrantTag = vaultTag(root, "grant", scope.Snapshot+scope.Challenge+scope.MediaID)
	row.FileTag = vaultTag(root, "file", scope.Descriptor.FileID)
	row.Salt = make([]byte, 32)
	row.Nonce = make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, row.Salt); err != nil {
		return keyVaultRow{}, invalid("vault salt")
	}
	if _, err := io.ReadFull(rand.Reader, row.Nonce); err != nil {
		return keyVaultRow{}, invalid("vault nonce")
	}
	derived := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, root, row.Salt, []byte("frontiercloud:preprod-key-vault:row:v1")), derived); err != nil {
		return keyVaultRow{}, invalid("vault key")
	}
	defer clear(derived)
	aead, err := gcm(derived)
	if err != nil {
		return keyVaultRow{}, err
	}
	encoded, err := json.Marshal(vaultPayload{Scope: scope, Key: fileKey, Proof: proof})
	if err != nil {
		return keyVaultRow{}, invalid("vault payload")
	}
	defer clear(encoded)
	if len(encoded) == 0 || len(encoded) > vaultPayloadBytes-2 {
		return keyVaultRow{}, invalid("vault payload size")
	}
	plain := make([]byte, vaultPayloadBytes)
	defer clear(plain)
	binary.BigEndian.PutUint16(plain[:2], uint16(len(encoded)))
	copy(plain[2:], encoded)
	row.Cipher = aead.Seal(nil, row.Nonce, plain, []byte(row.ObjectTag+row.GrantTag+row.FileTag))
	return row, nil
}

// decodeVaultRow authenticates a persisted row and its original signed proof.
// Its caller must clear the returned key and must not expose it to a peer.
func decodeVaultRow(root []byte, row keyVaultRow, source ed25519.PublicKey, target []byte) (vaultPayload, error) {
	var payload vaultPayload
	if len(root) != 32 || bytes.Equal(root, make([]byte, 32)) || len(row.Salt) != 32 || len(row.Nonce) != 12 || len(row.Cipher) != vaultPayloadBytes+16 || !id64.MatchString(row.ObjectTag) || !id64.MatchString(row.GrantTag) || !id64.MatchString(row.FileTag) {
		return payload, invalid("vault row")
	}
	derived := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, root, row.Salt, []byte("frontiercloud:preprod-key-vault:row:v1")), derived); err != nil {
		return payload, invalid("vault derivation")
	}
	defer clear(derived)
	aead, err := gcm(derived)
	if err != nil {
		return payload, err
	}
	plain, err := aead.Open(nil, row.Nonce, row.Cipher, []byte(row.ObjectTag+row.GrantTag+row.FileTag))
	if err != nil {
		return payload, invalid("vault authentication")
	}
	defer clear(plain)
	length := int(binary.BigEndian.Uint16(plain[:2]))
	if length == 0 || length > vaultPayloadBytes-2 {
		return payload, invalid("vault payload length")
	}
	for _, value := range plain[2+length:] {
		if value != 0 {
			return payload, invalid("vault payload padding")
		}
	}
	d := json.NewDecoder(bytes.NewReader(plain[2 : 2+length]))
	d.DisallowUnknownFields()
	if err = d.Decode(&payload); err != nil {
		clear(payload.Key)
		return vaultPayload{}, invalid("vault payload")
	}
	var extra any
	if err = d.Decode(&extra); !errors.Is(err, io.EOF) || len(payload.Key) != 32 || !payload.Scope.valid(time.Unix(payload.Scope.IssuedUnix, 0)) {
		clear(payload.Key)
		return vaultPayload{}, invalid("vault scope")
	}
	scope := payload.Scope
	if subtle.ConstantTimeCompare([]byte(row.ObjectTag), []byte(vaultTag(root, "object", scope.MediaID))) != 1 || subtle.ConstantTimeCompare([]byte(row.GrantTag), []byte(vaultTag(root, "grant", scope.Snapshot+scope.Challenge+scope.MediaID))) != 1 || subtle.ConstantTimeCompare([]byte(row.FileTag), []byte(vaultTag(root, "file", scope.Descriptor.FileID))) != 1 {
		clear(payload.Key)
		return vaultPayload{}, invalid("vault binding")
	}
	if err = verifyKeyProof(payload.Proof, scope, source, target); err != nil {
		clear(payload.Key)
		return vaultPayload{}, err
	}
	if subtle.ConstantTimeCompare(payload.Proof.Grant.KeyCommitment, fileKeyCommitment(payload.Proof.Grant.ScopeHash, payload.Key)) != 1 {
		clear(payload.Key)
		return vaultPayload{}, invalid("vault key commitment")
	}
	return payload, nil
}

// openVaultKey still requires an independently authorized exact scope. Grant
// expiry controls import delivery, not the lifetime of a stored media key.
func openVaultKey(root []byte, row keyVaultRow, expected keyScope, source ed25519.PublicKey, target []byte) ([]byte, error) {
	payload, err := decodeVaultRow(root, row, source, target)
	if err != nil {
		return nil, err
	}
	defer clear(payload.Key)
	if payload.Scope != expected {
		return nil, invalid("vault scope")
	}
	return append([]byte(nil), payload.Key...), nil
}
