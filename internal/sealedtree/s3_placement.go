package sealedtree

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Fixed padding accommodates JSON escaping of the existing S3 proof's
// 1024-byte version and 128-byte ETag, alongside its 768-byte key.
const s3PlacementPayloadBytes = 16384

// S3Placement is Master-only sensitive metadata. It preserves the existing
// provider object key; it neither moves objects nor grants access. Credential
// references identify a separate vault record, never credential material.
type S3Placement struct {
	Version        int                   `json:"version"`
	ObjectID       string                `json:"object_id"`
	MemberID       string                `json:"member_id"`
	ObjectRevision int64                 `json:"object_revision"`
	CreatedAt      int64                 `json:"created_at,omitempty"`
	UpdatedAt      int64                 `json:"updated_at,omitempty"`
	Location       s3store.Config        `json:"location"`
	Proof          store.S3ObjectProof   `json:"proof"`
	Encryption     *mediacrypto.Metadata `json:"encryption,omitempty"`
}

// S3PlacementRecord may only be persisted within an authenticated tree
// transaction and has no plaintext path, provider key, or credential reference.
type S3PlacementRecord struct {
	ObjectIndex string
	Revision    int64
	Sealed      []byte
}

func validS3Placement(p S3Placement) bool {
	if p.Version != 1 || !hexID(p.ObjectID) || !lowerHex(p.MemberID, 32) || p.ObjectRevision < 1 || p.CreatedAt < 0 || p.UpdatedAt < p.CreatedAt {
		return false
	}
	c, err := s3store.Normalize(p.Location)
	if err != nil || c != p.Location {
		return false
	}
	proof := p.Proof
	if proof.MediaID != p.ObjectID || proof.MemberID != p.MemberID || !hexID(proof.ObjectID) || !lowerHex(proof.SessionID, 32) || !store.ValidS3MetadataIdentity(proof.MetadataFormat, proof.Key, proof.MetadataOwner, proof.MediaID, proof.ObjectID) || proof.Bytes < 1 || proof.Bytes > store.S3MaxObjectBytes || proof.ETag == "" || !s3PlacementText(proof.ETag, 128) || !s3PlacementText(proof.VersionID, 1024) {
		return false
	}
	if _, err := c.ProviderKey(proof.Key); err != nil {
		return false
	}
	index := strings.LastIndexByte(proof.CompositeSHA256, '-')
	if index < 1 {
		return false
	}
	digest, err := base64.StdEncoding.Strict().DecodeString(proof.CompositeSHA256[:index])
	parts, numErr := strconv.ParseInt(proof.CompositeSHA256[index+1:], 10, 32)
	if err != nil || len(digest) != 32 || numErr != nil || parts != (proof.Bytes+store.S3PartBytes-1)/store.S3PartBytes || strconv.FormatInt(parts, 10) != proof.CompositeSHA256[index+1:] {
		return false
	}
	return p.Encryption == nil || p.Encryption.Validate() == nil && p.Encryption.CiphertextSize == proof.Bytes
}

func s3PlacementText(value string, limit int) bool {
	if len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// MatchesCurrentMember compares the authenticated member's current canonical
// namespace to the original placement. A caller must obtain the configuration
// and credential revision from the separate encrypted member vault under its
// lease; credential rotation alone never requires rewriting every object.
// This check is not permission to reuse old grants or an endpoint-change
// protocol, and must not be used without the existing provider validation.
func (p S3Placement) MatchesCurrentMember(memberID string, current s3store.Config) bool {
	if !validS3Placement(p) || memberID != p.MemberID {
		return false
	}
	normalized, err := s3store.Normalize(current)
	if err != nil || normalized != current {
		return false
	}
	expected, err := p.Location.Namespace()
	if err != nil {
		return false
	}
	actual, err := current.Namespace()
	return err == nil && actual == expected
}

func s3PlacementAAD(objectIndex string, revision int64) []byte {
	return []byte("frontiercloud:sealed-tree:s3-placement:v1\x00" + objectIndex + "\x00" + strconv.FormatInt(revision, 10))
}

// SealS3Placement encrypts all S3 location and proof fields at fixed length;
// it is not a migration, provider operation, or credential-vault replacement.
func (t *Tree) SealS3Placement(p S3Placement, revision int64) (S3PlacementRecord, error) {
	if t == nil || !t.ready || !validS3Placement(p) || revision < 1 {
		return S3PlacementRecord{}, ErrInvalid
	}
	index, err := t.ObjectIndex(p.ObjectID)
	if err != nil {
		return S3PlacementRecord{}, err
	}
	encoded, err := json.Marshal(p)
	if err != nil || len(encoded) == 0 || len(encoded) > s3PlacementPayloadBytes-2 {
		return S3PlacementRecord{}, ErrInvalid
	}
	defer clear(encoded)
	plain := make([]byte, s3PlacementPayloadBytes)
	defer clear(plain)
	binary.BigEndian.PutUint16(plain[:2], uint16(len(encoded)))
	copy(plain[2:], encoded)
	random := make([]byte, recordSaltBytes+nonceBytes)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return S3PlacementRecord{}, ErrInvalid
	}
	aead, err := t.recordCipher(random[:recordSaltBytes], "s3-placement")
	if err != nil {
		return S3PlacementRecord{}, err
	}
	sealed := append([]byte{recordVersion}, random...)
	sealed = aead.Seal(sealed, random[recordSaltBytes:], plain, s3PlacementAAD(index, revision))
	return S3PlacementRecord{ObjectIndex: index, Revision: revision, Sealed: sealed}, nil
}

// S3PlacementEncryptionID is a nonsecret reservation identifier, not proof
// of authenticity. The future SQL publisher must reserve it transactionally.
func S3PlacementEncryptionID(r S3PlacementRecord) (string, error) {
	if len(r.Sealed) != 1+recordSaltBytes+nonceBytes+s3PlacementPayloadBytes+16 || r.Sealed[0] != recordVersion {
		return "", ErrInvalid
	}
	return hex.EncodeToString(r.Sealed[1 : 1+recordSaltBytes]), nil
}

// OpenS3Placement authenticates tree object and revision bindings. Callers
// must separately verify current scope, credential availability and provider
// authorization under the same appropriate leases.
func (t *Tree) OpenS3Placement(r S3PlacementRecord) (S3Placement, error) {
	if t == nil || !t.ready || !hexID(r.ObjectIndex) || r.Revision < 1 || len(r.Sealed) != 1+recordSaltBytes+nonceBytes+s3PlacementPayloadBytes+16 || r.Sealed[0] != recordVersion {
		return S3Placement{}, ErrInvalid
	}
	salt, nonce := r.Sealed[1:1+recordSaltBytes], r.Sealed[1+recordSaltBytes:1+recordSaltBytes+nonceBytes]
	aead, err := t.recordCipher(salt, "s3-placement")
	if err != nil {
		return S3Placement{}, err
	}
	plain, err := aead.Open(nil, nonce, r.Sealed[1+recordSaltBytes+nonceBytes:], s3PlacementAAD(r.ObjectIndex, r.Revision))
	if err != nil {
		return S3Placement{}, ErrInvalid
	}
	defer clear(plain)
	length := int(binary.BigEndian.Uint16(plain[:2]))
	if length == 0 || length > s3PlacementPayloadBytes-2 {
		return S3Placement{}, ErrInvalid
	}
	for _, value := range plain[2+length:] {
		if value != 0 {
			return S3Placement{}, ErrInvalid
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(plain[2 : 2+length]))
	decoder.DisallowUnknownFields()
	var p S3Placement
	if err := decoder.Decode(&p); err != nil || !validS3Placement(p) {
		return S3Placement{}, ErrInvalid
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return S3Placement{}, ErrInvalid
	}
	index, err := t.ObjectIndex(p.ObjectID)
	if err != nil || !hmac.Equal([]byte(index), []byte(r.ObjectIndex)) {
		return S3Placement{}, ErrInvalid
	}
	return p, nil
}
