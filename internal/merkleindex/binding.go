package merkleindex

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
)

const Algorithm = "fc-sha256-merkle-1m-1024-v1"

// Binding is a canonical, name-free description for a Master-authenticated
// capability and encrypted placement. It is a digest input, not a signature
// or an authorization decision. A caller must independently authenticate it
// and retain the relevant relationship, resource and tree leases.
type Binding struct {
	MasterID, OwnerID, RelationshipID  string
	Alias, Blob, BasePlacementRevision string
	Manifest                           Manifest
}

func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func appendField(h hash.Hash, value string) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	_, _ = h.Write(size[:])
	_, _ = h.Write([]byte(value))
}

// Digest computes a domain-separated deterministic binding. Every textual
// field is UTF-8 with a four-byte big-endian length, size is big-endian uint64,
// and the three digest fields are raw 32-byte values in manifest order.
func (b Binding) Digest() (Hash, error) {
	validRelationship := b.MasterID == b.OwnerID && b.RelationshipID == "" || b.MasterID != b.OwnerID && lowerHex(b.RelationshipID, 32)
	if !lowerHex(b.MasterID, 32) || !lowerHex(b.OwnerID, 32) || !validRelationship ||
		!lowerHex(b.Alias, 64) || !lowerHex(b.Blob, 64) || b.Alias == b.Blob || !lowerHex(b.BasePlacementRevision, 64) || !validManifest(b.Manifest) {
		return Hash{}, ErrInvalid
	}
	h := sha256.New()
	_, _ = h.Write([]byte("frontiercloud:opaque-index-manifest:v1\x00"))
	for _, v := range []string{Algorithm, b.MasterID, b.OwnerID, b.RelationshipID, b.Alias, b.Blob, b.BasePlacementRevision} {
		appendField(h, v)
	}
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(b.Manifest.Size))
	_, _ = h.Write(size[:])
	_, _ = h.Write(b.Manifest.ContentSHA256[:])
	_, _ = h.Write(b.Manifest.Root[:])
	_, _ = h.Write(b.Manifest.Version[:])
	var result Hash
	copy(result[:], h.Sum(nil))
	return result, nil
}

// AuthorizationRevision is a distinct revision for owner registration,
// capabilities and revocation. Its input base revision must not include the
// index binding, which avoids a cyclic revision definition. This helper does
// not install any such registration or make an old capability valid.
func (b Binding) AuthorizationRevision() (Hash, error) {
	binding, err := b.Digest()
	if err != nil {
		return Hash{}, err
	}
	base, err := hex.DecodeString(b.BasePlacementRevision)
	if err != nil || len(base) != sha256.Size {
		return Hash{}, ErrInvalid
	}
	h := sha256.New()
	_, _ = h.Write([]byte("frontiercloud:opaque-index-authorization-revision:v1\x00"))
	_, _ = h.Write(base)
	_, _ = h.Write(binding[:])
	var result Hash
	copy(result[:], h.Sum(nil))
	return result, nil
}
