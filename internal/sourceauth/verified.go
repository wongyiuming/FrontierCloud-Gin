// Package sourceauth verifies isolated migration observations. Its capability
// is process-local and is not a publication grant or a rollback anchor.
package sourceauth

import (
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/snapshotcrypt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

var ErrInvalid = errors.New("invalid source observation")

// Pin is an expected authority, not proof that the caller obtained it from
// the target vault. The consuming transaction must independently authenticate
// this exact pin and target identity under its real lease.
type Pin struct {
	SourceNode, TargetNode, SourceKeyID, HostKeyDigest, AuthorityKind string
	SourcePublic, TargetReceiver                                      []byte
	Generation                                                        string
}

// Verified has no exported fields or public constructor other than Verify.
// Its zero value is invalid and no serialization grants authorization.
type Verified struct {
	valid                                                             bool
	sourceDigest, ciphertextDigest, generation, challenge             string
	sourceNode, targetNode, sourceKeyID, hostKeyDigest, authorityKind string
	sourcePublic, targetReceiver                                      []byte
	ciphertextVersion                                                 int64
	expiresAt                                                         int64
}

var columns = []struct {
	name   string
	fields []string
}{
	{"objects", []string{"media_id", "object_kind", "media_path", "path_locator", "created_at", "updated_at"}},
	{"placements", []string{"media_id", "storage_member_id", "object_id", "media_path", "object_kind", "size_bytes", "etag", "state", "created_at", "updated_at"}},
	{"visibility", []string{"relative_path", "hidden", "updated_at"}},
	{"playback", []string{"media_id", "media_path", "preference", "play_score", "created_at", "updated_at"}},
	{"lyric_links", []string{"media_id", "media_path", "lyric_id", "lyric_path", "created_at", "updated_at"}},
	{"encryption", []string{"object_kind", "object_id", "file_id", "descriptor_json", "created_at"}},
	{"members", []string{"member_id", "relationship_id", "member_kind", "transport", "storage_enabled", "allocated_bytes", "used_bytes", "reserved_bytes", "physical_free_bytes", "health", "writable", "updated_at"}},
	{"relationships", []string{"relationship_id", "peer_id", "peer_endpoint", "peer_key", "direction", "mode", "state", "created_at"}},
	{"crypto_key_id", []string{"singleton", "key_id", "created_at"}},
}

func hexID(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func boundedEnvelope(e store.EncryptedMediaSourceSnapshot) bool {
	// JSON encodes byte slices as base64; leave fixed overhead below 4 MiB.
	return e.Version == 1 && len(e.Ephemeral) == 32 && len(e.Nonce) == 12 && len(e.Cipher) >= 16 && len(e.Cipher) <= 3*1024*1024-256
}

// Verify checks the actual complete, signed nine-section source snapshot at
// the current process clock, and hashes the actual bounded ciphertext bytes.
// It does not assert the supplied pin was provisioned by a trusted vault, or
// that source rows have been reconciled with the target projection.
func Verify(envelope store.EncryptedMediaSourceSnapshot, receiver *ecdh.PrivateKey, pin Pin, challenge string, version int64) (*Verified, error) {
	if receiver == nil || !boundedEnvelope(envelope) || subtle.ConstantTimeCompare(receiver.PublicKey().Bytes(), pin.TargetReceiver) != 1 {
		return nil, ErrInvalid
	}
	ciphertext, err := json.Marshal(envelope)
	if err != nil || len(ciphertext) == 0 || len(ciphertext) > 4*1024*1024 {
		return nil, ErrInvalid
	}
	defer clear(ciphertext)
	signed, err := snapshotcrypt.Open(envelope, receiver)
	if err != nil {
		return nil, ErrInvalid
	}
	s := signed.Snapshot
	public, err := protocol.Decode(s.SourcePublic)
	now := time.Now().Unix()
	if err != nil || pin.AuthorityKind != "ssh-collector-v1" || !hexID(pin.SourceNode, 32) || !hexID(pin.TargetNode, 32) || !hexID(pin.HostKeyDigest, 64) || !hexID(pin.Generation, 64) || len(pin.SourcePublic) != 32 || len(pin.TargetReceiver) != 32 || !hexID(challenge, 64) || version < 1 || len(ciphertext) == 0 || len(ciphertext) > 4*1024*1024 || s.Version != 1 || s.AuthorityKind != pin.AuthorityKind || s.SourceSSHHostKeySHA256 != pin.HostKeyDigest || s.SourceNode != pin.SourceNode || s.TargetNode != pin.TargetNode || subtle.ConstantTimeCompare(public, pin.SourcePublic) != 1 || subtle.ConstantTimeCompare(s.TargetReceiver, pin.TargetReceiver) != 1 || s.Challenge != challenge || s.IssuedUnix <= 0 || s.IssuedUnix > now || s.ExpiresUnix <= now || s.ExpiresUnix-s.IssuedUnix > 300 || len(s.Sections) != len(columns) {
		return nil, ErrInvalid
	}
	count := 0
	for i, expected := range columns {
		section := s.Sections[i]
		if section.Name != expected.name || len(section.Columns) != len(expected.fields) || section.Rows == nil {
			return nil, ErrInvalid
		}
		for j, name := range expected.fields {
			if section.Columns[j] != name {
				return nil, ErrInvalid
			}
		}
		for _, row := range section.Rows {
			count++
			if count > 25000 || len(row) != len(expected.fields) {
				return nil, ErrInvalid
			}
			for j, cell := range row {
				if cell == nil {
					if !(section.Name == "encryption" && expected.fields[j] == "descriptor_json") && !(section.Name == "members" && expected.fields[j] == "relationship_id") {
						return nil, ErrInvalid
					}
				} else if !utf8.ValidString(*cell) || strings.ContainsRune(*cell, 0) {
					return nil, ErrInvalid
				}
			}
		}
	}
	keys := s.Sections[len(s.Sections)-1].Rows
	if len(keys) != 1 || keys[0][0] == nil || *keys[0][0] != "1" || keys[0][1] == nil || *keys[0][1] != pin.SourceKeyID {
		return nil, ErrInvalid
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > 16*1024*1024 {
		return nil, ErrInvalid
	}
	digest := sha256.Sum256(raw)
	clear(raw)
	sourceDigest := hex.EncodeToString(digest[:])
	if protocol.Verify(s.SourcePublic, map[string]any{"kind": "frontiercloud-preprod-media-source-v1", "sha256": sourceDigest, "source_node": s.SourceNode, "target_node": s.TargetNode, "challenge": s.Challenge}, signed.Signature) != nil || time.Now().Unix() >= s.ExpiresUnix {
		return nil, ErrInvalid
	}
	cipherHash := sha256.Sum256(ciphertext)
	return &Verified{valid: true, sourceDigest: sourceDigest, ciphertextDigest: hex.EncodeToString(cipherHash[:]), generation: pin.Generation, challenge: challenge, sourceNode: pin.SourceNode, targetNode: pin.TargetNode, sourceKeyID: pin.SourceKeyID, hostKeyDigest: pin.HostKeyDigest, authorityKind: pin.AuthorityKind, sourcePublic: append([]byte(nil), pin.SourcePublic...), targetReceiver: append([]byte(nil), pin.TargetReceiver...), ciphertextVersion: version, expiresAt: s.ExpiresUnix}, nil
}

// Check re-hashes the currently read ciphertext and checks exact authority,
// target, challenge, version and deadline. A real consumer must hold the
// source/owner/tree/admission fences across this check and commit.
func (v *Verified) Check(pin Pin, challenge string, envelope store.EncryptedMediaSourceSnapshot, version int64) error {
	if !boundedEnvelope(envelope) {
		return ErrInvalid
	}
	ciphertext, err := json.Marshal(envelope)
	if err != nil {
		return ErrInvalid
	}
	defer clear(ciphertext)
	if v == nil || !v.valid || version != v.ciphertextVersion || challenge != v.challenge || pin.SourceNode != v.sourceNode || pin.TargetNode != v.targetNode || pin.SourceKeyID != v.sourceKeyID || pin.HostKeyDigest != v.hostKeyDigest || pin.AuthorityKind != v.authorityKind || pin.Generation != v.generation || subtle.ConstantTimeCompare(pin.SourcePublic, v.sourcePublic) != 1 || subtle.ConstantTimeCompare(pin.TargetReceiver, v.targetReceiver) != 1 || len(ciphertext) == 0 || len(ciphertext) > 4*1024*1024 || time.Now().Unix() >= v.expiresAt {
		return ErrInvalid
	}
	hash := sha256.Sum256(ciphertext)
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(hash[:])), []byte(v.ciphertextDigest)) != 1 {
		return ErrInvalid
	}
	return nil
}

// Digest and ExpiresAt are non-authorizing inspection values.
func (v *Verified) Digest() string {
	if v == nil || !v.valid {
		return ""
	}
	return v.sourceDigest
}
func (v *Verified) ExpiresAt() int64 {
	if v == nil || !v.valid {
		return 0
	}
	return v.expiresAt
}
