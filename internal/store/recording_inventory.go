package store

import (
	"encoding/json"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

const MaxRecordingInventoryBytes = 4 * 1024 * 1024
const MaxRecordingInventoryItems = 5000

// Offline physical ownership proof, not a new account or quota authority.
// Secrets, credentials and mutable business metadata are deliberately absent.
type RecordingProof struct {
	ID                        string                `json:"recording_id"`
	UserID                    string                `json:"user_id"`
	Filename                  string                `json:"filename"`
	ContentType               string                `json:"content_type"`
	Bytes                     int64                 `json:"size_bytes"`
	SHA256                    string                `json:"sha256"`
	CreatedAt                 int64                 `json:"created_at"`
	EncryptedLyricsEncryption *mediacrypto.Metadata `json:"encrypted_lyrics_encryption,omitempty"`
	MetadataSHA256            string                `json:"metadata_sha256,omitempty"`
	// Populated only from physically verified opaque footer bytes. Its signed
	// descriptor/hash avoid placing large snapshots in the bounded manifest.
	VerifiedMetadata *RecordingMetadata `json:"-"`
}

func RecordingProofSnapshotMatches(v RecordingProof, metadata *RecordingMetadata) bool {
	if v.EncryptedLyricsEncryption == nil {
		return v.MetadataSHA256 == "" && (metadata == nil || metadata.EncryptedLyrics == nil)
	}
	return metadata != nil && metadata.EncryptedLyrics != nil && ValidRecordingMetadata(*metadata) && metadata.EncryptedLyrics.Encryption == *v.EncryptedLyricsEncryption && RecordingMetadataSHA256(*metadata) == v.MetadataSHA256
}

type RecordingInventory struct {
	Kind             string           `json:"kind"`
	Version          int              `json:"version"`
	SchemaGeneration int              `json:"schema_generation"`
	MasterID         string           `json:"master_id"`
	FollowerID       string           `json:"follower_id"`
	Relationship     string           `json:"relationship_id"`
	CreatedAt        int64            `json:"created_at"`
	ExpiresAt        int64            `json:"expires_at"`
	Recordings       []RecordingProof `json:"recordings"`
}
type SignedRecordingInventory struct {
	Payload   RecordingInventory `json:"payload"`
	Signature string             `json:"signature"`
}

// Canonical signing preserves integer precision and rejects oversize manifests.
func (v RecordingInventory) CanonicalPayload() (any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return protocol.ParseStrictJSON(raw, MaxRecordingInventoryBytes)
}
