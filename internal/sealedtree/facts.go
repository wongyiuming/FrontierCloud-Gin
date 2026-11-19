package sealedtree

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

const factsPayloadBytes = 32768
const legacyFactsPayloadBytes = 4096
const factsRecordVersion byte = 2

// Facts is sensitive trusted-Master memory. Legacy times and optional rows are
// preserved exactly; unset and explicit false are different. Legacy paths are
// historical source evidence, not live paths or permission to open a file.
// A tree rename does not rewrite them; live access must resolve stable IDs.
// Actual product permissions, audit, quota and object bytes remain separate.
type Facts struct {
	ObjectID                    string                 `json:"object_id"`
	InternalPlaceholder         bool                   `json:"internal_placeholder,omitempty"`
	InternalPromotedPlaceholder bool                   `json:"internal_promoted_placeholder,omitempty"`
	PendingPlaceholder          *PlaceholderTransition `json:"pending_placeholder,omitempty"`
	PendingSelectedUpload       *SelectedUploadFact    `json:"pending_selected_upload,omitempty"`
	Object                      *ObjectFact            `json:"object,omitempty"`
	Visibility                  *VisibilityFact        `json:"visibility,omitempty"`
	Playback                    *PlaybackFact          `json:"playback,omitempty"`
	Lyric                       *LyricFact             `json:"lyric,omitempty"`
	InternalDefaultLyric        *DefaultLyricFact      `json:"internal_default_lyric,omitempty"`
	LyricResolution             *LyricResolutionFact   `json:"lyric_resolution,omitempty"`
	Revocation                  *RevocationIntent      `json:"revocation,omitempty"`
	HiddenProof                 *RevocationIntent      `json:"hidden_proof,omitempty"`
	S3Deletion                  *S3MediaDeletion       `json:"s3_deletion,omitempty"`
	DirectoryDeletion           *DirectoryDeleteIntent `json:"directory_deletion,omitempty"`
}

// SelectedUploadFact exists only in encrypted pending facts. It ties the
// authenticated Admin admission and applied Direct policy to the placement;
// the placement itself carries the complete encrypted-media descriptor.
type SelectedUploadFact struct {
	UploadID     string `json:"upload_id"`
	AdminBinding string `json:"admin_binding"`
	Policy       string `json:"policy"`
	Revision     int64  `json:"revision"`
	Origin       string `json:"origin"`
}

// PlaceholderTransition is encrypted pending-only state. It pins the exact
// orphan rule version until a new file and its placement commit atomically.
type PlaceholderTransition struct {
	ObjectID          string `json:"object_id"`
	NameEncryptionID  string `json:"name_encryption_id"`
	FactsEncryptionID string `json:"facts_encryption_id"`
	NameRevision      int64  `json:"name_revision"`
	FactsRevision     int64  `json:"facts_revision"`
}

// RevocationIntent is encrypted Master state. It is a pending request, not an
// owner acknowledgement or evidence that previously issued grants are revoked.
type RevocationIntent struct {
	OperationID         string `json:"operation_id"`
	MasterID            string `json:"master_id"`
	MasterBinding       string `json:"master_binding"`
	OwnerID             string `json:"owner_id"`
	RelationshipID      string `json:"relationship_id"`
	RelationshipBinding string `json:"relationship_binding"`
	Alias               string `json:"alias"`
	BlobID              string `json:"blob_id"`
	Revision            string `json:"revision"`
	Action              string `json:"action"`
	SelectedDelete      bool   `json:"selected_delete,omitempty"`
	FollowerPublication string `json:"follower_publication,omitempty"`
	LocalDelete         bool   `json:"local_delete,omitempty"`
	LocalPublication    string `json:"local_publication,omitempty"`
	OwnerPublicKey      string `json:"owner_public_key,omitempty"`
	OwnerSignature      string `json:"owner_signature,omitempty"`
	DeletionPublicKey   string `json:"deletion_public_key,omitempty"`
	DeletionSignature   string `json:"deletion_signature,omitempty"`
}

type ObjectFact struct {
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}
type VisibilityFact struct {
	Hidden    int64  `json:"hidden"`
	UpdatedAt string `json:"updated_at"`
}
type PlaybackFact struct {
	LegacyMediaPath string `json:"legacy_media_path"`
	PlayScore       int64  `json:"play_score"`
	Preference      int64  `json:"preference"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}
type LyricFact struct {
	LegacyMediaPath string `json:"legacy_media_path"`
	LyricID         string `json:"lyric_id"`
	LegacyLyricPath string `json:"legacy_lyric_path"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

// DefaultLyricFact retains an authenticated historical association to the
// reserved built-in default, without turning it into a user-managed lyric.
// The source importer must independently prove the target and fixed content.
type DefaultLyricFact struct {
	LegacyMediaPath string `json:"legacy_media_path"`
	DefaultLyricID  string `json:"default_lyric_id"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

// LyricResolutionFact is an encrypted reference to separately authenticated
// completeness evidence; the string alone is not proof of a complete import.
type LyricResolutionFact struct {
	State            string `json:"state"`
	Evidence         string `json:"evidence"`
	Origin           string `json:"origin,omitempty"`
	SourceDigest     string `json:"source_digest,omitempty"`
	SourceGeneration string `json:"source_generation,omitempty"`
	// SourceProof is a tree-keyed import attestation stored inside the
	// existing fixed-size encrypted facts record. A bare source digest is not
	// proof; this value may only be created by a verified import transaction.
	SourceProof       string `json:"source_proof,omitempty"`
	OperationID       string `json:"operation_id,omitempty"`
	PreviousEvidence  string `json:"previous_evidence,omitempty"`
	PreviousRevision  int64  `json:"previous_revision,omitempty"`
	RelationCreatedAt string `json:"relation_created_at,omitempty"`
	RelationUpdatedAt string `json:"relation_updated_at,omitempty"`
}

type FactsRecord struct {
	ObjectIndex string
	Revision    int64
	Sealed      []byte
}

func factText(value string, limit int, allowEmpty bool) bool {
	return (allowEmpty || value != "") && len(value) <= limit && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

// Legacy business paths use the source database's 1024 Unicode-character
// contract. UTF-8 can require four bytes per character; validate both bounds.
func factPath(value string) bool {
	return factText(value, 1024*utf8.UTFMax, false) && utf8.RuneCountInString(value) <= 1024
}

func validRevocationIntent(r *RevocationIntent) bool {
	if r != nil && r.LocalDelete {
		return r.FollowerPublication == "" && validMasterLocalDeleteIntent(r)
	}
	if r != nil && (r.LocalPublication != "" || r.SelectedDelete && (r.Action != "delete" || !hexID(r.FollowerPublication) || r.FollowerPublication == r.Alias || r.FollowerPublication == r.BlobID) || !r.SelectedDelete && r.FollowerPublication != "") {
		return false
	}
	return r != nil && lowerHex(r.OperationID, 32) && lowerHex(r.MasterID, 32) && hexID(r.MasterBinding) && lowerHex(r.OwnerID, 32) && lowerHex(r.RelationshipID, 32) && hexID(r.RelationshipBinding) && hexID(r.Alias) && hexID(r.BlobID) && r.Alias != r.BlobID && hexID(r.Revision) && (r.Action == "delete" || r.Action == "migrate" || r.Action == "hide") && (r.OwnerPublicKey == "") == (r.OwnerSignature == "") && factText(r.OwnerPublicKey, 128, true) && factText(r.OwnerSignature, 256, true) && (r.DeletionPublicKey == "") == (r.DeletionSignature == "") && factText(r.DeletionPublicKey, 128, true) && factText(r.DeletionSignature, 256, true) && (r.DeletionSignature == "" || r.Action == "delete" && r.OwnerSignature != "")
}

func validFacts(value Facts) bool {
	if !hexID(value.ObjectID) {
		return false
	}
	if selected := value.PendingSelectedUpload; selected != nil {
		u, err := url.Parse(selected.Origin)
		validDirect := selected.Policy == "Direct" && err == nil && u.Scheme == "https" && u.Hostname() != "" && u.Host == strings.ToLower(u.Host) && !strings.HasSuffix(u.Host, ":") && !strings.ContainsAny(selected.Origin, "\\\r\n\t ") && u.Port() == "" && u.User == nil && u.Opaque == "" && u.Path == "" && u.RawPath == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.String() == selected.Origin
		validRelay := (selected.Policy == "Relay" || selected.Policy == "Local" || selected.Policy == "S3") && selected.Origin == ""
		if !lowerHex(selected.UploadID, 32) || !hexID(selected.AdminBinding) || (!validDirect && !validRelay) || selected.Revision < 1 || value.PendingPlaceholder != nil || value.Revocation != nil || value.HiddenProof != nil || value.InternalPlaceholder || value.InternalPromotedPlaceholder {
			return false
		}
	}
	if p := value.PendingPlaceholder; p != nil && (!hexID(p.ObjectID) || p.ObjectID == value.ObjectID || !hexID(p.NameEncryptionID) || !hexID(p.FactsEncryptionID) || p.NameEncryptionID == p.FactsEncryptionID || p.NameRevision < 1 || p.FactsRevision < 1 || value.InternalPlaceholder || value.InternalPromotedPlaceholder || value.Visibility == nil || value.Visibility.Hidden != 1 || value.Revocation != nil || value.HiddenProof != nil) {
		return false
	}
	if o := value.Object; o != nil && (!factText(o.CreatedAt, 128, false) || !factText(o.UpdatedAt, 128, false)) {
		return false
	}
	if value.Visibility != nil && (value.Visibility.Hidden < 0 || value.Visibility.Hidden > 1 || !factText(value.Visibility.UpdatedAt, 128, false)) {
		return false
	}
	if p := value.Playback; p != nil && (p.Preference < -7 || p.Preference > 500000 || p.LegacyMediaPath != "" && !factPath(p.LegacyMediaPath) || !factText(p.CreatedAt, 128, false) || !factText(p.UpdatedAt, 128, false)) {
		return false
	}
	if l := value.Lyric; l != nil && (!hexID(l.LyricID) || !factPath(l.LegacyMediaPath) || !factPath(l.LegacyLyricPath) || !factText(l.CreatedAt, 128, false) || !factText(l.UpdatedAt, 128, false)) {
		return false
	}
	if d := value.InternalDefaultLyric; d != nil && (value.Lyric != nil || !hexID(d.DefaultLyricID) || !factPath(d.LegacyMediaPath) || !factText(d.CreatedAt, 128, false) || !factText(d.UpdatedAt, 128, false)) {
		return false
	}
	if r := value.LyricResolution; r != nil {
		if !hexID(r.Evidence) || (r.State != "none" && r.State != "default" && r.State != "explicit") || r.State == "none" && (value.Lyric != nil || value.InternalDefaultLyric != nil) || r.State == "default" && (value.Lyric != nil || (r.Origin == "" && value.InternalDefaultLyric == nil) || (r.Origin == "native" && value.InternalDefaultLyric != nil)) || r.State == "explicit" && (value.Lyric == nil || value.InternalDefaultLyric != nil) || (r.Origin != "" && r.Origin != "native" && r.Origin != "local") || r.Origin == "" && (r.OperationID != "" || r.PreviousEvidence != "" || r.PreviousRevision != 0 || r.RelationCreatedAt != "" || r.RelationUpdatedAt != "") || r.Origin == "native" && (!hexID(r.OperationID) || r.PreviousRevision < 1 || r.PreviousEvidence != "" && !hexID(r.PreviousEvidence) || !factText(r.RelationCreatedAt, 128, false) || !factText(r.RelationUpdatedAt, 128, false)) {
			return false
		}
		if r.Origin == "local" && (r.State == "default" && value.InternalDefaultLyric == nil || !hexID(r.OperationID) || r.PreviousEvidence != "" || r.PreviousRevision != 0 || r.RelationCreatedAt != "" || r.RelationUpdatedAt != "" || r.SourceDigest != "" || r.SourceGeneration != "" || r.SourceProof != "") {
			return false
		}
		if (r.SourceDigest == "") != (r.SourceGeneration == "") || r.Origin == "native" && r.SourceDigest != "" {
			return false
		}
		if r.SourceProof != "" && (r.Origin != "" || r.SourceDigest == "" || !hexID(r.SourceProof)) {
			return false
		}
		if r.SourceDigest != "" {
			lyricID := ""
			if r.State == "explicit" {
				lyricID = value.Lyric.LyricID
			}
			if r.State == "default" {
				lyricID = value.InternalDefaultLyric.DefaultLyricID
			}
			evidence, err := LyricResolutionEvidence(r.SourceDigest, r.SourceGeneration, value.ObjectID, r.State, lyricID)
			if err != nil || evidence != r.Evidence {
				return false
			}
		}
	}
	if value.Revocation != nil && !validRevocationIntent(value.Revocation) {
		return false
	}
	if d := value.S3Deletion; d != nil && (!lowerHex(d.OperationID, 32) || !lowerHex(d.UploadID, 32) || d.OperationID == d.UploadID || !hexID(d.PlacementID) || d.QueuedAt <= 0 ||
		value.Revocation != nil || value.HiddenProof != nil || value.InternalPlaceholder || value.InternalPromotedPlaceholder ||
		value.PendingPlaceholder != nil || value.PendingSelectedUpload != nil) {
		return false
	}
	if d := value.DirectoryDeletion; d != nil && (!lowerHex(d.OperationID, 32) || value.Revocation != nil || value.S3Deletion != nil || value.HiddenProof != nil ||
		value.InternalPlaceholder || value.PendingPlaceholder != nil || value.PendingSelectedUpload != nil) {
		return false
	}
	if r := value.HiddenProof; r != nil {
		if !validRevocationIntent(r) || r.Action != "hide" || r.OwnerSignature == "" || r.DeletionSignature != "" || value.Revocation != nil || value.Visibility == nil || value.Visibility.Hidden != 1 {
			return false
		}
		payload, err := revocationReceipt(*r).Payload()
		if err != nil || protocol.Verify(r.OwnerPublicKey, payload, r.OwnerSignature) != nil {
			return false
		}
	}
	return true
}

func factsCompatible(entry Entry, facts Facts) bool {
	return facts.PendingPlaceholder == nil && facts.PendingSelectedUpload == nil && factsCompatiblePending(entry, facts)
}

func factsCompatiblePending(entry Entry, facts Facts) bool {
	if facts.DirectoryDeletion != nil && entry.Kind != "directory" {
		return false
	}
	if facts.S3Deletion != nil && entry.Kind != "audio" && entry.Kind != "video" {
		return false
	}
	return entry.ObjectID == facts.ObjectID && (facts.PendingPlaceholder == nil || entry.Kind != "directory") && (facts.PendingSelectedUpload == nil || entry.Kind == "audio" || entry.Kind == "video" || entry.Kind == "lyric") && (!facts.InternalPlaceholder || entry.Kind == "directory" && !facts.InternalPromotedPlaceholder && facts.Object == nil && facts.Playback == nil && facts.Lyric == nil && facts.InternalDefaultLyric == nil && facts.LyricResolution == nil && facts.Revocation == nil && facts.HiddenProof == nil) && (!facts.InternalPromotedPlaceholder || entry.Kind == "directory") && (facts.Lyric == nil && facts.InternalDefaultLyric == nil && facts.LyricResolution == nil || entry.Kind == "audio") && (facts.Revocation == nil || entry.Kind != "directory") && (facts.HiddenProof == nil || entry.Kind != "directory")
}

func factsAAD(index string, revision int64, version byte) []byte {
	return []byte("frontiercloud:sealed-tree:facts:v" + strconv.Itoa(int(version)) + "\x00" + index + "\x00" + strconv.FormatInt(revision, 10))
}

// SealFacts uses fixed padded ciphertext and independent random key identity.
// The caller must permanently reserve that identity in the same transaction.
func (t *Tree) SealFacts(facts Facts, revision int64) (FactsRecord, error) {
	if t == nil || !t.ready || !validFacts(facts) || revision <= 0 {
		return FactsRecord{}, ErrInvalid
	}
	index, err := t.ObjectIndex(facts.ObjectID)
	if err != nil {
		return FactsRecord{}, err
	}
	encoded, err := json.Marshal(facts)
	if err != nil || len(encoded) == 0 || len(encoded) > factsPayloadBytes-2 {
		return FactsRecord{}, ErrInvalid
	}
	defer clear(encoded)
	plain := make([]byte, factsPayloadBytes)
	defer clear(plain)
	binary.BigEndian.PutUint16(plain[:2], uint16(len(encoded)))
	copy(plain[2:], encoded)
	random := make([]byte, recordSaltBytes+nonceBytes)
	if _, err = io.ReadFull(rand.Reader, random); err != nil {
		return FactsRecord{}, ErrInvalid
	}
	aead, err := t.recordCipher(random[:recordSaltBytes], "facts")
	if err != nil {
		return FactsRecord{}, ErrInvalid
	}
	sealed := append([]byte{factsRecordVersion}, random...)
	sealed = aead.Seal(sealed, random[recordSaltBytes:], plain, factsAAD(index, revision, factsRecordVersion))
	return FactsRecord{ObjectIndex: index, Revision: revision, Sealed: sealed}, nil
}

func FactsEncryptionID(record FactsRecord) (string, error) {
	if len(record.Sealed) < 1 {
		return "", ErrInvalid
	}
	size := factsPayloadBytes
	if record.Sealed[0] == recordVersion {
		size = legacyFactsPayloadBytes
	} else if record.Sealed[0] != factsRecordVersion {
		return "", ErrInvalid
	}
	if len(record.Sealed) != 1+recordSaltBytes+nonceBytes+size+16 {
		return "", ErrInvalid
	}
	return hex.EncodeToString(record.Sealed[1 : 1+recordSaltBytes]), nil
}

// OpenFacts validates the whole encrypted record and its object binding. It is
// not an authorization decision and cannot establish freshness after rollback.
func (t *Tree) OpenFacts(record FactsRecord) (Facts, error) {
	return t.openFactsWithScratch(record, nil)
}

// openFactsWithScratch is for a synchronous caller that owns the buffer for
// the entire call. It is wiped even when authentication or decoding fails;
// decoded values must not refer to it. It is never safe to share concurrently.
func (t *Tree) openFactsWithScratch(record FactsRecord, scratch []byte) (Facts, error) {
	defer clear(scratch[:cap(scratch)])
	if t == nil || !t.ready || !hexID(record.ObjectIndex) || record.Revision <= 0 {
		return Facts{}, ErrInvalid
	}
	if _, err := FactsEncryptionID(record); err != nil {
		return Facts{}, err
	}
	aead, err := t.recordCipher(record.Sealed[1:1+recordSaltBytes], "facts")
	if err != nil {
		return Facts{}, ErrInvalid
	}
	version := record.Sealed[0]
	plain, err := aead.Open(scratch[:0], record.Sealed[1+recordSaltBytes:1+recordSaltBytes+nonceBytes], record.Sealed[1+recordSaltBytes+nonceBytes:], factsAAD(record.ObjectIndex, record.Revision, version))
	if err != nil {
		return Facts{}, ErrInvalid
	}
	defer clear(plain)
	length := int(binary.BigEndian.Uint16(plain[:2]))
	if length == 0 || length > len(plain)-2 {
		return Facts{}, ErrInvalid
	}
	for _, value := range plain[2+length:] {
		if value != 0 {
			return Facts{}, ErrInvalid
		}
	}
	d := json.NewDecoder(bytes.NewReader(plain[2 : 2+length]))
	d.DisallowUnknownFields()
	var facts Facts
	if err = d.Decode(&facts); err != nil || !validFacts(facts) {
		return Facts{}, ErrInvalid
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return Facts{}, ErrInvalid
	}
	index, err := t.ObjectIndex(facts.ObjectID)
	if err != nil || index != record.ObjectIndex {
		return Facts{}, ErrInvalid
	}
	return facts, nil
}
