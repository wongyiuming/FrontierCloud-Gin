package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

var ErrRecordingMissing = errors.New("录音不存在")
var ErrRecordingState = errors.New("录音状态或存储配额已变化")
var ErrRecordingQuota = errors.New("个人录音空间不足")

const MaxRecordingBytes int64 = GiB
const MaxRecordingMetadata = 2 * 1024 * 1024
const MaxEncryptedRecordingLyricPlaintext = 1400 * 1024

type RecordingEncryptedLyrics struct {
	Encryption mediacrypto.Metadata `json:"encryption"`
	Ciphertext string               `json:"ciphertext"`
}

type RecordingLyric struct {
	Time float64 `json:"time"`
	Text string  `json:"text"`
}
type RecordingMetadata struct {
	EncryptedLyricPath string                    `json:"encrypted_lyric_path,omitempty"`
	Title              string                    `json:"title"`
	Lyrics             []RecordingLyric          `json:"lyrics"`
	EncryptedLyrics    *RecordingEncryptedLyrics `json:"encrypted_lyrics,omitempty"`
}
type Recording struct {
	ID              string                    `json:"recording_id"`
	UserID          string                    `json:"-"`
	MemberID        string                    `json:"-"`
	Filename        string                    `json:"filename"`
	ContentType     string                    `json:"content_type"`
	Bytes           int64                     `json:"size_bytes"`
	SHA256          *string                   `json:"sha256"`
	State           string                    `json:"-"`
	Title           string                    `json:"title"`
	Lyrics          []RecordingLyric          `json:"lyrics"`
	EncryptedLyrics *RecordingEncryptedLyrics `json:"encrypted_lyrics,omitempty"`
	// Signed, bounded reservation for a remote recording. The large ciphertext
	// arrives in its footer; capabilities carry only its descriptor and hash.
	ExpectedEncryptedLyrics *mediacrypto.Metadata `json:"expected_encrypted_lyrics,omitempty"`
	EncryptedLyricsSHA256   string                `json:"encrypted_lyrics_sha256,omitempty"`
	CreatedAt               int64                 `json:"created_at"`
	UpdatedAt               int64                 `json:"-"`
}
type RecordingReceipt struct {
	ID       string             `json:"recording_id"`
	Bytes    int64              `json:"size_bytes"`
	SHA256   string             `json:"sha256"`
	Metadata *RecordingMetadata `json:"metadata,omitempty"`
}

func RecordingContentType(v string) bool {
	switch v {
	case "audio/webm", "audio/ogg", "audio/mp4", "audio/mpeg", "audio/wav", "application/octet-stream":
		return true
	}
	return false
}
func ValidRecordingMetadata(v RecordingMetadata) bool {
	if v.EncryptedLyrics != nil && (len(v.Lyrics) != 0 || v.EncryptedLyricPath != "" || !ValidRecordingEncryptedLyrics(*v.EncryptedLyrics)) {
		return false
	}
	if v.EncryptedLyricPath != "" {
		if !utf8.ValidString(v.EncryptedLyricPath) || len(v.EncryptedLyricPath) > 1024 || !strings.HasPrefix(v.EncryptedLyricPath, "lyrics/") || !strings.HasSuffix(v.EncryptedLyricPath, ".lrc") || strings.ContainsAny(v.EncryptedLyricPath, "\\\x00") {
			return false
		}
		for _, part := range strings.Split(v.EncryptedLyricPath, "/") {
			if part == "" || part == "." || part == ".." {
				return false
			}
		}
	}
	if !utf8.ValidString(v.Title) || utf8.RuneCountInString(v.Title) > 255 || len(v.Lyrics) > 10000 {
		return false
	}
	for _, line := range v.Lyrics {
		if !utf8.ValidString(line.Text) || utf8.RuneCountInString(line.Text) > 4000 || line.Time < 0 || math.IsNaN(line.Time) || math.IsInf(line.Time, 0) {
			return false
		}
	}
	raw, err := json.Marshal(v)
	return err == nil && len(raw) <= MaxRecordingMetadata
}

func ValidRecordingEncryptedLyrics(v RecordingEncryptedLyrics) bool {
	if v.Encryption.Validate() != nil || v.Encryption.PlaintextSize <= 0 || v.Encryption.PlaintextSize > MaxEncryptedRecordingLyricPlaintext || len(v.Ciphertext) != base64.StdEncoding.EncodedLen(int(v.Encryption.CiphertextSize)) {
		return false
	}
	cipher, err := base64.StdEncoding.Strict().DecodeString(v.Ciphertext)
	return err == nil && int64(len(cipher)) == v.Encryption.CiphertextSize && base64.StdEncoding.EncodeToString(cipher) == v.Ciphertext
}

func RecordingMetadataFor(v Recording) RecordingMetadata {
	lyrics := v.Lyrics
	if lyrics == nil {
		lyrics = []RecordingLyric{}
	}
	return RecordingMetadata{Title: v.Title, Lyrics: lyrics, EncryptedLyrics: v.EncryptedLyrics}
}

// A snapshot is immutable after its ticket was issued. Plain legacy receipts
// retain their existing optional metadata behavior, but cannot introduce an
// encrypted snapshot without a reserved, globally unique file ID.
func RecordingReceiptMetadataMatches(v Recording, metadata *RecordingMetadata) bool {
	if v.ExpectedEncryptedLyrics != nil {
		return metadata != nil && metadata.EncryptedLyrics != nil && ValidRecordingMetadata(*metadata) && metadata.EncryptedLyrics.Encryption == *v.ExpectedEncryptedLyrics && RecordingMetadataSHA256(*metadata) == v.EncryptedLyricsSHA256
	}
	if v.EncryptedLyrics == nil {
		return metadata == nil || metadata.EncryptedLyrics == nil
	}
	if metadata == nil || !ValidRecordingMetadata(*metadata) {
		return false
	}
	left, _ := json.Marshal(RecordingMetadataFor(v))
	right, _ := json.Marshal(*metadata)
	return bytes.Equal(left, right)
}

func RecordingMetadataSHA256(v RecordingMetadata) string {
	if v.Lyrics == nil {
		v.Lyrics = []RecordingLyric{}
	}
	raw, _ := json.Marshal(v)
	value, err := protocol.ParseStrictJSON(raw, MaxRecordingMetadata)
	if err != nil {
		return ""
	}
	canonical, err := protocol.Canonical(value)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:])
}

func ValidRecordingReservation(v Recording) bool {
	if v.ExpectedEncryptedLyrics == nil {
		return v.EncryptedLyricsSHA256 == "" && ValidRecordingMetadata(RecordingMetadataFor(v)) && RecordingEncryptedLyricsFit(RecordingMetadataFor(v), v.Bytes)
	}
	if v.EncryptedLyrics != nil || len(v.Lyrics) != 0 || v.ExpectedEncryptedLyrics.Validate() != nil || v.ExpectedEncryptedLyrics.PlaintextSize <= 0 || v.ExpectedEncryptedLyrics.PlaintextSize > MaxEncryptedRecordingLyricPlaintext {
		return false
	}
	hash, err := hex.DecodeString(v.EncryptedLyricsSHA256)
	return err == nil && len(hash) == 32 && hex.EncodeToString(hash) == v.EncryptedLyricsSHA256 && int64(base64.StdEncoding.EncodedLen(int(v.ExpectedEncryptedLyrics.CiphertextSize))) < v.Bytes
}

// The encrypted envelope and V1 footer framing are part of the charged upload
// bytes. A tiny audio reservation cannot persist a much larger snapshot.
func RecordingEncryptedLyricsFit(metadata RecordingMetadata, size int64) bool {
	if metadata.EncryptedLyrics == nil {
		return true
	}
	raw, err := json.Marshal(metadata)
	return err == nil && int64(len(raw)+12+8+len("FRONTIERCLOUD-KARAOKE-V1")) <= size
}

func EncodeRecordingReservation(v Recording) ([]byte, error) {
	if !ValidRecordingReservation(v) {
		return nil, ErrRecordingState
	}
	if v.ExpectedEncryptedLyrics == nil {
		return EncodeRecordingLyrics(RecordingMetadataFor(v))
	}
	return json.Marshal(struct {
		ExpectedEncryptedLyrics *mediacrypto.Metadata `json:"expected_encrypted_lyrics"`
		EncryptedLyricsSHA256   string                `json:"encrypted_lyrics_sha256"`
	}{v.ExpectedEncryptedLyrics, v.EncryptedLyricsSHA256})
}

func DecodeRecordingReservation(raw []byte, v *Recording) error {
	lyrics, encrypted, err := DecodeRecordingLyrics(raw)
	if err == nil {
		v.Lyrics, v.EncryptedLyrics = lyrics, encrypted
		return nil
	}
	value, err := protocol.ParseStrictJSON(raw, MaxRecordingMetadata)
	if err != nil {
		return ErrRecordingState
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) != 2 || object["expected_encrypted_lyrics"] == nil || object["encrypted_lyrics_sha256"] == nil {
		return ErrRecordingState
	}
	var envelope struct {
		ExpectedEncryptedLyrics *mediacrypto.Metadata `json:"expected_encrypted_lyrics"`
		EncryptedLyricsSHA256   string                `json:"encrypted_lyrics_sha256"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil {
		return ErrRecordingState
	}
	v.Lyrics, v.ExpectedEncryptedLyrics, v.EncryptedLyricsSHA256 = []RecordingLyric{}, envelope.ExpectedEncryptedLyrics, envelope.EncryptedLyricsSHA256
	if !ValidRecordingReservation(*v) {
		return ErrRecordingState
	}
	return nil
}

// Keep the legacy SQL array format for plaintext recordings. An encrypted
// snapshot uses a discriminated object in the same opaque JSON column.
func EncodeRecordingLyrics(v RecordingMetadata) ([]byte, error) {
	if !ValidRecordingMetadata(v) {
		return nil, ErrRecordingState
	}
	if v.EncryptedLyrics != nil {
		return json.Marshal(struct {
			EncryptedLyrics *RecordingEncryptedLyrics `json:"encrypted_lyrics"`
		}{v.EncryptedLyrics})
	}
	if v.Lyrics == nil {
		v.Lyrics = []RecordingLyric{}
	}
	return json.Marshal(v.Lyrics)
}

func DecodeRecordingLyrics(raw []byte) ([]RecordingLyric, *RecordingEncryptedLyrics, error) {
	value, err := protocol.ParseStrictJSON(raw, MaxRecordingMetadata)
	if err != nil {
		return nil, nil, ErrRecordingState
	}
	if _, ok := value.([]any); ok {
		var lyrics []RecordingLyric
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&lyrics) != nil || !ValidRecordingMetadata(RecordingMetadata{Lyrics: lyrics}) {
			return nil, nil, ErrRecordingState
		}
		return lyrics, nil, nil
	}
	// The original SQL representation permitted null for a missing array.
	if value == nil {
		return []RecordingLyric{}, nil, nil
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) != 1 || object["encrypted_lyrics"] == nil {
		return nil, nil, ErrRecordingState
	}
	var envelope struct {
		EncryptedLyrics *RecordingEncryptedLyrics `json:"encrypted_lyrics"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || envelope.EncryptedLyrics == nil || !ValidRecordingEncryptedLyrics(*envelope.EncryptedLyrics) {
		return nil, nil, ErrRecordingState
	}
	return []RecordingLyric{}, envelope.EncryptedLyrics, nil
}
func ValidRecordingFilename(v string) bool {
	return utf8.ValidString(v) && utf8.RuneCountInString(v) > 0 && utf8.RuneCountInString(v) <= 255 && !strings.ContainsAny(v, "\r\n\x00/\\")
}

// Completion methods require a verified physical receipt / cleanup proof.
// A timeout, expired ticket or client-provided hash never constitutes proof.
type RecordingRepository interface {
	Recording(context.Context, string) (*Recording, error)
	ListRecordings(context.Context, string, string, int) ([]Recording, error)
	ReserveRecording(context.Context, Recording, int64, KaraokeAudit) (Recording, StorageMember, error)
	FinalizeRecording(context.Context, string, string, RecordingReceipt, KaraokeAudit) error
	StageRecordingDeletion(context.Context, string, string, bool, KaraokeAudit) (*Recording, error)
	CompleteRecordingDeletion(context.Context, string, string, KaraokeAudit) error
	PendingRecordingDeletions(context.Context, int) ([]Recording, error)
	DeferRecordingDeletion(context.Context, string) error
	StageExpiredRecordings(context.Context, int) error
	ReserveOwnedRecording(context.Context, string, Recording, int64, NodeAudit) error
	CheckLocalRecordingUpload(context.Context, Recording) error
	StageOwnedRecordingDeletion(context.Context, string, string, string) (*Recording, error)
	StageOwnedUserDeletion(context.Context, string, string) error
	CompleteOwnedUserDeletion(context.Context, string, string, NodeAudit) error
	CompleteOwnedRecording(context.Context, string, RecordingReceipt, int64, NodeAudit) error
	CompleteOwnedRecordingDeletion(context.Context, string, string, string, int64, NodeAudit) error
}
