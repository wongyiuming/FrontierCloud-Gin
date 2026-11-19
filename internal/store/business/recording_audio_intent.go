package business

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// recordingAudioIntent is Master-only authenticated state. A persisted intent
// does not by itself authorize a browser, prove Owner bytes or settle quota.
type recordingAudioIntent struct {
	UserID       string               `json:"u"`
	RecordingID  string               `json:"r"`
	MasterID     string               `json:"m"`
	MemberID     string               `json:"n"`
	OperationID  string               `json:"o"`
	BlobID       string               `json:"b"`
	Digest       string               `json:"d"`
	Bytes        int64                `json:"s"`
	Binding      string               `json:"a"`
	OwnerBinding string               `json:"k"`
	ContentType  string               `json:"c"`
	Encryption   mediacrypto.Metadata `json:"e"`
	TitleDigest  string               `json:"h"`
	LyricsDigest string               `json:"l,omitempty"`
	State        string               `json:"t"`
}

func recordingAudioIndex(key []byte, id string) string {
	return hex.EncodeToString(capacityMAC(key, "recording-audio-id-v1", []byte(id)))
}

func validRecordingAudioIntent(v recordingAudioIntent) bool {
	parts := strings.Split(v.Binding, ":")
	if len(parts) != 5 || parts[0] != "recording-audio" || parts[1] != "v1" || parts[2] != v.UserID || !nodeHashPattern.MatchString(parts[3]) || parts[4] != v.RecordingID {
		return false
	}
	return nodeIDPattern.MatchString(v.UserID) && nodeIDPattern.MatchString(v.RecordingID) &&
		nodeIDPattern.MatchString(v.MasterID) && nodeIDPattern.MatchString(v.MemberID) &&
		nodeHashPattern.MatchString(v.OperationID) && nodeHashPattern.MatchString(v.BlobID) &&
		v.OperationID != v.BlobID && nodeHashPattern.MatchString(v.Digest) &&
		v.Bytes > 0 && v.Bytes <= store.MaxRecordingBytes && v.Encryption.Validate() == nil &&
		v.Encryption.CiphertextSize == v.Bytes && nodeHashPattern.MatchString(v.TitleDigest) &&
		nodeHashPattern.MatchString(v.OwnerBinding) && store.RecordingContentType(v.ContentType) &&
		(v.LyricsDigest == "" || nodeHashPattern.MatchString(v.LyricsDigest)) && (v.State == "pending" || v.State == "ready" || v.State == "deleting" || v.State == "deleted" || v.State == "cancelled" || v.State == "cancel_pending" && v.MemberID != v.MasterID)
}

func validRecordingAudioLyrics(v recordingAudioIntent, lyrics []byte) bool {
	if len(lyrics) == 0 {
		return v.LyricsDigest == ""
	}
	if len(lyrics) > store.MaxRecordingMetadata {
		return false
	}
	if _, err := protocol.ParseStrictJSON(lyrics, store.MaxRecordingMetadata); err != nil {
		return false
	}
	digest := sha256.Sum256(lyrics)
	if subtle.ConstantTimeCompare([]byte(v.LyricsDigest), []byte(hex.EncodeToString(digest[:]))) != 1 {
		return false
	}
	var snapshot store.RecordingEncryptedLyrics
	decoder := json.NewDecoder(bytes.NewReader(lyrics))
	decoder.DisallowUnknownFields()
	return decoder.Decode(&snapshot) == nil && decoder.Decode(new(any)) == io.EOF &&
		store.ValidRecordingEncryptedLyrics(snapshot) && snapshot.Encryption.FileID != v.Encryption.FileID
}

// insertRecordingAudioIntentTx runs only inside the fenced coordinator's
// transaction, together with preparation claim and user/member reservation.
// Both random encryption IDs receive permanent tombstones before the row is
// inserted. No user-controlled value is used as a filesystem name.
func (r *Repository) insertRecordingAudioIntentTx(ctx context.Context, q queryer, key []byte, v recordingAudioIntent, title string, lyrics []byte) error {
	if ctx == nil || q == nil || ctx.Err() != nil || !validCapacityKey(key) || !validRecordingAudioIntent(v) || v.State != "pending" || !utf8.ValidString(title) || utf8.RuneCountInString(title) > 255 || len(title) == 0 || len(lyrics) > store.MaxRecordingMetadata {
		return store.ErrRecordingState
	}
	if err := checkCapacityVerifier(ctx, q, key); err != nil {
		return err
	}
	titleDigest := sha256.Sum256([]byte(title))
	if subtle.ConstantTimeCompare([]byte(v.TitleDigest), []byte(hex.EncodeToString(titleDigest[:]))) != 1 || !validRecordingAudioLyrics(v, lyrics) {
		return store.ErrRecordingState
	}
	index := recordingAudioIndex(key, v.RecordingID)
	raw, err := json.Marshal(v)
	if err != nil {
		return store.ErrRecordingState
	}
	defer clear(raw)
	id, sealed, err := sealCapacityRecord(key, index, raw)
	if err != nil {
		return err
	}
	titleID, sealedTitle, err := sealCapacityRecord(key, index, []byte(title))
	if err != nil || id == titleID {
		return store.ErrRecordingState
	}
	for _, value := range []string{id, titleID} {
		if _, err = q.ExecContext(ctx, `INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)`, value); err != nil {
			return store.ErrRecordingState
		}
	}
	var storedLyrics any
	if len(lyrics) != 0 {
		storedLyrics = lyrics
	}
	if _, err = q.ExecContext(ctx, `INSERT INTO sealed_recording_audio(recording_index,encryption_id,sealed,title_encryption_id,sealed_title,lyric_ciphertext) VALUES(?,?,?,?,?,?)`, index, id, sealed, titleID, sealedTitle, storedLyrics); err != nil {
		return store.ErrRecordingState
	}
	return nil
}

// markRecordingAudioReadyTx changes only an authenticated pending record in
// the caller's transaction; the caller must first verify and settle its exact
// Owner receipt and update the corresponding account row atomically.
func (r *Repository) markRecordingAudioReadyTx(ctx context.Context, q queryer, key []byte, pending recordingAudioIntent) error {
	return r.transitionRecordingAudioTx(ctx, q, key, pending, "pending", "ready")
}

func (r *Repository) transitionRecordingAudioTx(ctx context.Context, q queryer, key []byte, pending recordingAudioIntent, from, to string) error {
	allowed := from == "pending" && to == "ready" || from == "ready" && to == "deleting" || from == "deleting" && to == "deleted" ||
		from == "pending" && to == "cancelled" && pending.MemberID == pending.MasterID ||
		from == "pending" && to == "cancel_pending" && pending.MemberID != pending.MasterID ||
		from == "cancel_pending" && to == "cancelled"
	if pending.State != from || !validRecordingAudioIntent(pending) || !allowed {
		return store.ErrRecordingState
	}
	current, _, _, found, err := r.readRecordingAudioIntentTx(ctx, q, key, pending.RecordingID)
	if err != nil || !found || current != pending {
		return store.ErrRecordingState
	}
	index := recordingAudioIndex(key, pending.RecordingID)
	var priorID string
	if err = q.QueryRowContext(ctx, `SELECT encryption_id FROM sealed_recording_audio WHERE recording_index=?`+r.lock(), index).Scan(&priorID); err != nil {
		return store.ErrRecordingState
	}
	current.State = to
	raw, err := json.Marshal(current)
	if err != nil {
		return err
	}
	defer clear(raw)
	id, sealed, err := sealCapacityRecord(key, index, raw)
	if err != nil {
		return err
	}
	if _, err = q.ExecContext(ctx, `INSERT INTO sealed_tree_capacity_ids(encryption_id) VALUES(?)`, id); err != nil {
		return store.ErrRecordingState
	}
	result, err := q.ExecContext(ctx, `UPDATE sealed_recording_audio SET encryption_id=?,sealed=? WHERE recording_index=? AND encryption_id=?`, id, sealed, index, priorID)
	if err != nil {
		return err
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return store.ErrRecordingState
	}
	return nil
}

// readRecordingAudioIntentTx reauthenticates the encrypted facts, title and
// browser-encrypted lyric bytes. The caller must still authorize the current
// user and validate the current Owner before issuing a read or mutation.
func (r *Repository) readRecordingAudioIntentTx(ctx context.Context, q queryer, key []byte, recordingID string) (recordingAudioIntent, string, []byte, bool, error) {
	var zero recordingAudioIntent
	if ctx == nil || q == nil || ctx.Err() != nil || !validCapacityKey(key) || !nodeIDPattern.MatchString(recordingID) {
		return zero, "", nil, false, store.ErrRecordingState
	}
	if err := checkCapacityVerifier(ctx, q, key); err != nil {
		return zero, "", nil, false, err
	}
	index := recordingAudioIndex(key, recordingID)
	var id, titleID string
	var sealed, sealedTitle, lyrics []byte
	err := q.QueryRowContext(ctx, `SELECT encryption_id,sealed,title_encryption_id,sealed_title,lyric_ciphertext FROM sealed_recording_audio WHERE recording_index=?`+r.lock(), index).Scan(&id, &sealed, &titleID, &sealedTitle, &lyrics)
	if errors.Is(err, sql.ErrNoRows) {
		return zero, "", nil, false, nil
	}
	if err != nil || id == titleID || !capacityIDExists(ctx, q, id, r.lock()) || !capacityIDExists(ctx, q, titleID, r.lock()) {
		return zero, "", nil, false, store.ErrRecordingState
	}
	raw, err := openCapacityRecord(key, index, id, sealed)
	if err != nil {
		return zero, "", nil, false, err
	}
	defer clear(raw)
	var value recordingAudioIntent
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&value) != nil || dec.Decode(new(any)) != io.EOF || !validRecordingAudioIntent(value) || value.RecordingID != recordingID {
		return zero, "", nil, false, store.ErrRecordingState
	}
	title, err := openCapacityRecord(key, index, titleID, sealedTitle)
	if err != nil {
		return zero, "", nil, false, err
	}
	defer clear(title)
	if len(title) == 0 || !utf8.Valid(title) || utf8.RuneCount(title) > 255 || len(lyrics) > store.MaxRecordingMetadata {
		return zero, "", nil, false, store.ErrRecordingState
	}
	titleDigest := sha256.Sum256(title)
	if subtle.ConstantTimeCompare([]byte(value.TitleDigest), []byte(hex.EncodeToString(titleDigest[:]))) != 1 || !validRecordingAudioLyrics(value, lyrics) {
		return zero, "", nil, false, store.ErrRecordingState
	}
	return value, string(title), lyrics, true, nil
}
