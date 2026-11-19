package store

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func recordingAudioHex(value string, size int) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == size && hex.EncodeToString(raw) == value
}

// RecordingAudioPreparationBinding binds a new recording descriptor to the
// authenticated account, current server-verified browser and recording ID.
// It does not itself authenticate any of these caller-supplied values.
func RecordingAudioPreparationBinding(userID, browser, recordingID string) (string, error) {
	if !recordingAudioHex(userID, 16) || !recordingAudioHex(recordingID, 16) || !strings.HasPrefix(browser, "browser:v2:") || !recordingAudioHex(strings.TrimPrefix(browser, "browser:v2:"), sha256.Size) {
		return "", ErrRecordingState
	}
	digest := sha256.Sum256([]byte(browser))
	return "recording-audio:v1:" + userID + ":" + hex.EncodeToString(digest[:]) + ":" + recordingID, nil
}
