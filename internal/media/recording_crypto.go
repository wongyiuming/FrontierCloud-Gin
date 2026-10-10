package media

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// RecordingLyricSnapshot authorizes the independently retained recording
// snapshot. The original media relation may have been renamed or removed.
func (s *Service) RecordingLyricSnapshot(ctx context.Context, userID, recordingID string) (*store.RecordingEncryptedLyrics, error) {
	role, err := s.role(ctx)
	if err != nil {
		return nil, err
	}
	if role != "Master" {
		return nil, store.ErrRecordingMissing
	}
	recordings, ok := s.repository.(store.RecordingRepository)
	if !ok {
		return nil, store.ErrRecordingState
	}
	registry, ok := s.repository.(store.RecordingEncryptionRepository)
	if !ok {
		return nil, store.ErrRecordingState
	}
	row, err := recordings.Recording(ctx, recordingID)
	if err != nil {
		return nil, err
	}
	if row == nil || row.UserID != userID || row.State != "ready" {
		return nil, store.ErrRecordingMissing
	}
	if row.EncryptedLyrics == nil || !store.ValidRecordingEncryptedLyrics(*row.EncryptedLyrics) {
		return nil, store.ErrRecordingState
	}
	meta, err := registry.RecordingEncryption(ctx, row.ID)
	if err != nil {
		return nil, err
	}
	if meta == nil || *meta != row.EncryptedLyrics.Encryption {
		return nil, mediacrypto.ErrMetadata
	}
	snapshot := *row.EncryptedLyrics
	return &snapshot, nil
}
