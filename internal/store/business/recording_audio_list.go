package business

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type RecordingAudioWork struct {
	ID        string `json:"recording_id"`
	MemberID  string `json:"storage_member_id"`
	State     string `json:"state"`
	Bytes     int64  `json:"size_bytes"`
	CreatedAt int64  `json:"created_at"`
}

// ListRecordingAudioWork exposes only the account's bounded, actionable rows.
// Owner credentials, paths and unfinished recording content remain private.
func (s *SelectedUploadRuntime) ListRecordingAudioWork(ctx context.Context, userID string) ([]RecordingAudioWork, error) {
	if s == nil || s.repo == nil || ctx == nil || !nodeIDPattern.MatchString(userID) {
		return nil, store.ErrRecordingState
	}
	master, err := readNode(ctx, s.repo.db, "")
	if err != nil || master.Role != "Master" {
		return nil, store.ErrNodeState
	}
	rows, err := s.repo.db.QueryContext(ctx, `SELECT recording_id,storage_member_id,state,size_bytes,created_at FROM karaoke_recordings
		WHERE user_id=? AND (state='deleting' OR (state='pending' AND storage_member_id<>?)) ORDER BY created_at DESC,recording_id LIMIT 50`, userID, master.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]RecordingAudioWork, 0)
	for rows.Next() {
		var item RecordingAudioWork
		if err = rows.Scan(&item.ID, &item.MemberID, &item.State, &item.Bytes, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
