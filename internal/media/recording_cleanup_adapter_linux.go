//go:build linux

package media

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/selectedupload"
)

// TryRecordingCleanupLease is a startup-only adapter for the real media
// volume. The caller owns release and must not treat the lease as authority.
func (s *Service) TryRecordingCleanupLease(ctx context.Context) (selectedupload.CleanupMediaLease, func(), error) {
	lease, err := s.TryRecordingCleanup(ctx)
	if err != nil {
		return nil, nil, err
	}
	return lease, lease.Release, nil
}
