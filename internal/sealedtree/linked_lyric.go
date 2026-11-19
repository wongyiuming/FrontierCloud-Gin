package sealedtree

import (
	"context"
	"strings"
)

// ReadLinkedVisibleLyricWithLease authenticates both sides of the persisted
// track-to-lyric relationship under one caller-owned tree lease. The returned
// paths and facts are sensitive Master memory; this method neither authorizes
// a browser session nor opens bytes. Callers must retain the lease through
// their independent user authorization and capability commit.
func (s *SQLStore) ReadLinkedVisibleLyricWithLease(ctx context.Context, lease *TreeLease, trackID string) (VisibleObject, VisibleObject, error) {
	var empty VisibleObject
	if !s.valid() || ctx == nil || lease == nil {
		return empty, empty, ErrFenceRequired
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return empty, empty, ErrFenceRequired
	}
	track, err := s.readVisibleObjectLocked(ctx, lease, trackID)
	if err != nil {
		return empty, empty, err
	}
	if track.Entry.Kind != "audio" || !strings.HasPrefix(track.Path, "music/") || track.Facts.Lyric == nil || !hexID(track.Facts.Lyric.LyricID) {
		return empty, empty, ErrInvalid
	}
	lyric, err := s.readVisibleObjectLocked(ctx, lease, track.Facts.Lyric.LyricID)
	if err != nil {
		return empty, empty, err
	}
	if lyric.Entry.Kind != "lyric" || !strings.HasPrefix(lyric.Path, "lyrics/") || lyric.Entry.ObjectID != track.Facts.Lyric.LyricID {
		return empty, empty, ErrInvalid
	}
	if err := lease.checkLocked(ctx); err != nil {
		return empty, empty, err
	}
	return track, lyric, nil
}
