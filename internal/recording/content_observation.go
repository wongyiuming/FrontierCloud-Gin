package recording

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"strings"
)

// ObserveManagedContent hashes opaque bytes at the native recording mount.
// Admission must resolve current ready metadata and the active relationship.
func (s *Storage) ObserveManagedContent(ctx context.Context, item store.ExpectedPhysicalItem, bytes int64, admission func() error) (resourceinventory.ContentObservation, error) {
	var empty resourceinventory.ContentObservation
	if admission == nil || !strings.HasPrefix(item.Path, "recordings/") || item.ExpectedBytes == nil || *item.ExpectedBytes != bytes {
		return empty, resourceinventory.ErrSession
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return empty, err
	}
	defer func() {
		if release != nil {
			release()
		}
	}()
	if err = s.ready(); err != nil {
		return empty, err
	}
	if err = admission(); err != nil {
		return empty, err
	}
	release()
	release = nil
	result, err := resourceinventory.ContentAt(ctx, s.root, strings.TrimPrefix(item.Path, "recordings/"), bytes)
	if err != nil {
		return empty, err
	}
	release, err = s.acquire(ctx, false)
	if err != nil {
		return empty, err
	}
	if err = admission(); err != nil {
		return empty, err
	}
	result.Path = item.Path
	return result, nil
}
