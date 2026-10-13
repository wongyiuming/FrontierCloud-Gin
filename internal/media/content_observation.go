package media

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"strings"
)

// ObserveManagedContent borrows the native media root. Admission is rechecked
// at short native mutation boundaries before and after reading bytes.
// This is an observation, not a frozen version or publication grant.
func (s *Service) ObserveManagedContent(ctx context.Context, item store.ExpectedPhysicalItem, bytes int64, admission func() error) (resourceinventory.ContentObservation, error) {
	var empty resourceinventory.ContentObservation
	if admission == nil || !strings.HasPrefix(item.Path, "media/") {
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
	object, err := s.repository.ObjectByID(ctx, item.ObjectID)
	if err != nil {
		return empty, err
	}
	if object == nil || "media/"+object.Path != item.Path {
		return empty, resourceinventory.ErrSession
	}
	digest, err := store.MigrationDigest(*object)
	if err != nil || digest != item.MetadataSHA256 {
		return empty, resourceinventory.ErrSession
	}
	if object.Encryption != nil && (object.Encryption.Validate() != nil || object.Encryption.CiphertextSize != bytes) {
		return empty, resourceinventory.ErrSession
	}
	release()
	release = nil
	result, err := resourceinventory.ContentAt(ctx, s.root, object.Path, bytes)
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
