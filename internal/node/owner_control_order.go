package node

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Take the node-local control fence before any media-volume mutation lock.
// Repositories without this optional startup facility retain legacy behavior;
// opaque owner control remains separately disabled until it is installed.
func (s *Service) withOwnerControlExclusive(ctx context.Context, fn func(context.Context) error) error {
	if coordinator, ok := s.repo.(store.OwnerControlCoordinator); ok {
		return coordinator.WithOwnerControlExclusive(ctx, fn)
	}
	return fn(ctx)
}
