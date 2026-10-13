package node

import (
	"bytes"
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// ValidateRetainedIdentity opens only the runtime's configured vault and proves
// that it still decrypts the persisted identity used by this process. Keys and
// key fingerprints are never included in inventory responses.
func (s *Service) ValidateRetainedIdentity(ctx context.Context, directory string) error {
	current, e := OpenExisting(ctx, s.repo, directory)
	if e != nil {
		return e
	}
	if current.ID != s.identity.ID || !bytes.Equal(current.private, s.identity.private) {
		return store.ErrNodeState
	}
	return nil
}
