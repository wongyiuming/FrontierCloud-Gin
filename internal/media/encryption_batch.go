package media

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Encryptions decorates an already-authorized catalog using bounded SQL batches.
// It does not issue keys or weaken the per-key permission check.
func (s *Service) Encryptions(ctx context.Context, ids []string) (map[string]*mediacrypto.Metadata, error) {
	if len(ids) == 0 {
		return map[string]*mediacrypto.Metadata{}, nil
	}
	repository, ok := s.repository.(store.EncryptionBatchRepository)
	if !ok {
		return nil, mediacrypto.ErrMetadata
	}
	return repository.Encryptions(ctx, ids)
}
