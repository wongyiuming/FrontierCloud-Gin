package node

import (
	"context"
	"fmt"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// InitializeStorage is local bootstrap, not remote promotion. Follower remains
// a persisted protocol-v2 discriminator, never a deployable business role.
// Existing identities/endpoints are not silently rewritten on restart.
func (s *Service) InitializeStorage(ctx context.Context, endpoint string) error {
	endpoint, err := Endpoint(endpoint)
	if err != nil {
		return err
	}
	row, err := s.repo.ReadIdentity(ctx)
	if err != nil {
		return err
	}
	if row.Role == "Follower" && row.Endpoint == endpoint {
		return nil
	}
	if row.Role != "Standalone" || s.volume == nil {
		return fmt.Errorf("%w: only_stroge cannot replace an existing business identity or endpoint", store.ErrNodeState)
	}
	return s.volume.WithPromotion(ctx, "Follower", func(p store.NodePromotion) error {
		p.Endpoint = endpoint
		return s.emptyRecordings(ctx, func() error {
			result, err := s.repo.PromoteIdentity(ctx, p, store.NodeAudit{Actor: "local-storage-bootstrap"})
			if err == nil {
				s.identity.NodeIdentity = result
			}
			return err
		})
	})
}
