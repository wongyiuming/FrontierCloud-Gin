package node

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"net/http"
)

// The retiring credential may only inspect its own inventory or finish the
// explicitly initiated retirement. It cannot authorize resource work again.
func (s *Service) AuthenticateRetirement(ctx context.Context, headers http.Header, method, path string, body []byte) (store.Relationship, error) {
	if method != "POST" || path != "/internal/v1/resource-inventory" && path != "/internal/v1/retirement" {
		return store.Relationship{}, ErrAuthentication
	}
	rel, e := s.authenticate(ctx, headers, method, path, body, false, path == "/internal/v1/retirement", true)
	if e != nil {
		return rel, e
	}
	if rel.State != "active" {
		n, e := s.repo.ReadIdentity(ctx)
		if e != nil {
			return rel, e
		}
		if n.Role != "Follower" || rel.Direction != "upstream" {
			return rel, ErrAuthentication
		}
		if _, e = s.repo.(store.RetirementFenceRepository).RetirementFence(ctx, rel.ID, n.ID); e != nil {
			return rel, ErrAuthentication
		}
	}
	return rel, nil
}
func (s *Service) RequireInventoryFollower(ctx context.Context, rel store.Relationship) error {
	n, e := s.repo.ReadIdentity(ctx)
	if e != nil {
		return e
	}
	if n.Role != "Follower" || rel.Direction != "upstream" || rel.Protocol != 2 || rel.State != "active" && rel.State != "retiring" {
		return store.ErrNodeState
	}
	return nil
}

// Ordinary Admin removal cannot bypass the independent retirement workflow.
// Pending pair cancellation and existing tombstone notification remain usable.
func (s *Service) RevokeFromAdmin(ctx context.Context, id string, audit store.NodeAudit) error {
	rel, e := s.repo.Relationship(ctx, id)
	if e != nil {
		return e
	}
	if rel.State == "active" || rel.State == "retiring" {
		return store.ErrNodeState
	}
	return s.Revoke(ctx, id, audit)
}
