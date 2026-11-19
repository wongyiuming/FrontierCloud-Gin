package node

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// OpaqueIngressSelectionTreeMatches permits a recovery retry to finish after a
// durable selection was committed but its response or readiness check failed.
func (s *Service) OpaqueIngressSelectionTreeMatches(tree *sealedtree.SQLStore) bool {
	return s != nil && tree != nil && s.opaqueIngressTree.Load() == tree
}

// RecoverMasterIngress is for the separately authenticated recovery-only
// control plane. It can select only this Master, never a peer, and uses the
// same Owner -> ingress -> tree -> SQL fencing and generation CAS as selection.
// The caller must keep normal business routes closed until tree readiness is
// re-established after a successful commit.
func (s *Service) RecoverMasterIngress(ctx context.Context, tree *sealedtree.SQLStore, memberID string, expected int64, audit store.NodeAudit) (store.PublicIngress, error) {
	var selected store.PublicIngress
	if s == nil || ctx == nil || tree == nil || s.repo == nil || s.ingressSelectionReady == nil || !ValidIdentifier(memberID) || expected < 1 || s.masterPublicOrigin == "" {
		return selected, store.ErrNodeState
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" || memberID != identity.ID {
		return selected, store.ErrNodeState
	}
	coordinator, ok := s.repo.(store.OwnerControlCoordinator)
	if !ok {
		return selected, store.ErrNodeState
	}
	ordered, ok := s.repo.(interface {
		WithOrderedIngressTree(context.Context, *sealedtree.SQLStore, func(context.Context) error) error
	})
	if !ok {
		return selected, store.ErrNodeState
	}
	routing, ok := s.repo.(store.PublicRoutingRepository)
	if !ok {
		return selected, store.ErrNodeState
	}
	err = coordinator.WithOwnerControlExclusive(ctx, func(held context.Context) error {
		return ordered.WithOrderedIngressTree(held, tree, func(locked context.Context) error {
			ready, e := s.ingressSelectionReady(locked)
			if e != nil || !validPrerequisiteLease(ready) {
				if validPrerequisiteLease(ready) {
					ready.Release()
				}
				return store.ErrNodeState
			}
			defer ready.Release()
			composite, ok := ready.(*CatalogPrerequisite)
			validator, validates := s.repo.(interface {
				CheckOrderedIngressTree(context.Context, *sealedtree.SQLStore, store.OwnerControlLease) error
			})
			if !ok || !validates || composite.treeStore != tree || ready.Check(locked) != nil || validator.CheckOrderedIngressTree(locked, tree, composite.owner) != nil {
				return store.ErrNodeState
			}
			current, e := s.repo.ReadIdentity(locked)
			if e != nil || current != identity || locked.Err() != nil {
				return store.ErrNodeState
			}
			selected, e = routing.CommitMasterPublicIngress(locked, s.masterPublicOrigin, expected, audit)
			return e
		})
	})
	if err != nil {
		return store.PublicIngress{}, err
	}
	s.Wake()
	return selected, nil
}
