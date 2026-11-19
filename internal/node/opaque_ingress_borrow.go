package node

import (
	"context"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// ingressTreeBorrow never exposes release or the underlying tree lease. It is
// valid only while its composite remains held by the ingress admission.
type ingressTreeBorrow struct{ prerequisite *CatalogPrerequisite }

// RegisterPrecommitCheck adds a trusted in-process recheck to the same final
// admission that owns this tree borrow. The callback cannot release its lease.
func (b *ingressTreeBorrow) RegisterPrecommitCheck(check func(context.Context) error, deadline time.Time) error {
	if b == nil || b.prerequisite == nil || check == nil {
		return store.ErrNodeState
	}
	p := b.prerequisite
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done || p.busy || p.pendingRelease || len(p.checks) >= 32 || !deadline.IsZero() && !time.Now().Before(deadline) {
		return store.ErrNodeState
	}
	p.checks = append(p.checks, check)
	if !deadline.IsZero() && (p.deadline.IsZero() || deadline.Before(p.deadline)) {
		p.deadline = deadline
	}
	return nil
}

// ConfigureOpaqueIngressSelectionTree binds the opaque peer probe requirement
// to the exact fenced tree used by the prepared Master's ingress readiness.
// It runs during startup or the explicit Master ingress recovery path.
func (s *Service) ConfigureOpaqueIngressSelectionTree(ctx context.Context, tree *sealedtree.SQLStore) error {
	return s.bindOpaqueIngressSelectionTree(ctx, tree, nil)
}

// RevalidateSelectedOpaqueIngress refreshes the selected peer's heartbeat and
// signed readiness proofs. It may finish an earlier partial installation, but
// never writes a selection or accepts a different one.
func (s *Service) RevalidateSelectedOpaqueIngress(ctx context.Context, tree *sealedtree.SQLStore, expected store.PublicIngress) error {
	return s.bindOpaqueIngressSelectionTree(ctx, tree, &expected)
}

func (s *Service) bindOpaqueIngressSelectionTree(ctx context.Context, tree *sealedtree.SQLStore, expected *store.PublicIngress) error {
	if s == nil || ctx == nil || tree == nil || s.ingressSelectionReady == nil {
		return store.ErrNodeState
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" {
		return store.ErrNodeState
	}
	routing, ok := s.repo.(store.PublicRoutingRepository)
	if !ok {
		return store.ErrNodeState
	}
	read := routing.PublicIngress
	if expected != nil {
		existing, ok := s.repo.(store.ExistingIngressRepository)
		if !ok {
			return store.ErrNodeState
		}
		read = existing.ExistingPublicIngress
	}
	current, err := read(ctx)
	if err != nil || expected != nil && (current != *expected || current.NodeID == identity.ID) {
		return store.ErrNodeState
	}
	var relation store.Relationship
	var challenge, opaqueChallenge string
	var proof, opaqueProof Envelope
	var started time.Time
	checkCtx := ctx
	if current.NodeID != identity.ID {
		relations, e := s.repo.Relationships(ctx, false)
		if e != nil {
			return store.ErrNodeState
		}
		for _, candidate := range relations {
			if candidate.PeerID == current.NodeID && candidate.Direction == "downstream" && candidate.State == "active" {
				if relation.ID != "" {
					return store.ErrNodeState
				}
				relation = candidate
			}
		}
		if relation.ID == "" {
			return store.ErrNodeState
		}
		if expected != nil {
			// A cold restart can outlast the heartbeat's freshness window.
			heartbeat, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := s.Tick(heartbeat, relation)
			cancel()
			if err != nil {
				return err
			}
			probe, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			ctx = probe
		}
		started = time.Now()
		origin, signedChallenge, signed, e := s.verifyFollowerIngressProxyEvidence(ctx, relation.ID)
		if e != nil || origin != current.PublicOrigin {
			return store.ErrNodeState
		}
		challenge, proof = signedChallenge, signed
		opaqueChallenge, opaqueProof, e = s.verifyFollowerOpaqueReadinessEvidence(ctx, relation, origin)
		if e != nil {
			return store.ErrNodeState
		}
		var cancel context.CancelFunc
		checkCtx, cancel = context.WithDeadline(ctx, started.Add(time.Duration(protocol.TokenSeconds)*time.Second))
		defer cancel()
	}
	ready, err := s.ingressSelectionReady(checkCtx)
	if err != nil || !validPrerequisiteLease(ready) {
		if validPrerequisiteLease(ready) {
			ready.Release()
		}
		return store.ErrNodeState
	}
	defer ready.Release()
	composite, ok := ready.(*CatalogPrerequisite)
	if !ok || composite.treeStore != tree || composite.Check(checkCtx) != nil {
		return store.ErrNodeState
	}
	s.opaqueIngressMu.Lock()
	defer s.opaqueIngressMu.Unlock()
	nowIdentity, err := s.repo.ReadIdentity(checkCtx)
	if err != nil || nowIdentity != identity {
		return store.ErrNodeState
	}
	nowIngress, err := read(checkCtx)
	if err != nil || nowIngress != current {
		return store.ErrNodeState
	}
	if current.NodeID != identity.ID {
		verified, e := s.repo.Relationship(checkCtx, relation.ID)
		if e != nil || !sameCatalogRelationship(relation, verified) || validateSelectionProbe(verified, challenge, proof, started, time.Now()) != nil || validateSelectionOpaqueProbe(verified, opaqueChallenge, opaqueProof, started, time.Now()) != nil {
			return store.ErrNodeState
		}
	}
	if composite.Check(checkCtx) != nil || checkCtx.Err() != nil {
		return store.ErrNodeState
	}
	if expected != nil && s.opaqueIngressTree.Load() == tree {
		return nil
	}
	if !s.opaqueIngressTree.CompareAndSwap(nil, tree) {
		return store.ErrNodeState
	}
	return nil
}

func (b *ingressTreeBorrow) Check(ctx context.Context) error {
	if b == nil || b.prerequisite == nil {
		return store.ErrNodeState
	}
	return b.prerequisite.Check(ctx)
}

func (p *CatalogPrerequisite) readTree(ctx context.Context, read func(*sealedtree.TreeLease) error) (result error) {
	if p == nil || ctx == nil || read == nil {
		return store.ErrNodeState
	}
	p.mu.Lock()
	if p.done || p.busy || !validPrerequisiteLease(p.owner) || p.tree == nil {
		p.mu.Unlock()
		return store.ErrNodeState
	}
	p.busy = true
	p.mu.Unlock()
	defer func() {
		if !p.finishUse(false) {
			result = store.ErrNodeState
		}
	}()
	if p.owner.Check(ctx) != nil || p.tree.Check(ctx) != nil {
		return store.ErrNodeState
	}
	if err := read(p.tree); err != nil {
		return err
	}
	if p.owner.Check(ctx) != nil || p.tree.Check(ctx) != nil {
		return store.ErrNodeState
	}
	return ctx.Err()
}

func (b *ingressTreeBorrow) ReadVisibleObject(ctx context.Context, tree *sealedtree.SQLStore, id string) (out sealedtree.VisibleObject, result error) {
	if b == nil || b.prerequisite == nil || tree == nil {
		return out, store.ErrNodeState
	}
	result = b.prerequisite.readTree(ctx, func(lease *sealedtree.TreeLease) error {
		var err error
		out, err = tree.ReadVisibleObjectWithLease(ctx, lease, id)
		return err
	})
	if result != nil {
		out = sealedtree.VisibleObject{}
	}
	return
}
func (b *ingressTreeBorrow) ReadVisibleObjectByAlias(ctx context.Context, tree *sealedtree.SQLStore, alias string) (out sealedtree.VisibleObject, result error) {
	if b == nil || b.prerequisite == nil || tree == nil {
		return out, store.ErrNodeState
	}
	result = b.prerequisite.readTree(ctx, func(lease *sealedtree.TreeLease) error {
		var err error
		out, err = tree.ReadVisibleObjectByAliasWithLease(ctx, lease, alias)
		return err
	})
	if result != nil {
		out = sealedtree.VisibleObject{}
	}
	return
}
func (b *ingressTreeBorrow) ReadLinkedVisibleLyric(ctx context.Context, tree *sealedtree.SQLStore, id string) (track, lyric sealedtree.VisibleObject, result error) {
	if b == nil || b.prerequisite == nil || tree == nil {
		return track, lyric, store.ErrNodeState
	}
	result = b.prerequisite.readTree(ctx, func(lease *sealedtree.TreeLease) error {
		var err error
		track, lyric, err = tree.ReadLinkedVisibleLyricWithLease(ctx, lease, id)
		return err
	})
	if result != nil {
		track, lyric = sealedtree.VisibleObject{}, sealedtree.VisibleObject{}
	}
	return
}

func (b *ingressTreeBorrow) SelectLyricForDisplay(ctx context.Context, tree *sealedtree.SQLStore, id string) (out sealedtree.LyricSelection, result error) {
	if b == nil || b.prerequisite == nil || tree == nil {
		return out, store.ErrNodeState
	}
	result = b.prerequisite.readTree(ctx, func(lease *sealedtree.TreeLease) error {
		var err error
		out, err = tree.SelectLyricForDisplayWithLease(ctx, lease, id)
		return err
	})
	if result != nil {
		out = sealedtree.LyricSelection{}
	}
	return
}

func (b *ingressTreeBorrow) ReadListingObject(ctx context.Context, tree *sealedtree.SQLStore, id string, includeHidden bool) (out sealedtree.ListingObject, result error) {
	if b == nil || b.prerequisite == nil || tree == nil {
		return out, store.ErrNodeState
	}
	result = b.prerequisite.readTree(ctx, func(lease *sealedtree.TreeLease) error {
		var err error
		out, err = tree.ReadListingObjectWithLease(ctx, lease, id, includeHidden)
		return err
	})
	if result != nil {
		out = sealedtree.ListingObject{}
	}
	return
}

func (b *ingressTreeBorrow) ReadListingObjectByAlias(ctx context.Context, tree *sealedtree.SQLStore, alias string, includeHidden bool) (out sealedtree.ListingObject, result error) {
	if b == nil || b.prerequisite == nil || tree == nil {
		return out, store.ErrNodeState
	}
	result = b.prerequisite.readTree(ctx, func(lease *sealedtree.TreeLease) error {
		var err error
		out, err = tree.ReadListingObjectByAliasWithLease(ctx, lease, alias, includeHidden)
		return err
	})
	if result != nil {
		out = sealedtree.ListingObject{}
	}
	return
}

// ReadS3ListingObject borrows the already-admitted tree lease; it does not
// grant provider access or allow the caller to release the composite lease.
func (b *ingressTreeBorrow) ReadS3ListingObject(ctx context.Context, tree *sealedtree.SQLStore, id string, includeHidden bool) (out sealedtree.S3ListingObject, result error) {
	if b == nil || b.prerequisite == nil || tree == nil {
		return out, store.ErrNodeState
	}
	result = b.prerequisite.readTree(ctx, func(lease *sealedtree.TreeLease) error {
		var err error
		out, err = tree.ReadS3ListingObjectWithLease(ctx, lease, id, includeHidden)
		return err
	})
	if result != nil {
		out = sealedtree.S3ListingObject{}
	}
	return
}
