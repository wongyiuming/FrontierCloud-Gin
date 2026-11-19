package node

import (
	"context"
	"sync"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type catalogCommitGuard interface {
	IngressPrerequisiteLease
	commitCatalog(context.Context, func(context.Context, store.IngressPrerequisite) error, func() error, func()) error
}
type catalogIngressLease struct {
	mu         sync.Mutex
	done       bool
	committing bool
	ctx        context.Context
	inner      store.PublicIngressLease
	guard      catalogCommitGuard
	check      func(context.Context, store.IngressPrerequisite) error
}

// acquireOrderedCatalog discards the preliminary readiness lease before
// acquiring the final Owner -> ingress -> tree set. The first lease is only
// used to obtain the real tree and its Owner acquisition function; none of
// its observations are carried across the release.
func (s *Service) acquireOrderedCatalog(ctx context.Context) (current store.PublicIngress, ingress store.PublicIngressLease, guard *CatalogPrerequisite, err error) {
	if s == nil || s.ingressSelectionReady == nil || ctx == nil {
		return current, nil, nil, store.ErrNodeState
	}
	initial, err := s.ingressSelectionReady(ctx)
	if err != nil || !validPrerequisiteLease(initial) {
		if validPrerequisiteLease(initial) {
			initial.Release()
		}
		return current, nil, nil, store.ErrNodeState
	}
	return s.acquireOrderedCatalogFromInitial(ctx, initial)
}

func (s *Service) acquireOrderedCatalogFromInitial(ctx context.Context, initial IngressPrerequisiteLease) (current store.PublicIngress, ingress store.PublicIngressLease, guard *CatalogPrerequisite, err error) {
	if s == nil || ctx == nil || !validPrerequisiteLease(initial) {
		if validPrerequisiteLease(initial) {
			initial.Release()
		}
		return current, nil, nil, store.ErrNodeState
	}
	initialOwned := true
	defer func() {
		if initialOwned {
			initial.Release()
		}
	}()
	existing, ok := s.repo.(store.ExistingIngressRepository)
	if !ok {
		return current, nil, nil, store.ErrNodeState
	}
	pre, ok := initial.(*CatalogPrerequisite)
	if !ok || pre.ownerAcquire == nil || pre.treeStore == nil || pre.Check(ctx) != nil {
		return current, nil, nil, store.ErrNodeState
	}
	pre.mu.Lock()
	if pre.done || pre.busy || pre.pendingRelease || len(pre.checks) != 0 || !pre.deadline.IsZero() {
		pre.mu.Unlock()
		return current, nil, nil, store.ErrNodeState
	}
	acquireOwner, tree := pre.ownerAcquire, pre.treeStore
	pre.mu.Unlock()
	initial.Release()
	initialOwned = false
	configured := s.opaqueIngressTree.Load()
	if configured != nil && configured != tree {
		return current, nil, nil, store.ErrNodeState
	}
	var owner store.OwnerControlLease
	var treeLease *sealedtree.TreeLease
	var acquiredIngress store.PublicIngressLease
	complete := false
	defer func() {
		if !complete {
			if treeLease != nil {
				treeLease.Release()
			}
			if validIngressLease(acquiredIngress) {
				acquiredIngress.Release()
			}
			if validPrerequisiteLease(owner) {
				owner.Release()
			}
		}
	}()
	owner, err = acquireOwner(ctx)
	if err != nil || !validPrerequisiteLease(owner) || owner.Check(ctx) != nil {
		return current, nil, nil, store.ErrNodeState
	}
	current, ingress, err = existing.AcquireExistingIngress(ctx)
	acquiredIngress = ingress
	if err != nil || !validIngressLease(ingress) {
		return store.PublicIngress{}, nil, nil, store.ErrNodeState
	}
	treeLease, err = tree.AcquireReadFence(ctx)
	if err != nil || treeLease == nil {
		return store.PublicIngress{}, nil, nil, store.ErrNodeState
	}
	guard = &CatalogPrerequisite{owner: owner, ownerAcquire: acquireOwner, tree: treeLease, treeStore: tree}
	if guard.Check(ctx) != nil || s.opaqueIngressTree.Load() != configured || ctx.Err() != nil {
		return store.PublicIngress{}, nil, nil, store.ErrNodeState
	}
	complete = true
	return current, ingress, guard, nil
}

func (l *catalogIngressLease) Commit() error {
	l.mu.Lock()
	if l.done {
		l.mu.Unlock()
		return store.ErrNodeState
	}
	l.done = true
	l.committing = true
	l.mu.Unlock()
	defer func() { l.mu.Lock(); l.committing = false; l.mu.Unlock() }()
	return l.guard.commitCatalog(l.ctx, l.check, l.inner.Commit, l.inner.Release)
}
func (l *catalogIngressLease) Release() {
	l.mu.Lock()
	if l.done {
		committing := l.committing
		l.mu.Unlock()
		if committing {
			l.guard.Release()
		}
		return
	}
	l.done = true
	l.mu.Unlock()
	defer l.guard.Release()
	l.inner.Release()
}

// AcquireCatalogIngress is the final fence for a bounded read-only catalog
// prepared privately after a peer proof has been authenticated exactly once.
// The final admission acquires Owner, ingress and tree in that order, asks
// the trusted caller to recheck scope while they are held, and rechecks the
// same relationship instance.
// It does not authenticate a request, consume a nonce, publish a response, or
// authorize arbitrary callers. Runtime routing remains disabled until the
// authenticated precomputation and response commit are integrated.
func (s *Service) AcquireCatalogIngress(ctx context.Context, authenticated store.Relationship, expected store.PublicIngress, checkScope func(context.Context, store.IngressPrerequisite) error) (store.PublicIngress, store.PublicIngressLease, error) {
	if s == nil || ctx == nil || s.repo == nil || !s.peerIngressSelection || s.ingressSelectionReady == nil || checkScope == nil || authenticated.Direction != "downstream" || authenticated.State != "active" || authenticated.Protocol != protocol.Version || !ValidIdentifier(authenticated.ID) || !ValidIdentifier(authenticated.PeerID) || expected.NodeID != authenticated.PeerID || expected.Generation < 1 {
		return store.PublicIngress{}, nil, store.ErrNodeState
	}
	ingress, lease, guard, err := s.acquireOrderedCatalog(ctx)
	if err != nil {
		return store.PublicIngress{}, nil, store.ErrNodeState
	}
	ready := guard
	defer func() {
		if recovered := recover(); recovered != nil {
			ready.Release()
			panic(recovered)
		}
	}()
	defer func() {
		if recovered := recover(); recovered != nil {
			lease.Release()
			panic(recovered)
		}
	}()
	fail := func() (store.PublicIngress, store.PublicIngressLease, error) {
		lease.Release()
		ready.Release()
		return store.PublicIngress{}, nil, store.ErrNodeState
	}
	canonical, err := MasterEndpoint(ingress.PublicOrigin)
	if err != nil || canonical != ingress.PublicOrigin || ingress != expected || ctx.Err() != nil {
		return fail()
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" {
		return fail()
	}
	current, err := s.repo.Relationship(ctx, authenticated.ID)
	if err != nil || !sameCatalogRelationship(authenticated, current) || ready.Check(ctx) != nil || ctx.Err() != nil {
		return fail()
	}
	return ingress, &catalogIngressLease{ctx: ctx, inner: lease, guard: guard, check: checkScope}, nil
}

// Mutable health and heartbeat fields are deliberately excluded. Instance
// identity, cryptographic credentials and routing fields are all rechecked.
func sameCatalogRelationship(a, b store.Relationship) bool {
	return a.ID == b.ID && a.PeerID == b.PeerID && a.Endpoint == b.Endpoint && a.PublicKey == b.PublicKey && a.Credential == b.Credential && a.Direction == b.Direction && a.Mode == b.Mode && a.State == "active" && b.State == "active" && a.Protocol == b.Protocol && a.CreatedAt == b.CreatedAt
}

// AcquireLocalCatalogIngress is the corresponding final fence when Master
// itself is the selected ingress. The caller must already have established
// the request's trusted public origin and must not fabricate a peer identity.
func (s *Service) AcquireLocalCatalogIngress(ctx context.Context, expected store.PublicIngress, checkScope func(context.Context, store.IngressPrerequisite) error) (store.PublicIngress, store.PublicIngressLease, error) {
	if s == nil || ctx == nil || s.repo == nil || s.ingressSelectionReady == nil || checkScope == nil || !ValidIdentifier(expected.NodeID) || expected.Generation < 1 {
		return store.PublicIngress{}, nil, store.ErrNodeState
	}
	ingress, lease, guard, err := s.acquireOrderedCatalog(ctx)
	if err != nil {
		return store.PublicIngress{}, nil, store.ErrNodeState
	}
	ready := guard
	defer func() {
		if recovered := recover(); recovered != nil {
			ready.Release()
			panic(recovered)
		}
	}()
	defer func() {
		if recovered := recover(); recovered != nil {
			lease.Release()
			panic(recovered)
		}
	}()
	fail := func() (store.PublicIngress, store.PublicIngressLease, error) {
		lease.Release()
		ready.Release()
		return store.PublicIngress{}, nil, store.ErrNodeState
	}
	canonical, err := MasterEndpoint(ingress.PublicOrigin)
	if err != nil || canonical != ingress.PublicOrigin || ingress != expected || ctx.Err() != nil {
		return fail()
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" || identity.ID != expected.NodeID || ready.Check(ctx) != nil || ctx.Err() != nil {
		return fail()
	}
	return ingress, &catalogIngressLease{ctx: ctx, inner: lease, guard: guard, check: checkScope}, nil
}
