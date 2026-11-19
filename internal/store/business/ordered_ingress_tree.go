package business

import (
	"context"
	"sync"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type orderedIngressTreeKey struct{}
type orderedIngressTreeScope struct {
	mu     sync.Mutex
	repo   *Repository
	tree   *sealedtree.TreeLease
	store  *sealedtree.SQLStore
	owner  store.OwnerControlLease
	active bool
}

// WithOrderedIngressTree is a short SQLite-only selection scope. Its caller
// must already hold this repository's genuine exclusive Owner context. It
// takes ingress, then the real tree fence, before the existing CAS begins SQL.
// It does not enable selection or authenticate any external request.
func (r *Repository) WithOrderedIngressTree(ctx context.Context, tree *sealedtree.SQLStore, fn func(context.Context) error) error {
	if r == nil || ctx == nil || tree == nil || fn == nil || r.backend != "sqlite" {
		return store.ErrNodeState
	}
	owner, ok := ctx.Value(ownerControlContextKey{}).(*ownerControlContext)
	if !ok || owner == nil || owner.repository != r {
		return store.ErrNodeState
	}
	owner.mu.RLock()
	valid := !owner.closed && validOwnerControlLease(owner.lease) && owner.lease.Check(ctx) == nil
	owner.mu.RUnlock()
	if !valid || r.checkOwnerControlMarker(ctx, r.db, owner.lease) != nil {
		return store.ErrNodeState
	}
	release, err := r.ingressLease(ctx, true)
	if err != nil {
		return err
	}
	defer release()
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil || lease == nil {
		if lease != nil {
			lease.Release()
		}
		return store.ErrNodeState
	}
	defer lease.Release()
	scope := &orderedIngressTreeScope{repo: r, tree: lease, store: tree, owner: owner.lease, active: true}
	defer func() { scope.mu.Lock(); scope.active = false; scope.mu.Unlock() }()
	if lease.Check(ctx) != nil || owner.lease.Check(ctx) != nil {
		return store.ErrNodeState
	}
	if err := fn(context.WithValue(ctx, orderedIngressTreeKey{}, scope)); err != nil {
		return err
	}
	// The scoped CAS has already committed. Do not turn a subsequent timeout
	// into a false failure after a successful durable mutation.
	return nil
}

// CheckOrderedIngressTree binds a readiness lease to the exact tree and the
// same authenticated Owner inode as the enclosing ordered writer scope.
func (r *Repository) CheckOrderedIngressTree(ctx context.Context, tree *sealedtree.SQLStore, readyOwner store.OwnerControlLease) error {
	scope, ok := ctx.Value(orderedIngressTreeKey{}).(*orderedIngressTreeScope)
	if !ok || scope == nil || scope.repo != r || tree == nil || readyOwner == nil {
		return store.ErrNodeState
	}
	scope.mu.Lock()
	defer scope.mu.Unlock()
	if !scope.active || scope.store != tree || scope.tree == nil || !validOwnerControlLease(scope.owner) || !validOwnerControlLease(readyOwner) || scope.tree.Check(ctx) != nil || scope.owner.Check(ctx) != nil || readyOwner.Check(ctx) != nil {
		return store.ErrNodeState
	}
	expected, err := scope.owner.Binding(ctx)
	if err != nil || expected == "" {
		return store.ErrNodeState
	}
	actual, err := readyOwner.Binding(ctx)
	if err != nil || actual != expected || scope.tree.Check(ctx) != nil {
		return store.ErrNodeState
	}
	return nil
}
