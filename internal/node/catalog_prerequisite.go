package node

import (
	"context"
	"sync"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// CatalogPrerequisite is an isolated ownerControl→tree composite. Production
// must not install it until every writer, recovery path and supported database
// topology has been verified to obey this order. It does not grant admission.
type CatalogPrerequisite struct {
	mu             sync.Mutex
	owner          store.OwnerControlLease
	ownerAcquire   func(context.Context) (store.OwnerControlLease, error)
	tree           *sealedtree.TreeLease
	treeStore      *sealedtree.SQLStore
	done           bool
	busy           bool
	pendingRelease bool
	checks         []func(context.Context) error
	deadline       time.Time
}

// AcquireCatalogPrerequisite acquires the node-local owner control first and
// the actual tree fence second. The trusted owner callback must verify its
// persistent DB marker and must never rebuild it.
func AcquireCatalogPrerequisite(ctx context.Context, ownerAcquire func(context.Context) (store.OwnerControlLease, error), treeStore *sealedtree.SQLStore) (*CatalogPrerequisite, error) {
	if ctx == nil || ownerAcquire == nil || treeStore == nil {
		return nil, store.ErrNodeState
	}
	owner, err := ownerAcquire(ctx)
	if err != nil || !validPrerequisiteLease(owner) {
		if validPrerequisiteLease(owner) {
			owner.Release()
		}
		return nil, store.ErrNodeState
	}
	var tree *sealedtree.TreeLease
	defer func() {
		if recovered := recover(); recovered != nil {
			defer owner.Release()
			if tree != nil {
				tree.Release()
			}
			panic(recovered)
		}
	}()
	if owner.Check(ctx) != nil {
		owner.Release()
		return nil, store.ErrNodeState
	}
	tree, err = treeStore.AcquireReadFence(ctx)
	if err != nil || tree == nil {
		if tree != nil {
			tree.Release()
		}
		owner.Release()
		return nil, store.ErrNodeState
	}
	value := &CatalogPrerequisite{owner: owner, ownerAcquire: ownerAcquire, tree: tree, treeStore: treeStore}
	if value.Check(ctx) != nil {
		value.Release()
		return nil, store.ErrNodeState
	}
	return value, nil
}

func (p *CatalogPrerequisite) Check(ctx context.Context) (result error) {
	if p == nil || ctx == nil {
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
	return ctx.Err()
}

// catalogBorrow is read-only and expires before its owner unlocks. It never
// exposes either underlying Release method or the tree lease pointer.
type catalogBorrow struct {
	mu         sync.Mutex
	active     bool
	owner      store.OwnerControlLease
	tree       *sealedtree.TreeLease
	finalizers []func()
	busy       bool
	cond       *sync.Cond
	cancel     func()
}

func (b *catalogBorrow) CancelCatalogAdmission() {
	b.mu.Lock()
	cancel := b.cancel
	active := b.active
	b.mu.Unlock()
	if active && cancel != nil {
		cancel()
	}
}

// HoldCatalogResource transfers resource cleanup to the guarded commit.
// Only trusted preparation code can obtain this in-process borrow.
func (b *catalogBorrow) HoldCatalogResource(release func()) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.active || release == nil {
		return store.ErrNodeState
	}
	b.finalizers = append(b.finalizers, release)
	return nil
}

func (b *catalogBorrow) Check(ctx context.Context) (result error) {
	if !b.begin(ctx) {
		return store.ErrNodeState
	}
	defer func() {
		if !b.end() {
			result = store.ErrNodeState
		}
	}()
	if b.owner.Check(ctx) != nil || b.tree.Check(ctx) != nil {
		return store.ErrNodeState
	}
	return ctx.Err()
}
func (b *catalogBorrow) CheckCatalogScopes(ctx context.Context, tree *sealedtree.SQLStore, checks []sealedtree.CatalogScopeCheck) (result error) {
	if tree == nil || !b.begin(ctx) {
		return store.ErrNodeState
	}
	defer func() {
		if !b.end() {
			result = store.ErrNodeState
		}
	}()
	if b.owner.Check(ctx) != nil || b.tree.Check(ctx) != nil {
		return store.ErrNodeState
	}
	return tree.CheckCatalogScopesWithLease(ctx, b.tree, checks)
}
func (b *catalogBorrow) CatalogOwnerBinding(ctx context.Context) (binding string, result error) {
	if !b.begin(ctx) {
		return "", store.ErrNodeState
	}
	defer func() {
		if !b.end() {
			binding = ""
			result = store.ErrNodeState
		}
	}()
	if b.owner.Check(ctx) != nil || b.tree.Check(ctx) != nil {
		return "", store.ErrNodeState
	}
	value, err := b.owner.Binding(ctx)
	if err != nil || value == "" {
		return "", store.ErrNodeState
	}
	return value, nil
}
func (b *catalogBorrow) begin(ctx context.Context) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ctx == nil || !b.active || b.busy {
		return false
	}
	if b.cond == nil {
		b.cond = sync.NewCond(&b.mu)
	}
	b.busy = true
	return true
}
func (b *catalogBorrow) end() bool {
	b.mu.Lock()
	valid := b.active
	b.busy = false
	b.cond.Broadcast()
	b.mu.Unlock()
	return valid
}
func (b *catalogBorrow) close() {
	b.mu.Lock()
	b.active = false
	for b.busy {
		b.cond.Wait()
	}
	finalizers := b.finalizers
	b.finalizers = nil
	b.mu.Unlock()
	for _, release := range finalizers {
		defer release()
	}
}

// commitCatalog reserves the composite across scope verification and the
// ingress transaction commit without holding its mutex in external callbacks.
// Release defers physical unlock until that reservation ends. The borrowed
// view expires before tree/owner are released.
func (p *CatalogPrerequisite) commitCatalog(ctx context.Context, check func(context.Context, store.IngressPrerequisite) error, commit func() error, releaseIngress func()) error {
	if p == nil || ctx == nil || check == nil || commit == nil || releaseIngress == nil {
		return store.ErrNodeState
	}
	p.mu.Lock()
	if p.done || p.busy {
		p.mu.Unlock()
		releaseIngress()
		return store.ErrNodeState
	}
	p.busy = true
	p.mu.Unlock()
	defer p.finishUse(true)
	defer releaseIngress()
	if !validPrerequisiteLease(p.owner) || p.tree == nil || p.owner.Check(ctx) != nil || p.tree.Check(ctx) != nil || ctx.Err() != nil {
		return store.ErrNodeState
	}
	borrow := &catalogBorrow{active: true, owner: p.owner, tree: p.tree, cancel: p.Release}
	defer borrow.close()
	if check(ctx, borrow) != nil || p.owner.Check(ctx) != nil || p.tree.Check(ctx) != nil || ctx.Err() != nil {
		return store.ErrNodeState
	}
	p.mu.Lock()
	checks := append([]func(context.Context) error(nil), p.checks...)
	p.mu.Unlock()
	for _, verify := range checks {
		if verify(ctx) != nil {
			return store.ErrNodeState
		}
	}
	if p.owner.Check(ctx) != nil || p.tree.Check(ctx) != nil || ctx.Err() != nil {
		return store.ErrNodeState
	}
	// This is the admission linearization point. A Release that wins before
	// it cancels admission; one that races after it defers actual unlock.
	p.mu.Lock()
	if p.pendingRelease || p.done || !p.deadline.IsZero() && !time.Now().Before(p.deadline) {
		p.mu.Unlock()
		return store.ErrNodeState
	}
	p.mu.Unlock()
	return commit()
}

func (p *CatalogPrerequisite) finishUse(force bool) bool {
	p.mu.Lock()
	valid := !p.done && !p.pendingRelease
	p.busy = false
	release := !p.done && (force || p.pendingRelease)
	if release {
		p.done = true
		p.checks = nil
		p.deadline = time.Time{}
	}
	p.mu.Unlock()
	if release {
		p.releaseLeases()
	}
	return valid
}
func (p *CatalogPrerequisite) releaseLeases() {
	if validPrerequisiteLease(p.owner) {
		defer p.owner.Release()
	}
	if p.tree != nil {
		p.tree.Release()
	}
}

func (p *CatalogPrerequisite) Release() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.done {
		p.mu.Unlock()
		return
	}
	if p.busy {
		p.pendingRelease = true
		p.mu.Unlock()
		return
	}
	p.done = true
	p.checks = nil
	p.deadline = time.Time{}
	p.mu.Unlock()
	p.releaseLeases()
}
