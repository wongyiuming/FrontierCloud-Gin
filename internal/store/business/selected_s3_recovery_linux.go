//go:build linux

package business

import (
	"context"
	"sync"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// recovery owns the actual cross-process control lock until every authenticated
// pending operation has reached a terminal state and a fresh audit succeeds.
// The token serializes recovery work and origin probes within this process.
type selectedS3Recovery struct {
	control     *selectedS3HeldFile
	token       chan struct{}
	audit       func(context.Context) error
	probeMember func(context.Context, string) error
}

type selectedS3RecoveryBorrow struct {
	gate     *SelectedS3FileGate
	recovery *selectedS3Recovery
	once     sync.Once
}

func (g *SelectedS3FileGate) recoveryBlocked() bool {
	if g == nil {
		return true
	}
	g.modeMu.Lock()
	defer g.modeMu.Unlock()
	return g.closing || g.recovery != nil
}

// StartSelectedS3 runs at startup. audit must use the supplied context, and
// must not capture a temporary key or reenter this gate. A successful install
// owns the recovery lock until settlement or shutdown, independent of ctx.
func (g *SelectedS3FileGate) StartSelectedS3(ctx context.Context, tree *sealedtree.SQLStore, audit func(context.Context) error, probeMember func(context.Context, string) error, install func(context.Context) error) error {
	if audit == nil || install == nil || g.recoveryBlocked() || g.valid(ctx, tree) != nil {
		return store.ErrNodeState
	}
	g.modeMu.Lock()
	if g.closing || g.starting || g.started || g.recovery != nil {
		g.modeMu.Unlock()
		return store.ErrNodeState
	}
	g.starting = true
	g.startDone = make(chan struct{})
	g.modeMu.Unlock()
	defer func() { g.modeMu.Lock(); g.starting = false; close(g.startDone); g.startDone = nil; g.modeMu.Unlock() }()
	held, err := g.acquire(ctx, "control.lock", true, false)
	if err != nil {
		return err
	}
	transferred := false
	defer func() {
		if !transferred {
			held.release()
		}
	}()
	if g.valid(ctx, tree) != nil || g.checkFile(held) != nil {
		return store.ErrNodeState
	}
	err = audit(ctx)
	if err != nil && err != ErrSelectedS3RecoveryRequired {
		return err
	}
	var recovery *selectedS3Recovery
	if err != nil {
		if probeMember == nil {
			return store.ErrNodeState
		}
		recovery = &selectedS3Recovery{control: held, token: make(chan struct{}, 1), audit: audit, probeMember: probeMember}
		recovery.token <- struct{}{}
		g.modeMu.Lock()
		if g.closing || g.recovery != nil {
			g.modeMu.Unlock()
			return store.ErrNodeState
		}
		g.recovery = recovery
		g.modeMu.Unlock()
	}
	if err = install(ctx); err != nil || g.valid(ctx, tree) != nil || g.checkFile(held) != nil || ctx.Err() != nil {
		if recovery != nil {
			g.modeMu.Lock()
			if g.recovery == recovery {
				g.recovery = nil
			}
			g.modeMu.Unlock()
		}
		if err != nil {
			return err
		}
		return store.ErrNodeState
	}
	g.modeMu.Lock()
	if g.closing {
		if g.recovery == recovery {
			g.recovery = nil
		}
		g.modeMu.Unlock()
		return store.ErrNodeState
	}
	g.started = true
	g.modeMu.Unlock()
	transferred = recovery != nil
	return nil
}

func (g *SelectedS3FileGate) borrowRecovery(ctx context.Context, tree *sealedtree.SQLStore) (*selectedS3RecoveryBorrow, bool, error) {
	if g == nil || ctx == nil {
		return nil, false, store.ErrNodeState
	}
	g.modeMu.Lock()
	recovery, closing := g.recovery, g.closing || g.starting
	g.modeMu.Unlock()
	if closing {
		return nil, false, store.ErrNodeState
	}
	if recovery == nil {
		return nil, false, nil
	}
	select {
	case <-ctx.Done():
		return nil, false, ctx.Err()
	case <-recovery.token:
	}
	borrow := &selectedS3RecoveryBorrow{gate: g, recovery: recovery}
	if borrow.check(ctx) != nil || g.valid(ctx, tree) != nil {
		borrow.release()
		return nil, false, store.ErrNodeState
	}
	return borrow, true, nil
}

func (b *selectedS3RecoveryBorrow) check(ctx context.Context) error {
	if b == nil || b.gate == nil || ctx == nil || ctx.Err() != nil {
		return store.ErrNodeState
	}
	b.gate.modeMu.Lock()
	valid := !b.gate.closing && !b.gate.starting && b.gate.recovery == b.recovery
	b.gate.modeMu.Unlock()
	if !valid || b.gate.checkFile(b.recovery.control) != nil {
		return store.ErrNodeState
	}
	return nil
}
func (b *selectedS3RecoveryBorrow) release() {
	if b != nil {
		b.once.Do(func() { b.recovery.token <- struct{}{} })
	}
}

// FinishSelectedS3Recovery is called after an authenticated terminal result.
// A failed or cancelled audit retains the exclusive recovery lock unchanged.
func (g *SelectedS3FileGate) FinishSelectedS3Recovery(ctx context.Context, tree *sealedtree.SQLStore) error {
	borrow, recovering, err := g.borrowRecovery(ctx, tree)
	if err != nil || !recovering {
		return err
	}
	defer borrow.release()
	if err = borrow.recovery.audit(ctx); err != nil {
		return err
	}
	if borrow.check(ctx) != nil || g.valid(ctx, tree) != nil {
		return store.ErrNodeState
	}
	g.modeMu.Lock()
	if g.closing || g.recovery != borrow.recovery {
		g.modeMu.Unlock()
		return store.ErrNodeState
	}
	g.recovery = nil
	borrow.recovery.control.release()
	g.modeMu.Unlock()
	return nil
}

// CloseContext stops new borrows, waits for any actual borrower to return,
// and only then releases control. Cancellation leaves the lock held for a
// later retry or process exit; it never races an outstanding operation.
func (g *SelectedS3FileGate) CloseContext(ctx context.Context) error {
	if g == nil || ctx == nil {
		return store.ErrNodeState
	}
	var recovery *selectedS3Recovery
	for {
		g.modeMu.Lock()
		g.closing = true
		if !g.starting {
			recovery = g.recovery
			g.modeMu.Unlock()
			break
		}
		done := g.startDone
		g.modeMu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
		}
	}
	if recovery != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-recovery.token:
		}
		defer func() { recovery.token <- struct{}{} }()
		g.modeMu.Lock()
		if g.recovery == recovery {
			g.recovery = nil
			recovery.control.release()
		}
		g.modeMu.Unlock()
	}
	g.modeMu.Lock()
	defer g.modeMu.Unlock()
	if g.closed {
		return nil
	}
	if g.dir == nil {
		return store.ErrNodeState
	}
	err := g.dir.Close()
	if err == nil {
		g.closed = true
	}
	return err
}
