package media

import (
	"sync"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// catalogResourceGuard retains all resources until final admission ends. An
// overlapping Release is deferred; external callbacks never run under mu.
type catalogResourceGuard struct {
	mu             sync.Mutex
	active, closed bool
	held           []CatalogResourceLease
	cancel         func()
}

func releaseCatalogResources(held []CatalogResourceLease) {
	for _, lease := range held {
		defer lease.Release()
	}
}

func (g *catalogResourceGuard) finish() {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	g.closed = true
	g.active = false
	held := g.held
	g.held = nil
	g.cancel = nil
	g.mu.Unlock()
	releaseCatalogResources(held)
}

// release may return while final admission is active. In that case ownership
// has transferred to its guard and actual resource release is deferred until
// its finalizer, even if this call is reentrant from a resource callback.
func (g *catalogResourceGuard) release() {
	g.mu.Lock()
	if g.active {
		cancel := g.cancel
		g.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		return
	}
	if g.closed {
		g.mu.Unlock()
		return
	}
	g.closed = true
	held := g.held
	g.held = nil
	g.mu.Unlock()
	releaseCatalogResources(held)
}

func (g *catalogResourceGuard) begin(prerequisite store.IngressPrerequisite) (err error) {
	holder, ok := prerequisite.(interface {
		HoldCatalogResource(func()) error
		CancelCatalogAdmission()
	})
	if !ok {
		return ErrUnavailable
	}
	g.mu.Lock()
	if g.closed || g.active {
		g.mu.Unlock()
		return ErrUnavailable
	}
	g.active = true
	g.cancel = holder.CancelCatalogAdmission
	g.mu.Unlock()
	registered := false
	defer func() {
		if !registered {
			g.finish()
		}
	}()
	if err = holder.HoldCatalogResource(g.finish); err != nil {
		return ErrUnavailable
	}
	registered = true
	return nil
}

func (g *catalogResourceGuard) add(lease CatalogResourceLease) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.active || g.closed {
		return false
	}
	g.held = append(g.held, lease)
	return true
}

func (g *catalogResourceGuard) resources() []CatalogResourceLease {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]CatalogResourceLease(nil), g.held...)
}
