package media

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

type catalogGuardHolder struct {
	finish    func()
	cancelled atomic.Bool
}

func (*catalogGuardHolder) Check(context.Context) error          { return nil }
func (h *catalogGuardHolder) CancelCatalogAdmission()            { h.cancelled.Store(true) }
func (h *catalogGuardHolder) HoldCatalogResource(f func()) error { h.finish = f; return nil }

type catalogGuardResource struct {
	released  chan struct{}
	onRelease func()
	onCheck   func()
}

func (r *catalogGuardResource) Check(context.Context) error {
	if r.onCheck != nil {
		r.onCheck()
	}
	return nil
}
func (r *catalogGuardResource) Release() {
	if r.onRelease != nil {
		r.onRelease()
	}
	close(r.released)
}

func TestCatalogResourceReleaseDefersUnlockAndCancelsAdmission(t *testing.T) {
	g := &catalogResourceGuard{}
	h := &catalogGuardHolder{}
	r := &catalogGuardResource{released: make(chan struct{})}
	if err := g.begin(h); err != nil {
		t.Fatal(err)
	}
	if !g.add(r) {
		t.Fatal("resource not retained")
	}
	done := make(chan struct{})
	go func() { g.release(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("release blocked during final commit")
	}
	if !h.cancelled.Load() {
		t.Fatal("release did not cancel pending admission")
	}
	select {
	case <-r.released:
		t.Fatal("lease escaped final commit")
	default:
	}
	h.finish()
	select {
	case <-r.released:
	default:
		t.Fatal("resource not released")
	}
	if err := g.begin(&catalogGuardHolder{}); err == nil {
		t.Fatal("closed resource reused")
	}
}

func TestCatalogResourceReentrantReleaseDoesNotDeadlock(t *testing.T) {
	g := &catalogResourceGuard{}
	h := &catalogGuardHolder{}
	if err := g.begin(h); err != nil {
		t.Fatal(err)
	}
	acquire := func() *catalogGuardResource {
		g.release()
		return &catalogGuardResource{released: make(chan struct{}), onCheck: g.release, onRelease: g.release}
	}
	r := acquire()
	if !g.add(r) {
		t.Fatal("resource not retained")
	}
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { h.finish(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reentrant release deadlocked")
	}
	select {
	case <-r.released:
	default:
		t.Fatal("resource not released")
	}
}

func TestCatalogResourcePanicStillReleasesOtherResources(t *testing.T) {
	g := &catalogResourceGuard{}
	h := &catalogGuardHolder{}
	if err := g.begin(h); err != nil {
		t.Fatal(err)
	}
	first := &catalogGuardResource{released: make(chan struct{})}
	panics := &catalogGuardResource{released: make(chan struct{}), onRelease: func() { panic("fixture") }}
	if !g.add(first) || !g.add(panics) {
		t.Fatal("resource not retained")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("missing panic")
			}
		}()
		h.finish()
	}()
	select {
	case <-first.released:
	default:
		t.Fatal("panic stranded other resource")
	}
	g.release()
}
