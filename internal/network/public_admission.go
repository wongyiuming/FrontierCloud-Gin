package network

import (
	"context"
	"sync"
)

// PublicAdmission is process-local request state, never an HTTP assertion. A
// handler may register the rollback of one newly created authorization while
// its caller holds an ingress lease. Committing the admission discards that
// rollback; every other exit executes it at most once.
type PublicAdmission struct {
	mu      sync.Mutex
	ctx     context.Context
	state   uint8 // 0 active, 1 committed, 2 aborted
	abort   func()
	wait    chan struct{}
	discard bool
	stop    func() bool
}

type publicAdmissionKey struct{}

// HasActivePublicAdmission reports only process-local verifier state; no HTTP
// header can supply it. It does not acquire a lease or commit admission.
func HasActivePublicAdmission(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	a, ok := ctx.Value(publicAdmissionKey{}).(*PublicAdmission)
	if !ok || a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state == 0 && a.ctx.Err() == nil
}

// WithPublicAdmission installs trusted, request-local rollback coordination.
// It is intended for the owner of a held ingress lease, not for HTTP input.
func WithPublicAdmission(ctx context.Context) (context.Context, *PublicAdmission) {
	a := &PublicAdmission{ctx: ctx}
	// The mutex also covers installation of stop if ctx is already canceled.
	a.mu.Lock()
	a.stop = context.AfterFunc(ctx, func() { a.Abort() })
	a.mu.Unlock()
	return context.WithValue(ctx, publicAdmissionKey{}, a), a
}

// RegisterPublicAdmissionAbort registers exactly one callback. When there is
// no admission, the caller can preserve its normal non-ingress behavior. If an
// admission has already failed, or a second callback is attempted, the new
// callback is executed immediately and registration fails.
func RegisterPublicAdmissionAbort(ctx context.Context, fn func()) (present, registered bool) {
	if ctx == nil {
		return false, false
	}
	a, ok := ctx.Value(publicAdmissionKey{}).(*PublicAdmission)
	if !ok || a == nil {
		return false, false
	}
	return true, a.register(fn)
}

func (a *PublicAdmission) register(fn func()) bool {
	if fn == nil {
		a.Abort()
		return false
	}
	a.mu.Lock()
	if a.state != 0 {
		if a.state == 2 {
			a.discard = true
		}
		a.mu.Unlock()
		fn()
		return false
	}
	if a.abort == nil && a.ctx.Err() == nil {
		a.abort = fn
		a.mu.Unlock()
		return true
	}
	old := a.abort
	// A duplicate registration or cancellation aborts both authorizations,
	// including if a commit races this call.
	combined := fn
	if old != nil {
		combined = func() { defer fn(); old() }
	}
	cb, done, stop := a.abortLocked(combined)
	a.mu.Unlock()
	runPublicAbort(cb, done, stop)
	return false
}

// Commit discards the rollback only if the admission is still live and its
// context has not been canceled. The lease owner calls this only after its
// ingress lease commits successfully.
func (a *PublicAdmission) Commit() bool {
	a.mu.Lock()
	if a.state != 0 {
		a.mu.Unlock()
		return false
	}
	if a.ctx.Err() != nil {
		cb, done, stop := a.abortLocked(a.abort)
		a.mu.Unlock()
		runPublicAbort(cb, done, stop)
		return false
	}
	a.state = 1
	a.abort = nil
	stop := a.stop
	a.mu.Unlock()
	if stop != nil {
		stop()
	}
	return true
}

func (a *PublicAdmission) abortLocked(fn func()) (func(), chan struct{}, func() bool) {
	a.state = 2
	a.abort = nil
	a.discard = fn != nil
	if fn != nil {
		a.wait = make(chan struct{})
	}
	return fn, a.wait, a.stop
}

func runPublicAbort(fn func(), done chan struct{}, stop func() bool) {
	if stop != nil {
		stop()
	}
	if fn != nil {
		defer close(done)
		fn()
	}
}

// Abort finishes an admission and waits for its rollback, including when
// cancellation started it concurrently. Its result reports whether any
// registered authorization must be discarded with the buffered response.
func (a *PublicAdmission) Abort() bool {
	a.mu.Lock()
	if a.state != 0 {
		done, discard := a.wait, a.discard
		a.mu.Unlock()
		if done != nil {
			<-done
		}
		return discard
	}
	cb, done, stop := a.abortLocked(a.abort)
	discard := a.discard
	a.mu.Unlock()
	runPublicAbort(cb, done, stop)
	return discard
}

// AbortPublicAdmission lets an inner recovery boundary report a panic before
// that panic is recovered by the HTTP framework.
func AbortPublicAdmission(ctx context.Context) {
	if ctx == nil {
		return
	}
	if a, ok := ctx.Value(publicAdmissionKey{}).(*PublicAdmission); ok && a != nil {
		a.Abort()
	}
}
