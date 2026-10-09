package media

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Advancing this clock delivers only due timers, without sleeping or changing
// the process/system clock. The production scheduler itself runs unchanged.
type controlledRecoveryClock struct {
	mu      sync.Mutex
	now     time.Time
	timers  []*controlledRecoveryTimer
	created chan *controlledRecoveryTimer
}

type controlledRecoveryTimer struct {
	clock   *controlledRecoveryClock
	due     time.Time
	ch      chan time.Time
	fired   bool
	stopped bool
}

type recoverySweepInvocation struct {
	ctx    context.Context
	budget time.Duration
}

func (t *controlledRecoveryTimer) channel() <-chan time.Time { return t.ch }
func (t *controlledRecoveryTimer) stop() {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	t.stopped = true
}

func newControlledRecoveryClock() *controlledRecoveryClock {
	return &controlledRecoveryClock{now: time.Unix(1_700_000_000, 0), created: make(chan *controlledRecoveryTimer, 8)}
}

func (c *controlledRecoveryClock) newTimer(delay time.Duration) uploadRecoveryTimer {
	c.mu.Lock()
	timer := &controlledRecoveryTimer{clock: c, due: c.now.Add(delay), ch: make(chan time.Time, 1)}
	c.timers = append(c.timers, timer)
	c.mu.Unlock()
	c.created <- timer
	return timer
}

func (c *controlledRecoveryClock) advance(delta time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(delta)
	fired := 0
	for _, timer := range c.timers {
		if !timer.stopped && !timer.fired && !timer.due.After(c.now) {
			timer.fired = true
			timer.ch <- c.now
			fired++
		}
	}
	return fired
}

func waitRecoverySignal[T any](t *testing.T, channel <-chan T) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(10 * time.Second):
		t.Fatal("recovery scheduler did not reach synchronization point")
		var zero T
		return zero
	}
}

func TestUploadRecoveryCooldownStartsAfterShortAndLongSweep(t *testing.T) {
	for _, duration := range []time.Duration{15 * time.Second, 75 * time.Second} {
		t.Run(duration.String(), func(t *testing.T) {
			clock := newControlledRecoveryClock()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := make(chan recoverySweepInvocation, 2)
			finishFirst := make(chan struct{})
			done := make(chan struct{})
			go func() {
				defer close(done)
				n := 0
				runUploadRecovery(ctx, func(bounded context.Context) error {
					n++
					deadline, _ := bounded.Deadline()
					calls <- recoverySweepInvocation{ctx: bounded, budget: time.Until(deadline)}
					if n == 1 {
						select {
						case <-finishFirst:
							return context.DeadlineExceeded
						case <-bounded.Done():
							return bounded.Err()
						}
					}
					<-bounded.Done()
					return bounded.Err()
				}, clock.newTimer)
			}()
			first := waitRecoverySignal(t, calls)
			if first.budget < 179*time.Second || first.budget > 180*time.Second {
				t.Fatal("180-second investigation budget regressed", first.budget)
			}
			// Immediate first sweep must not create a timer before doing work;
			// even a sweep longer than 30s cannot accumulate an old tick.
			if clock.advance(duration) != 0 {
				t.Fatal("cooldown timer started before work completed")
			}
			close(finishFirst)
			timer := waitRecoverySignal(t, clock.created)
			if timer.due != time.Unix(1_700_000_000, 0).Add(duration+30*time.Second) {
				t.Fatal("cooldown was not measured from sweep completion", timer.due)
			}
			if first.ctx.Err() != context.Canceled {
				t.Fatal("completed sweep context not released", first.ctx.Err())
			}
			if clock.advance(29*time.Second) != 0 {
				t.Fatal("cooldown released before its complete interval")
			}
			select {
			case <-calls:
				t.Fatal("next sweep started inside cooldown")
			default:
			}
			if clock.advance(time.Second) != 1 {
				t.Fatal("full cooldown did not release exactly one sweep")
			}
			waitRecoverySignal(t, calls)
			cancel()
			waitRecoverySignal(t, done)
			if clock.advance(time.Hour) != 0 {
				t.Fatal("canceled recovery retained an active timer")
			}
		})
	}
}

func TestUploadRecoveryCancellationStopsCooldownAndPreventsNextSweep(t *testing.T) {
	clock := newControlledRecoveryClock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := make(chan struct{}, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runUploadRecovery(ctx, func(context.Context) error { calls <- struct{}{}; return nil }, clock.newTimer)
	}()
	waitRecoverySignal(t, calls)
	waitRecoverySignal(t, clock.created)
	cancel()
	waitRecoverySignal(t, done)
	if clock.advance(time.Minute) != 0 {
		t.Fatal("cooldown timer survived cancellation")
	}
	select {
	case <-calls:
		t.Fatal("a new sweep ran after cancellation")
	default:
	}
}

func TestUploadRecoveryAlreadyCanceledDoesNotStartFirstSweep(t *testing.T) {
	clock := newControlledRecoveryClock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	runUploadRecovery(ctx, func(context.Context) error { called = true; return nil }, clock.newTimer)
	if called || len(clock.timers) != 0 {
		t.Fatal("already canceled scheduler started work or a timer")
	}
}
