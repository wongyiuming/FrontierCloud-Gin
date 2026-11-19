package network

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
)

func TestPublicAdmissionCommitAndFailure(t *testing.T) {
	var calls atomic.Int32
	ctx, admission := WithPublicAdmission(context.Background())
	if present, registered := RegisterPublicAdmissionAbort(ctx, func() { calls.Add(1) }); !present || !registered {
		t.Fatal("callback was not registered")
	}
	if !admission.Commit() || admission.Abort() || calls.Load() != 0 {
		t.Fatal("committed admission must preserve the authorization")
	}
	if present, registered := RegisterPublicAdmissionAbort(context.Background(), func() { calls.Add(1) }); present || registered || calls.Load() != 0 {
		t.Fatal("a request without an admission must retain its existing behavior")
	}

	ctx, admission = WithPublicAdmission(context.Background())
	RegisterPublicAdmissionAbort(ctx, func() { calls.Add(1) })
	if !admission.Abort() || !admission.Abort() || admission.Commit() || calls.Load() != 1 {
		t.Fatal("failed admission must run its callback exactly once")
	}
}

func TestPublicAdmissionCancellationAndLateRegistration(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	ctx, admission := WithPublicAdmission(parent)
	var calls atomic.Int32
	started, finish := make(chan struct{}), make(chan struct{})
	RegisterPublicAdmissionAbort(ctx, func() {
		calls.Add(1)
		close(started)
		<-finish
	})
	cancel()
	<-started
	returned := make(chan bool, 1)
	go func() { returned <- admission.Abort() }()
	select {
	case <-returned:
		t.Fatal("abort returned before concurrent rollback completed")
	default:
	}
	close(finish)
	if !<-returned || admission.Commit() || calls.Load() != 1 {
		t.Fatal("cancellation must finish rollback before returning")
	}
	if present, registered := RegisterPublicAdmissionAbort(ctx, func() { calls.Add(1) }); !present || registered || calls.Load() != 2 {
		t.Fatal("late session was not immediately rolled back")
	}
}

func TestPublicAdmissionDuplicateAndRacingCancellation(t *testing.T) {
	ctx, admission := WithPublicAdmission(context.Background())
	var calls atomic.Int32
	RegisterPublicAdmissionAbort(ctx, func() { calls.Add(1) })
	if present, registered := RegisterPublicAdmissionAbort(ctx, func() { calls.Add(1) }); !present || registered || calls.Load() != 2 || admission.Commit() {
		t.Fatal("duplicate registration must fail and revoke both authorizations")
	}

	for range 100 {
		parent, cancel := context.WithCancel(context.Background())
		ctx, admission = WithPublicAdmission(parent)
		var done atomic.Int32
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); RegisterPublicAdmissionAbort(ctx, func() { done.Add(1) }) }()
		go func() { defer wg.Done(); cancel() }()
		wg.Wait()
		admission.Abort()
		if done.Load() != 1 || admission.Commit() {
			t.Fatal("cancellation and registration raced without exactly one rollback")
		}
	}
}
