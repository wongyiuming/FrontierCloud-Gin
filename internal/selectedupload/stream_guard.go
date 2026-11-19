// Package selectedupload contains dormant admission primitives for the future
// policy-bound upload endpoint. It registers no route and authorizes no caller.
package selectedupload

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// ReadDeadline controls the actual request connection, for example an
// http.ResponseController. Implementations that cannot set it must fail closed.
type ReadDeadline interface {
	SetReadDeadline(time.Time) error
}

// RunStream owns lease until transfer has actually returned and any cancellation
// close has finished. A timer never releases it while code may still write.
// Deadline cancellation closes the request body and forces the socket deadline;
// the transfer must honor ctx and finish or recover durable staging state. A
// kernel/filesystem write stuck independently of the request body cannot be
// forcibly terminated by this helper; the lease stays held in that case. The
// transfer function must not return while any spawned writer or cleanup is live.
// Admission/authentication and owner-policy verification occur before this call.
func RunStream(ctx context.Context, lease store.OwnerControlLease, deadline ReadDeadline, body io.ReadCloser, maximum time.Duration, transfer func(context.Context) error) (result error) {
	if lease == nil {
		return errors.New("invalid selected upload stream guard")
	}
	defer lease.Release()
	if ctx == nil || deadline == nil || body == nil || transfer == nil || maximum <= 0 || maximum > 24*time.Hour {
		return errors.New("invalid selected upload stream guard")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := lease.Check(ctx); err != nil {
		return err
	}
	end := time.Now().Add(maximum)
	if prior, ok := ctx.Deadline(); ok && prior.Before(end) {
		end = prior
	}
	if err := deadline.SetReadDeadline(end); err != nil {
		return err
	}
	bounded, cancel := context.WithDeadline(ctx, end)
	defer cancel()
	finished, watcherDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-bounded.Done():
			_ = deadline.SetReadDeadline(time.Now())
			_ = body.Close()
		case <-finished:
		}
	}()
	// This deferred join also runs during panic unwinding. The original panic
	// propagates only after the watcher has stopped and the deadline is cleared,
	// before the earlier deferred lease release is allowed to execute.
	defer func() {
		close(finished)
		<-watcherDone
		resetErr := deadline.SetReadDeadline(time.Time{})
		if bounded.Err() != nil {
			result = bounded.Err()
		} else if result == nil && resetErr != nil {
			result = resetErr
		} else if result == nil {
			result = lease.Check(ctx)
		}
	}()
	return transfer(bounded)
}

// RunStaged keeps the Owner policy lease through both durable staging and the
// publication decision. stage must only write a private staging location;
// publish must synchronously perform the final mutation and check its context
// immediately before that mutation. Neither callback may leave background
// writers. Authentication and short-lived capability admission happen before
// this call; a later Admin logout does not revoke an already admitted stream.
// This coordinator does not commit Master metadata or authorize a route.
func RunStaged(ctx context.Context, lease store.OwnerControlLease, deadline ReadDeadline, body io.ReadCloser, maximum time.Duration, stage, publish func(context.Context) error) error {
	if stage == nil || publish == nil {
		if lease != nil {
			lease.Release()
		}
		return errors.New("invalid selected upload stages")
	}
	return RunStream(ctx, lease, deadline, body, maximum, func(bounded context.Context) error {
		if err := stage(bounded); err != nil {
			return err
		}
		if err := bounded.Err(); err != nil {
			return err
		}
		if err := lease.Check(bounded); err != nil {
			return err
		}
		return publish(bounded)
	})
}
