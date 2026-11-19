package selectedupload

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testLease struct{ released atomic.Bool }

func (l *testLease) Check(context.Context) error {
	if l.released.Load() {
		return errors.New("lease released")
	}
	return nil
}
func (l *testLease) Binding(context.Context) (string, error) { return "fixture", nil }
func (l *testLease) Release()                                { l.released.Store(true) }

type testDeadline struct {
	mu    sync.Mutex
	times []time.Time
	err   error
}

func (d *testDeadline) SetReadDeadline(v time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.times = append(d.times, v)
	return d.err
}

type testBody struct {
	closed chan struct{}
	once   sync.Once
}

func (b *testBody) Read([]byte) (int, error) { <-b.closed; return 0, io.ErrClosedPipe }
func (b *testBody) Close() error             { b.once.Do(func() { close(b.closed) }); return nil }

type blockedCloseBody struct {
	started chan struct{}
	finish  chan struct{}
}

func (*blockedCloseBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b *blockedCloseBody) Close() error {
	close(b.started)
	<-b.finish
	return nil
}

func TestStreamGuardTimeoutKeepsFenceUntilWriterExits(t *testing.T) {
	lease, deadline, body := &testLease{}, &testDeadline{}, &testBody{closed: make(chan struct{})}
	reading, writing, finish := make(chan struct{}), make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- RunStream(context.Background(), lease, deadline, body, 100*time.Millisecond, func(ctx context.Context) error {
			close(reading)
			_, err := io.Copy(io.Discard, body)
			if err == nil || ctx.Err() == nil {
				return errors.New("timed out read did not stop")
			}
			close(writing)
			<-finish // Model a staging write that remains active after socket close.
			return nil
		})
	}()
	<-reading
	select {
	case <-writing:
	case <-time.After(3 * time.Second):
		t.Fatal("deadline did not close request body")
	}
	if lease.released.Load() {
		t.Fatal("expired timer released fence while a writer remained active")
	}
	close(finish)
	if err := <-result; !errors.Is(err, context.DeadlineExceeded) || !lease.released.Load() {
		t.Fatal("deadline did not fail closed after writer exit", err)
	}
}

func TestStreamGuardRequiresSocketDeadlineAndReleasesOnCompletion(t *testing.T) {
	lease, deadline, body := &testLease{}, &testDeadline{err: errors.New("unsupported")}, &testBody{closed: make(chan struct{})}
	called := false
	if err := RunStream(context.Background(), lease, deadline, body, 0, func(context.Context) error { called = true; return nil }); err == nil || called || !lease.released.Load() {
		t.Fatal("invalid duration leaked lease or admitted transfer", err, called)
	}
	lease = &testLease{}
	if err := RunStream(context.Background(), lease, deadline, body, time.Second, func(context.Context) error { called = true; return nil }); err == nil || called || !lease.released.Load() {
		t.Fatal("unsupported deadline admitted transfer", err, called)
	}
	lease, deadline = &testLease{}, &testDeadline{}
	if err := RunStream(context.Background(), lease, deadline, body, time.Second, func(context.Context) error { return nil }); err != nil || !lease.released.Load() {
		t.Fatal("completed stream did not release lease", err)
	}
	deadline.mu.Lock()
	defer deadline.mu.Unlock()
	if len(deadline.times) != 2 || deadline.times[0].IsZero() || !deadline.times[1].IsZero() {
		t.Fatal("request deadline was not installed and cleared", deadline.times)
	}
}

func TestRunStagedChecksBeforePublicationAndHoldsPolicyFence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	lease := &testLease{}
	called := false
	err := RunStaged(ctx, lease, &testDeadline{}, &testBody{closed: make(chan struct{})}, time.Second, func(context.Context) error {
		cancel()
		return nil
	}, func(context.Context) error { called = true; return nil })
	if !errors.Is(err, context.Canceled) || called || !lease.released.Load() {
		t.Fatal("cancelled stage reached publication or leaked lease", err, called)
	}
	lease = &testLease{}
	started, finish := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- RunStaged(context.Background(), lease, &testDeadline{}, &testBody{closed: make(chan struct{})}, time.Second, func(context.Context) error { return nil }, func(ctx context.Context) error {
			if lease.released.Load() || ctx.Err() != nil {
				return errors.New("publication entered without lease")
			}
			close(started)
			<-finish
			if lease.released.Load() {
				return errors.New("lease released during publication")
			}
			return nil
		})
	}()
	<-started
	if lease.released.Load() {
		t.Fatal("policy fence released before publish finished")
	}
	close(finish)
	if err = <-result; err != nil || !lease.released.Load() {
		t.Fatal("staged success did not release fence", err)
	}
}

func TestStreamGuardActualHTTPPartialClientTimesOut(t *testing.T) {
	lease := &testLease{}
	result := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := RunStream(r.Context(), lease, http.NewResponseController(w), r.Body, 200*time.Millisecond, func(context.Context) error {
			_, err := io.Copy(io.Discard, r.Body)
			return err
		})
		result <- err
	}))
	defer server.Close()
	conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := fmt.Fprint(conn, "POST / HTTP/1.1\r\nHost: fixture.test\r\nContent-Length: 1000\r\n\r\nx"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil || !lease.released.Load() {
			t.Fatal("partial request succeeded or retained its completed lease", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop the partial request at its own deadline")
	}
}

func TestStreamGuardPanicJoinsWatcherBeforeFenceRelease(t *testing.T) {
	lease, deadline := &testLease{}, &testDeadline{}
	body := &blockedCloseBody{started: make(chan struct{}), finish: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	recovered := make(chan any, 1)
	go func() {
		defer func() { recovered <- recover() }()
		_ = RunStream(ctx, lease, deadline, body, time.Second, func(context.Context) error {
			cancel()
			<-body.started
			panic("transfer-panic")
		})
	}()
	select {
	case <-body.started:
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation watcher did not start")
	}
	select {
	case value := <-recovered:
		t.Fatal("panic escaped before body close completed", value)
	default:
	}
	if lease.released.Load() {
		t.Fatal("panic released the fence while cancellation was active")
	}
	close(body.finish)
	select {
	case value := <-recovered:
		if value != "transfer-panic" || !lease.released.Load() {
			t.Fatal("original panic or fence release lost", value)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("panic remained blocked after close finished")
	}
	deadline.mu.Lock()
	defer deadline.mu.Unlock()
	if len(deadline.times) < 2 || !deadline.times[len(deadline.times)-1].IsZero() {
		t.Fatal("panic failed to clear deadline", deadline.times)
	}
}
