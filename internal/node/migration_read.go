package node

import (
	"context"
	"sync"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// ProtectOwnedRead is called only after capability validation, before delivering
// bytes. Its joined renewal worker keeps the durable lease alive for the actual
// Go stream. Failure cancels the stream and closes its pinned file. It does not
// claim to observe a separate Nginx X-Accel transfer's lifetime.
func (s *Service) ProtectOwnedRead(ctx context.Context, relationship, logical, physical, resource string, closeStream func()) (context.Context, func(), error) {
	return s.protectOwnedRead(ctx, relationship, logical, physical, resource, closeStream, 30*time.Second)
}

func (s *Service) protectOwnedRead(ctx context.Context, relationship, logical, physical, resource string, closeStream func(), interval time.Duration) (context.Context, func(), error) {
	r, ok := s.repo.(store.MigrationReadRepository)
	if !ok {
		return nil, nil, store.ErrMigrationState
	}
	id, e := r.AcquireMigrationRead(ctx, relationship, logical, physical, resource)
	if e != nil {
		return nil, nil, e
	}
	readCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-readCtx.Done():
				return
			case <-ticker.C:
				checkCtx, stop := context.WithTimeout(readCtx, 10*time.Second)
				e := r.RenewMigrationRead(checkCtx, relationship, id)
				stop()
				if e != nil {
					cancel()
					closeStream()
					return
				}
			}
		}
	}()
	var once sync.Once
	release := func() {
		once.Do(func() {
			cancel()
			<-done
			cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			// Failed release leaves a bounded durable lease; it is never a successful
			// cleanup receipt. Expiry is checked again by the deletion transaction.
			_ = r.ReleaseMigrationRead(cleanup, id)
		})
	}
	return readCtx, release, nil
}
