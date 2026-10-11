package certmanager

import (
	"context"
	"fmt"
	"sync"

	"github.com/caddyserver/certmagic"
)

// CertMagic owns ACME scheduling and storage semantics. This wrapper fences
// node shutdown: no late asynchronous task may write after the node lease is
// released. Existing library locks must finish and unlock before Close returns.
type controlledStorage struct {
	backend certmagic.Storage
	mu      sync.Mutex
	closed  bool
	held    map[string]int
	active  sync.WaitGroup
}

func (s *controlledStorage) String() string { return fmt.Sprint(s.backend) }
func (s *controlledStorage) enter(ctx context.Context) (func(), error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	return s.mu.Unlock, nil
}
func (s *controlledStorage) Store(ctx context.Context, key string, value []byte) error {
	leave, err := s.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	return s.backend.Store(ctx, key, value)
}
func (s *controlledStorage) Load(ctx context.Context, key string) ([]byte, error) {
	leave, err := s.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer leave()
	return s.backend.Load(ctx, key)
}
func (s *controlledStorage) Delete(ctx context.Context, key string) error {
	leave, err := s.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	return s.backend.Delete(ctx, key)
}
func (s *controlledStorage) Exists(ctx context.Context, key string) bool {
	leave, err := s.enter(ctx)
	if err != nil {
		return false
	}
	defer leave()
	return s.backend.Exists(ctx, key)
}
func (s *controlledStorage) List(ctx context.Context, path string, recursive bool) ([]string, error) {
	leave, err := s.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer leave()
	return s.backend.List(ctx, path, recursive)
}
func (s *controlledStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	leave, err := s.enter(ctx)
	if err != nil {
		return certmagic.KeyInfo{}, err
	}
	defer leave()
	return s.backend.Stat(ctx, key)
}
func (s *controlledStorage) lock(ctx context.Context, name string, attempt func() (bool, error)) (bool, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		s.mu.Unlock()
		return false, err
	}
	s.active.Add(1)
	s.mu.Unlock()
	ok, err := attempt()
	s.mu.Lock()
	defer s.mu.Unlock()
	if ok && s.closed {
		err = s.backend.Unlock(context.Background(), name)
		if err == nil {
			err = context.Canceled
		}
		ok = false
	}
	if !ok {
		s.active.Done()
	} else {
		if s.held == nil {
			s.held = make(map[string]int)
		}
		s.held[name]++
	}
	return ok, err
}
func (s *controlledStorage) Lock(ctx context.Context, name string) error {
	_, err := s.lock(ctx, name, func() (bool, error) {
		err := s.backend.Lock(ctx, name)
		return err == nil, err
	})
	return err
}
func (s *controlledStorage) TryLock(ctx context.Context, name string) (bool, error) {
	return s.lock(ctx, name, func() (bool, error) {
		if locker, ok := s.backend.(certmagic.TryLocker); ok {
			return locker.TryLock(ctx, name)
		}
		err := s.backend.Lock(ctx, name)
		return err == nil, err
	})
}
func (s *controlledStorage) Unlock(ctx context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.held[name] == 0 {
		return context.Canceled
	}
	err := s.backend.Unlock(ctx, name)
	s.held[name]--
	if s.held[name] == 0 {
		delete(s.held, name)
	}
	s.active.Done()
	return err
}
func (s *controlledStorage) close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.active.Wait()
}
