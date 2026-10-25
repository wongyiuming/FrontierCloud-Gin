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
	gates   map[string]func()
	active  sync.WaitGroup
	ip      *ipCertificateStorage
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
	// Capture the owning attempt before taking Storage.mu. Completion may need
	// Manager.mu, so neither capture nor notification may run under this lock.
	var finish func(string)
	if s.ip != nil && key == s.ip.privateKey && s.ip.capture != nil {
		finish = s.ip.capture()
	}
	leave, err := s.enter(ctx)
	if err != nil {
		return err
	}
	var notify func()
	defer func() {
		leave()
		if notify != nil {
			notify()
		}
	}()
	if s.ip != nil {
		var handled bool
		handled, err, notify = s.ip.store(ctx, s.backend, key, value, finish)
		if handled {
			return err
		}
	}
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
	if s.ip != nil && s.ip.rollbackDelete(key) {
		return nil
	}
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
func (s *controlledStorage) lock(ctx context.Context, name string, try bool, attempt func() (bool, error)) (bool, error) {
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
	var release func()
	ok := true
	var err error
	if s.ip != nil {
		release, ok, err = s.ip.acquireOperation(ctx, name, try)
	}
	if ok && err == nil {
		ok, err = attempt()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ok && s.closed {
		err = s.backend.Unlock(context.Background(), name)
		if err != nil && release != nil {
			// The backend still owns this lease. Preserve the local fence and
			// shutdown join until a successful explicit unlock can resolve it.
			s.recordLock(name, release)
			return false, err
		}
		if err == nil {
			err = context.Canceled
		}
		ok = false
	}
	if !ok {
		if release != nil {
			release()
		}
		s.active.Done()
	} else {
		s.recordLock(name, release)
	}
	return ok, err
}

// Called with Storage.mu held after the actual backend lock was acquired.
func (s *controlledStorage) recordLock(name string, release func()) {
	if s.held == nil {
		s.held = make(map[string]int)
	}
	s.held[name]++
	if release != nil {
		if s.gates == nil {
			s.gates = make(map[string]func())
		}
		s.gates[name] = release
	}
}
func (s *controlledStorage) Lock(ctx context.Context, name string) error {
	_, err := s.lock(ctx, name, false, func() (bool, error) {
		err := s.backend.Lock(ctx, name)
		return err == nil, err
	})
	return err
}
func (s *controlledStorage) TryLock(ctx context.Context, name string) (bool, error) {
	return s.lock(ctx, name, true, func() (bool, error) {
		if locker, ok := s.backend.(certmagic.TryLocker); ok {
			return locker.TryLock(ctx, name)
		}
		err := s.backend.Lock(ctx, name)
		return err == nil, err
	})
}
func (s *controlledStorage) Unlock(ctx context.Context, name string) error {
	s.mu.Lock()
	var notify func()
	defer func() {
		s.mu.Unlock()
		if notify != nil {
			notify()
		}
	}()
	if s.held[name] == 0 {
		return context.Canceled
	}
	err := s.backend.Unlock(ctx, name)
	if err != nil && s.gates[name] != nil {
		return err
	}
	s.held[name]--
	if s.held[name] == 0 {
		delete(s.held, name)
		if s.ip != nil && name == "issue_cert_"+s.ip.host {
			// The SDK rolls back with the original Store context. If it was
			// cancelled, Delete never entered storage admission. Abandon that
			// unfinished stage before a later ARI/save owner can take the gate.
			if s.ip.pending != nil {
				notify = s.ip.reject("ca_error", nil)
			}
			s.ip.rollback = nil
		}
		if release := s.gates[name]; release != nil {
			release()
			delete(s.gates, name)
		}
	}
	s.active.Done()
	return err
}
func (s *controlledStorage) close() {
	s.mu.Lock()
	s.closed = true
	if s.ip != nil {
		s.ip.clearPending()
	}
	s.mu.Unlock()
	s.active.Wait()
}
