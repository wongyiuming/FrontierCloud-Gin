package media

import (
	"context"
	"errors"
	"os"
	"sync"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// RecordingCleanupLease is an exclusive, cross-process media-volume lease.
// It is an internal filesystem prerequisite, not authorization to delete.
type RecordingCleanupLease struct {
	mu      sync.Mutex
	service *Service
	file    *os.File
	release func()
	closed  bool
}

// TryRecordingCleanup never waits for existing readers. A caller holding the
// Owner fence must release it and retry later on ErrBusy, rather than block the
// Master behind a long audio stream.
func (s *Service) TryRecordingCleanup(ctx context.Context) (*RecordingCleanupLease, error) {
	if s == nil || s.root == nil || ctx == nil || ctx.Err() != nil {
		return nil, store.ErrNodeState
	}
	if !s.mutation.TryLock() {
		return nil, filelease.ErrBusy
	}
	fail := func(err error) (*RecordingCleanupLease, error) { s.mutation.Unlock(); return nil, err }
	if info, err := s.root.Lstat(".media-mutation.lock"); err == nil && !info.Mode().IsRegular() {
		return fail(ErrRecovery)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fail(err)
	}
	f, err := s.root.OpenFile(".media-mutation.lock", os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return fail(err)
	}
	opened, err := f.Stat()
	current, pathErr := s.root.Lstat(".media-mutation.lock")
	if err != nil || pathErr != nil || !current.Mode().IsRegular() || !os.SameFile(opened, current) || fsutil.InheritOwner(f, s.root) != nil {
		f.Close()
		return fail(ErrRecovery)
	}
	release, err := filelease.Try(f, true)
	if err != nil {
		return fail(err)
	}
	lease := &RecordingCleanupLease{service: s, file: f, release: release}
	if err = lease.CheckCleanupRoot(ctx, s.root); err != nil {
		lease.Release()
		return nil, err
	}
	return lease, nil
}

func (l *RecordingCleanupLease) CheckCleanupRoot(ctx context.Context, root *os.Root) error {
	if l == nil || ctx == nil || root == nil || ctx.Err() != nil {
		return store.ErrNodeState
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.service == nil || l.file == nil {
		return store.ErrNodeState
	}
	opened, e1 := l.file.Stat()
	current, e2 := l.service.root.Lstat(".media-mutation.lock")
	expectedRoot, e3 := l.service.root.Stat(".")
	actualRoot, e4 := root.Stat(".")
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || !current.Mode().IsRegular() || !os.SameFile(opened, current) || !os.SameFile(expectedRoot, actualRoot) || ctx.Err() != nil {
		return store.ErrNodeState
	}
	return nil
}

func (l *RecordingCleanupLease) Release() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	l.closed = true
	l.service.invalidateCatalog()
	l.release()
	l.service.mutation.Unlock()
}
