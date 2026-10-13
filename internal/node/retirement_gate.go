package node

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/filelease"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"os"
	"sync"
)

const RetirementAdmissionFile = ".node-retirement-admission.lock"

type retirementRequestGate struct {
	root     *os.Root
	info     os.FileInfo
	shutdown context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	active   sync.WaitGroup
	closed   bool
}

// OpenRetirementRequestGate is called once before internal HTTP routes are
// registered. The pinned native lease joins already-authorized handlers across
// processes sharing this data root. SQL relationship state is the durable fence;
// this OS lease only joins work still in flight and is released on crash.
func (s *Service) OpenRetirementRequestGate(directory string) (func() error, error) {
	if s.retirementGate != nil {
		return nil, store.ErrNodeState
	}
	root, e := os.OpenRoot(directory)
	if e != nil {
		return nil, e
	}
	if info, e := root.Lstat(RetirementAdmissionFile); e == nil && (!info.Mode().IsRegular() || info.Size() != 0) {
		root.Close()
		return nil, store.ErrNodeState
	} else if e != nil && !os.IsNotExist(e) {
		root.Close()
		return nil, e
	}
	f, e := root.OpenFile(RetirementAdmissionFile, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		root.Close()
		return nil, e
	}
	info, e := f.Stat()
	named, ne := root.Lstat(RetirementAdmissionFile)
	if e != nil || ne != nil || !info.Mode().IsRegular() || info.Size() != 0 || !os.SameFile(info, named) {
		f.Close()
		root.Close()
		return nil, store.ErrNodeState
	}
	e = f.Sync()
	f.Close()
	if e == nil {
		e = fsutil.SyncDirectory(root, ".")
	}
	if e != nil {
		root.Close()
		return nil, e
	}
	shutdown, cancel := context.WithCancel(context.Background())
	gate := &retirementRequestGate{root: root, info: info, shutdown: shutdown, cancel: cancel}
	s.retirementGate = gate
	var once sync.Once
	var closeErr error
	return func() error {
		once.Do(func() {
			gate.mu.Lock()
			gate.closed = true
			gate.cancel()
			gate.mu.Unlock()
			gate.active.Wait()
			closeErr = gate.root.Close()
		})
		return closeErr
	}, nil
}

// RetirementRequestLease must surround authentication and the complete internal
// request, not only the SQL admission. Complete uses exclusive=true before the
// native media/recording barriers and never recursively calls an internal route.
func (s *Service) RetirementRequestLease(parent context.Context, exclusive bool) (context.Context, func(), error) {
	gate := s.retirementGate
	if gate == nil {
		return parent, nil, store.ErrNodeState
	}
	gate.mu.Lock()
	if gate.closed {
		gate.mu.Unlock()
		return parent, nil, store.ErrNodeState
	}
	gate.active.Add(1)
	gate.mu.Unlock()
	ctx, cancel := context.WithCancel(parent)
	unhook := context.AfterFunc(gate.shutdown, cancel)
	finish := func() { unhook(); cancel(); gate.active.Done() }
	info, e := gate.root.Lstat(RetirementAdmissionFile)
	if e != nil || !info.Mode().IsRegular() || info.Size() != 0 || !os.SameFile(info, gate.info) {
		finish()
		return parent, nil, store.ErrNodeState
	}
	f, e := gate.root.OpenFile(RetirementAdmissionFile, os.O_RDWR, 0)
	if e != nil {
		finish()
		return parent, nil, e
	}
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) {
		f.Close()
		finish()
		return parent, nil, store.ErrNodeState
	}
	release, e := filelease.Acquire(ctx, f, exclusive)
	if e != nil {
		finish()
		return parent, nil, e
	}
	current, e := gate.root.Lstat(RetirementAdmissionFile)
	if e != nil || !current.Mode().IsRegular() || current.Size() != 0 || !os.SameFile(opened, current) {
		release()
		finish()
		return parent, nil, store.ErrNodeState
	}
	var once sync.Once
	return ctx, func() { once.Do(func() { release(); finish() }) }, nil
}

// Queued native jobs join the same barrier as HTTP handlers. Rechecking the
// durable relationship after acquiring the lease rejects work queued before a
// fence but scheduled only after retirement completed.
func (s *Service) ActiveFollowerWork(ctx context.Context, relationship string) (context.Context, func(), error) {
	ctx, release, e := s.RetirementRequestLease(ctx, false)
	if e != nil {
		return ctx, nil, e
	}
	rel, e := s.repo.Relationship(ctx, relationship)
	if e == nil {
		e = s.RequireFollower(ctx, rel)
	}
	if e != nil {
		release()
		return ctx, nil, e
	}
	return ctx, release, nil
}
