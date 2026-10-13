package media

import (
	"context"
	"os"
)

func (s *Service) RetainsControlLease(info os.FileInfo) bool {
	s.controlLeaseMu.Lock()
	defer s.controlLeaseMu.Unlock()
	if s.controlLeaseFile == nil || info == nil || !info.Mode().IsRegular() || info.Size() != 0 {
		return false
	}
	held, e := s.controlLeaseFile.Stat()
	if e != nil || !held.Mode().IsRegular() || held.Size() != 0 || !os.SameFile(held, info) {
		return false
	}
	current, e := s.root.Lstat(".node-control.lock")
	return e == nil && current.Mode().IsRegular() && current.Size() == 0 && os.SameFile(held, current)
}

func (s *Service) ValidateRetainedControlState() error {
	s.controlLeaseMu.Lock()
	defer s.controlLeaseMu.Unlock()
	if s.controlLeaseFile == nil {
		return nil
	}
	held, e := s.controlLeaseFile.Stat()
	if e != nil || !held.Mode().IsRegular() || held.Size() != 0 {
		return ErrRecovery
	}
	current, e := s.root.Lstat(".node-control.lock")
	if e != nil || !current.Mode().IsRegular() || current.Size() != 0 || !os.SameFile(held, current) {
		return ErrRecovery
	}
	return nil
}

// RetirementBarrier joins readers and writers using the established native
// volume fence. The caller first persists a relationship fence; otherwise new
// work could be admitted after this barrier returns.
func (s *Service) RetirementBarrier(ctx context.Context, inspect func() error) error {
	if inspect == nil {
		return ErrRecovery
	}
	release, e := s.acquire(ctx, true)
	if e != nil {
		return e
	}
	defer release()
	if e = s.ready(); e != nil {
		return e
	}
	return inspect()
}
