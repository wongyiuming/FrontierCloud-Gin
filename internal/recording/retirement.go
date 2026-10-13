package recording

import "context"

func (s *Storage) RetirementBarrier(ctx context.Context, inspect func() error) error {
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
