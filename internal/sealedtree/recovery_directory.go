package sealedtree

import "context"

// ResolveDirectoryForRecoveryWithLease reconstructs a directory's authenticated
// logical path even when it or an ancestor is hidden. It is only for trusted
// Master recovery comparisons: it does not authorize reads or publication and
// must never persist or send the returned path to an owner. The virtual root is
// intentionally excluded. All writers must cooperate with this same fence.
func (s *SQLStore) ResolveDirectoryForRecoveryWithLease(ctx context.Context, lease *TreeLease, objectID string) (string, error) {
	if !s.valid() || ctx == nil || lease == nil {
		return "", ErrFenceRequired
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.fence == nil || lease.fence.store != s || lease.exclusive {
		return "", ErrFenceRequired
	}
	if err := lease.checkLocked(ctx); err != nil {
		return "", err
	}
	entry, _, err := s.Get(ctx, objectID)
	if err != nil {
		return "", err
	}
	if entry.Kind != "directory" {
		return "", ErrInvalid
	}
	path, err := s.resolvePath(ctx, objectID, false)
	if err != nil {
		return "", err
	}
	if err := lease.checkLocked(ctx); err != nil {
		return "", err
	}
	return path, nil
}
