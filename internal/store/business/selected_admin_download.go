package business

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// WithAdminDownload pins readiness, Owner controls and the encrypted tree
// while admitting an authenticated Admin download. An opened ciphertext stream
// retains its own volume lease after this admission returns.
func (s *SelectedUploadRuntime) WithAdminDownload(ctx context.Context, sessionHash string, admit func(*sealedtree.SQLStore, *sealedtree.TreeLease) error) error {
	if admit == nil {
		return store.ErrNodeState
	}
	ready, err := s.lease(ctx, sessionHash)
	if err != nil {
		return err
	}
	defer ready.Release()
	owner, err := s.repo.AcquireOwnerControlShared(ctx)
	if err != nil {
		return err
	}
	defer owner.Release()
	lease, err := s.tree.AcquireReadFence(ctx)
	if err != nil {
		return err
	}
	defer lease.Release()
	if owner.Check(ctx) != nil || ready.Check(ctx) != nil {
		return store.ErrNodeState
	}
	if err = admit(s.tree, lease); err != nil {
		return err
	}
	if owner.Check(ctx) != nil || ready.Check(ctx) != nil || lease.Check(ctx) != nil {
		return store.ErrNodeState
	}
	return nil
}
