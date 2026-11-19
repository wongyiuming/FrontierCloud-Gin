package business

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// PrepareHiddenDirectory retains the selected-upload runtime, Owner and
// ingress fences while the tree atomically creates directly hidden facts.
func (s *SelectedUploadRuntime) PrepareHiddenDirectory(ctx context.Context, sessionHash, path string) error {
	return s.withTreeWrite(ctx, sessionHash, func(held context.Context) error {
		return s.tree.PrepareSelectedHiddenDirectory(held, path)
	})
}

// SetDirectoryVisibility orders the catalog change after earlier public
// admissions and prevents new grants once it commits. Already issued remote
// bearer grants and admitted streams retain their existing expiry semantics.
func (s *SelectedUploadRuntime) SetDirectoryVisibility(ctx context.Context, sessionHash string, paths []string, hidden bool, audit store.AdminAudit) (changed int, err error) {
	err = s.withTreeWrite(ctx, sessionHash, func(held context.Context) error {
		var mutationErr error
		changed, mutationErr = s.tree.SetNativeDirectoryVisibility(held, paths, hidden, audit)
		return mutationErr
	})
	return changed, err
}
