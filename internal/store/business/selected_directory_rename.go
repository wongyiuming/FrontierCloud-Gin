package business

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// RenameDirectory retains the existing Master readiness, Owner and ingress
// gates until the encrypted namespace transaction has completed.
func (s *SelectedUploadRuntime) RenameDirectory(ctx context.Context, sessionHash, old, newName string, audit store.AdminAudit) (result sealedtree.NativeDirectoryRenameResult, err error) {
	err = s.withTreeWrite(ctx, sessionHash, func(held context.Context) error {
		var e error
		result, e = s.tree.RenameNativeDirectory(held, old, newName, audit)
		return e
	})
	return
}
