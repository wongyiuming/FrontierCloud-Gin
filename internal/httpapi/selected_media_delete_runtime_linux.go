//go:build linux

package httpapi

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// ConfigureSealedMediaDeletion binds HTTP admission and supervised recovery
// to the same upload runtime and actual media volume used by this Master.
func (a *Admin) ConfigureSealedMediaDeletion() (func(context.Context), error) {
	if a == nil || a.public == nil || a.public.media == nil || a.selectedUpload == nil {
		return nil, store.ErrNodeState
	}
	runtime, volume := a.selectedUpload, a.public.media
	err := a.ConfigureSelectedMediaDelete(func(ctx context.Context, sessionHash string, targets []store.SelectedMediaDeleteTarget, audit store.AdminAudit) (store.SelectedMediaDeleteResult, error) {
		return runtime.DeleteMedia(ctx, sessionHash, targets, audit, volume)
	})
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) { runtime.RunMediaDeletions(ctx, volume) }, nil
}
