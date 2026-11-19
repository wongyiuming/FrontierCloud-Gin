package business

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (s *SelectedUploadRuntime) MovePriority(ctx context.Context, sessionHash, scope, kind string, move store.PriorityMove) (order store.PriorityOrder, err error) {
	err = s.withTreeWrite(ctx, sessionHash, func(heldCtx context.Context) error {
		order, err = s.tree.MoveNativePriority(heldCtx, scope, kind, move)
		return err
	})
	return order, err
}
