//go:build !linux

package main

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type runtimeOwner struct{}

func (*runtimeOwner) Close() error { return nil }

func openRuntimeOwner(ctx context.Context, settings config.Config, database store.Store, _ *node.Identity) (*runtimeOwner, error) {
	prepared, err := runtimeOwnerPresent(ctx, database, settings.DataRoot)
	if err != nil {
		return nil, err
	}
	if prepared {
		return nil, store.ErrNodeState
	}
	return nil, nil
}
