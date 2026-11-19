//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type runtimeOwner struct {
	root  *os.Root
	fence *ownerfence.Fence
}

func (o *runtimeOwner) Close() error { return o.root.Close() }

// Authenticate the physical Owner binding and its database marker before any
// media startup recovery can modify the volume. Keep the root descriptor alive
// until the HTTP handlers and node workers have stopped.
func openRuntimeOwner(ctx context.Context, settings config.Config, database store.Store, identity *node.Identity) (*runtimeOwner, error) {
	prepared, err := runtimeOwnerPresent(ctx, database, settings.DataRoot)
	if err != nil || !prepared {
		return nil, err
	}
	mediaRoot := filepath.Join(settings.DataRoot, "media")
	if identity == nil || !settings.TLSEnabled || settings.DatabaseType != config.DatabaseSQLite || identity.Role != "Master" && identity.Role != "Follower" {
		return nil, store.ErrNodeState
	}
	repo, ok := database.Nodes().(interface {
		ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
		AcquireOwnerControlShared(context.Context) (store.OwnerControlLease, error)
	})
	if !ok {
		return nil, store.ErrNodeState
	}
	root, err := os.OpenRoot(mediaRoot)
	if err != nil {
		return nil, err
	}
	ready := false
	defer func() {
		if !ready {
			root.Close()
		}
	}()
	fence, err := ownerfence.Open(root, mediaRoot, identity)
	if err != nil {
		return nil, err
	}
	if err := repo.ConfigureOwnerControlFence(func(ctx context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return fence.Acquire(ctx, exclusive)
	}); err != nil {
		return nil, err
	}
	lease, err := repo.AcquireOwnerControlShared(ctx)
	if lease != nil {
		defer lease.Release()
	}
	if err != nil || lease == nil || lease.Check(ctx) != nil {
		return nil, store.ErrNodeState
	}
	ready = true
	return &runtimeOwner{root: root, fence: fence}, nil
}
