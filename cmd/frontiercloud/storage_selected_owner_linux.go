//go:build linux

package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/httpapi"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// A legacy Storage without a provisioned fence keeps its existing routes.
// Once any fence state exists, authenticate the original vault, volume and
// same-database marker before installing the encrypted Direct endpoints.
func installStorageSelectedOwner(settings config.Config, services runtimeHTTP, router *gin.Engine) error {
	sqlStore, ok := services.Database.(interface{ Database() *sql.DB })
	if !ok || sqlStore.Database() == nil {
		return store.ErrNodeState
	}
	root := services.Media.InventoryRoot()
	if root == nil {
		return store.ErrNodeState
	}
	_, bindingErr := root.Lstat(".opaque-aliases/.owner-control-binding")
	_, lockErr := root.Lstat(".opaque-aliases/.owner-control-lock")
	if bindingErr != nil && !errors.Is(bindingErr, os.ErrNotExist) || lockErr != nil && !errors.Is(lockErr, os.ErrNotExist) {
		return store.ErrNodeState
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var markers int
	if err := sqlStore.Database().QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_owner_fence`).Scan(&markers); err != nil {
		return store.ErrNodeState
	}
	if markers == 0 && services.Owner == nil && errors.Is(bindingErr, os.ErrNotExist) && errors.Is(lockErr, os.ErrNotExist) {
		return nil
	}
	if markers != 1 || bindingErr != nil || lockErr != nil || services.Owner == nil || services.Owner.root == nil || services.Owner.fence == nil || !settings.TLSEnabled || services.Identity.Role != "Follower" {
		return store.ErrNodeState
	}
	actual, err := root.Stat(".")
	ownerRoot, ownerErr := services.Owner.root.Stat(".")
	if err != nil || ownerErr != nil || !os.SameFile(actual, ownerRoot) {
		return store.ErrNodeState
	}
	repo, ok := services.Database.Nodes().(interface {
		AcquireOwnerControlShared(context.Context) (store.OwnerControlLease, error)
	})
	if !ok {
		return store.ErrNodeState
	}
	lease, err := repo.AcquireOwnerControlShared(ctx)
	if err != nil || lease == nil {
		if lease != nil {
			lease.Release()
		}
		return store.ErrNodeState
	}
	checkErr := lease.Check(ctx)
	lease.Release()
	if checkErr != nil {
		return store.ErrNodeState
	}
	receiver, err := node.NewSelectedDirectReceiver(ctx, services.Control, services.Owner.fence)
	if err != nil || !httpapi.RegisterSelectedOwnerHTTP(router, settings, services.Resolver, services.Control, services.Media, receiver) ||
		!httpapi.RegisterSelectedRelayOwnerHTTP(router, settings, services.Resolver, services.Control, services.Media, receiver) ||
		!httpapi.RegisterRecordingOwnerHTTP(router, settings, services.Resolver, services.Control, services.Media, receiver) {
		return store.ErrNodeState
	}
	services.Control.ConfigureOpaqueOwnerRequestReadiness(func(ctx context.Context) (node.IngressPrerequisiteLease, error) {
		return repo.AcquireOwnerControlShared(ctx)
	})
	httpapi.RegisterOpaqueNodeMedia(router, settings, services.Resolver, services.Control, services.Media)
	httpapi.RegisterOpaqueRevocationControl(router, settings, services.Resolver, services.Control, services.Media)
	// Only a prepared, same-volume Owner with real media handlers gets an
	// application verifier. Direct additionally requires its browser origin.
	services.Control.ConfigureNativeTransportReadiness(func(ctx context.Context, relation store.Relationship, mode string) error {
		if ctx == nil || ctx.Err() != nil || (mode != "Direct" && mode != "Relay") || (mode == "Direct" && settings.FollowerResourceOrigin == "") {
			return store.ErrNodeState
		}
		lease, err := services.Control.AcquireOpaqueOwnerRequestFence(ctx)
		if err != nil || lease == nil {
			if lease != nil {
				lease.Release()
			}
			return store.ErrNodeState
		}
		defer lease.Release()
		if lease.Check(ctx) != nil || services.Control.VerifyNativeOpaqueTransportReadiness(ctx, relation, mode) != nil || lease.Check(ctx) != nil || ctx.Err() != nil {
			return store.ErrNodeState
		}
		return nil
	})
	return nil
}
