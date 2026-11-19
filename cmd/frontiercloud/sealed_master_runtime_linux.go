//go:build linux

package main

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/httpapi"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func installSealedMasterRuntime(settings config.Config, services runtimeHTTP, router *gin.Engine, public *httpapi.Public, admin *httpapi.Admin, accounts *httpapi.KaraokeAccounts) error {
	sealed := services.Sealed
	if sealed == nil || sealed.tree == nil || sealed.runtime == nil || sealed.maintenance == nil || services.Owner == nil || services.Owner.fence == nil || services.Identity.Role != "Master" || !settings.TLSEnabled {
		return store.ErrNodeState
	}
	repo, ok := services.Database.Nodes().(*business.Repository)
	if !ok || services.Database.Pool() != repo {
		return store.ErrNodeState
	}
	ctx, cancel := context.WithTimeout(sealed.runtime.Context(), 45*time.Second)
	defer cancel()
	for _, root := range []string{"music", "vido", "lyrics"} {
		if _, err := sealed.tree.EnsureSelectedDirectories(ctx, root); err != nil {
			return fmt.Errorf("open encrypted catalog roots: %w", err)
		}
	}
	// This prerequisite is checked before the repository can read a persisted
	// peer. The listener remains probe-only until all setup below succeeds.
	if err := services.Control.ConfigureIngressSelectionReadiness(ctx, func(ctx context.Context) (node.IngressPrerequisiteLease, error) {
		return node.AcquireCatalogPrerequisite(ctx, repo.AcquireOwnerControlShared, sealed.tree)
	}); err != nil {
		return fmt.Errorf("verify ingress prerequisite: %w", err)
	}
	// PublicIngress can initialize a fresh local record only outside the Owner
	// shared lease. A persisted peer is never replaced with a local default.
	current, err := repo.PublicIngress(ctx)
	if err != nil {
		return fmt.Errorf("initialize Master ingress: %w", err)
	}
	peer := current.NodeID != services.Identity.ID
	var unavailable bool
	if !peer {
		if current.PublicOrigin != settings.PublicOrigin {
			return store.ErrNodeState
		}
		probe, stop := context.WithTimeout(ctx, 20*time.Second)
		err = services.Control.ConfigureOpaqueIngressSelectionTree(probe, sealed.tree)
		stop()
		if err != nil {
			return fmt.Errorf("bind encrypted ingress tree: %w", err)
		}
	} else {
		unavailable = services.Control.RevalidateSelectedOpaqueIngress(ctx, sealed.tree, current) != nil
	}
	// Verify the stored peer-instance binding under the real ordered
	// Owner -> ingress -> tree admission, not merely the selected node ID.
	if !unavailable && verifyCurrentIngress(ctx, services.Control, current) != nil {
		if !peer {
			return store.ErrNodeState
		}
		unavailable = true
	}
	catalog, err := public.ConfigureSealedMaster(router, sealed.tree)
	if err != nil {
		return fmt.Errorf("install encrypted catalog and readers: %w", err)
	}
	local, err := node.NewSelectedLocalReceiver(ctx, services.Control, services.Owner.fence)
	if err != nil {
		return fmt.Errorf("open Master local upload receiver: %w", err)
	}
	nodeVault, err := vault.OpenExisting(settings.SecretsDirectory)
	if err != nil {
		return err
	}
	gate := &sealedUploadGate{tree: sealed.tree, runtime: sealed.runtime, maintenance: sealed.maintenance}
	if err := admin.ConfigureSealedUploads(repo, nodeVault, gate, local, services.Control); err != nil {
		return fmt.Errorf("install encrypted Admin upload: %w", err)
	}
	if err := installOptionalSealedS3(ctx, settings, services, repo, admin); err != nil {
		return fmt.Errorf("install encrypted S3 runtime: %w", err)
	}
	sealed.mediaDeletionRun, err = admin.ConfigureSealedMediaDeletion()
	if err != nil {
		return fmt.Errorf("install encrypted resource deletion: %w", err)
	}
	if err := admin.ConfigureSealedRecordingRead(accounts); err != nil {
		return fmt.Errorf("install encrypted recording read: %w", err)
	}
	if err := admin.ConfigureSealedRecordingDelete(accounts, local); err != nil {
		return fmt.Errorf("install encrypted recording cleanup: %w", err)
	}
	if err := admin.ConfigureSealedRecordingDirect(accounts, repo); err != nil {
		return fmt.Errorf("install encrypted Direct recording controls: %w", err)
	}
	sealed.recordingControlsReady = true
	sealed.catalog = catalog
	if unavailable {
		adminOrigin, e := node.Endpoint(settings.AdminOrigin)
		if e != nil || adminOrigin != settings.AdminOrigin || adminOrigin == current.PublicOrigin {
			return store.ErrNodeState
		}
		sealed.recovery = &ingressRecoveryRuntime{repo: repo, control: services.Control, tree: sealed.tree, runtime: sealed.runtime, gate: sealed.maintenance, done: make(chan struct{}), initial: current}
		sealed.recovery.active.Store(true)
		httpapi.RegisterIngressRecovery(router, admin, sealed.recovery)
	}
	// Apply only after the pinned Owner proves both media handlers under the
	// same authenticated Owner/tree gate, for Direct or paired-endpoint Relay.
	services.Control.ConfigureNativeTransportReadiness(func(ctx context.Context, relation store.Relationship, mode string) error {
		if ctx == nil || ctx.Err() != nil || (mode != "Direct" && mode != "Relay") || sealed.runtime.Context().Err() != nil || sealed.recovery != nil && sealed.recovery.Active() {
			return store.ErrNodeState
		}
		if enabled, err := sealed.maintenance.Enabled(); err != nil || enabled {
			return store.ErrNodeState
		}
		lease, err := node.AcquireCatalogPrerequisite(ctx, repo.AcquireOwnerControlShared, sealed.tree)
		if err != nil || lease == nil {
			if lease != nil {
				lease.Release()
			}
			return store.ErrNodeState
		}
		defer lease.Release()
		if lease.Check(ctx) != nil || services.Control.VerifyNativeOpaqueTransportReadiness(ctx, relation, mode) != nil || lease.Check(ctx) != nil || ctx.Err() != nil || sealed.runtime.Context().Err() != nil {
			return store.ErrNodeState
		}
		if enabled, err := sealed.maintenance.Enabled(); err != nil || enabled {
			return store.ErrNodeState
		}
		return nil
	})
	return nil
}

type sealedUploadGate struct {
	tree        *sealedtree.SQLStore
	runtime     *maintenance.Runtime
	maintenance *maintenance.Gate
}

// Runtime holds the native shared lease through HTTP drain. The upload lease
// checks its liveness without reacquiring Owner, ingress or tree locks.
type sealedUploadLease struct {
	gate     *sealedUploadGate
	released atomic.Bool
}

func (g *sealedUploadGate) AcquireSelectedUpload(ctx context.Context, tree *sealedtree.SQLStore) (business.SelectedUploadRuntimeLease, error) {
	if tree == nil || g.tree != tree {
		return nil, store.ErrNodeState
	}
	lease := &sealedUploadLease{gate: g}
	if err := lease.Check(ctx); err != nil {
		return nil, err
	}
	return lease, nil
}

func (l *sealedUploadLease) Check(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || l.released.Load() || l.gate.runtime.Context().Err() != nil {
		return store.ErrNodeState
	}
	if enabled, err := l.gate.maintenance.Enabled(); enabled || err != nil {
		return store.ErrNodeState
	}
	return nil
}

func (l *sealedUploadLease) Release() { l.released.Store(true) }
