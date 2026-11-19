//go:build linux

package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/httpapi"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
)

// installOptionalSealedS3 leaves S3 unavailable unless the actual data root,
// startup journal audit and provider are all available. It does not turn a
// startup audit into a provider-origin proof or alter native admission.
func installOptionalSealedS3(ctx context.Context, settings config.Config, services runtimeHTTP, repo *business.Repository, admin *httpapi.Admin) error {
	sealed := services.Sealed
	if ctx == nil || sealed == nil || sealed.tree == nil || sealed.runtime == nil || sealed.maintenance == nil ||
		services.Owner == nil || services.Owner.fence == nil || services.Media == nil || repo == nil || admin == nil || sealed.s3Close != nil {
		return store.ErrNodeState
	}
	provider, err := services.Media.SelectedS3Provider()
	if err != nil {
		slog.Warn("sealed S3 unavailable", "reason", "provider_unavailable")
		return nil
	}
	root, err := os.OpenRoot(settings.DataRoot)
	if err != nil {
		slog.Warn("sealed S3 unavailable", "reason", "control_unavailable")
		return nil
	}
	defer func() {
		if root != nil {
			_ = root.Close()
		}
	}()
	current, err := os.Lstat(settings.DataRoot)
	if err != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 {
		slog.Warn("sealed S3 unavailable", "reason", "control_unavailable")
		return nil
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(current, opened) {
		slog.Warn("sealed S3 unavailable", "reason", "control_unavailable")
		return nil
	}
	live := func(c context.Context) error {
		if c == nil || c.Err() != nil || sealed.runtime.Context().Err() != nil {
			return store.ErrNodeState
		}
		if enabled, e := sealed.maintenance.Enabled(); e != nil || enabled {
			return store.ErrNodeState
		}
		return nil
	}
	gate, err := business.OpenSelectedS3FileGate(root, sealed.tree, live)
	if err != nil {
		slog.Warn("sealed S3 unavailable", "reason", "control_unavailable")
		return nil
	}
	keepGate := false
	defer func() {
		if !keepGate {
			_ = gate.CloseContext(context.Background())
		}
	}()
	// Recovery may invoke either callback long after startup returns. Obtain a
	// fresh key for each call; never retain the startup temporary key.
	audit := func(c context.Context) error {
		key, e := sealed.tree.CapacityKey()
		if e != nil {
			return e
		}
		defer clear(key)
		return repo.CheckSelectedS3Startup(c, sealed.tree, key)
	}
	probeMember := func(c context.Context, memberID string) error {
		key, e := sealed.tree.CapacityKey()
		if e != nil {
			return e
		}
		defer clear(key)
		return repo.CheckSelectedS3RecoveryMember(c, sealed.tree, key, memberID)
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	configured := false
	err = gate.StartSelectedS3(bounded, sealed.tree, audit, probeMember, func(c context.Context) error {
		// Any failure after installation begins aborts HTTP construction.
		configured = true
		return admin.ConfigureSealedS3(provider, gate)
	})
	if err != nil {
		if configured {
			return err
		}
		reason := "audit_failed"
		if errors.Is(err, business.ErrSelectedS3RecoveryRequired) {
			reason = "recovery_required"
		}
		slog.Warn("sealed S3 unavailable", "reason", reason)
		return nil
	}
	ownedRoot := root
	sealed.s3Close = func() error {
		// HTTP handlers and background workers are joined by the runtime before
		// this closer. Keep the root open until every gate borrower has drained.
		if err := gate.CloseContext(context.Background()); err != nil {
			return err
		}
		return ownedRoot.Close()
	}
	keepGate = true
	root = nil // ownership transferred to the runtime closer
	slog.Info("sealed S3 control installed; provider probes remain required")
	return nil
}
