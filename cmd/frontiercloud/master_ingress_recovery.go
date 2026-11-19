package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
)

type ingressRecoveryRuntime struct {
	active  atomic.Bool
	mu      sync.Mutex
	repo    *business.Repository
	control *node.Service
	tree    *sealedtree.SQLStore
	runtime *maintenance.Runtime
	gate    *maintenance.Gate
	done    chan struct{}
	initial store.PublicIngress
}

func (r *ingressRecoveryRuntime) Active() bool { return r != nil && r.active.Load() }

func (r *ingressRecoveryRuntime) Status(ctx context.Context) (string, store.PublicIngress, error) {
	if !r.Active() || ctx == nil || r.runtime.Context().Err() != nil {
		return "", store.PublicIngress{}, store.ErrNodeState
	}
	if enabled, err := r.gate.Enabled(); err != nil || enabled {
		return "", store.PublicIngress{}, store.ErrNodeState
	}
	ready, err := node.AcquireCatalogPrerequisite(ctx, r.repo.AcquireOwnerControlShared, r.tree)
	if err != nil {
		return "", store.PublicIngress{}, store.ErrNodeState
	}
	defer ready.Release()
	identity, err := r.control.IdentityState(ctx)
	if err != nil || identity.Role != "Master" || ready.Check(ctx) != nil {
		return "", store.PublicIngress{}, store.ErrNodeState
	}
	// The Owner shared lease is held; a missing row must not trigger the
	// lazy writer, which would require the same Owner fence exclusively.
	current, err := r.repo.ExistingPublicIngress(ctx)
	if err != nil || ready.Check(ctx) != nil {
		return "", store.PublicIngress{}, store.ErrNodeState
	}
	return identity.ID, current, nil
}

func (r *ingressRecoveryRuntime) Restore(ctx context.Context, memberID string, expected int64, audit store.NodeAudit) (store.PublicIngress, error) {
	if r == nil {
		return store.PublicIngress{}, store.ErrNodeState
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	master, _, err := r.Status(ctx)
	if err != nil || memberID != master {
		return store.PublicIngress{}, store.ErrNodeState
	}
	selected, err := r.control.RecoverMasterIngress(ctx, r.tree, memberID, expected, audit)
	if err != nil {
		return store.PublicIngress{}, err
	}
	if !r.control.OpaqueIngressSelectionTreeMatches(r.tree) {
		if err = r.control.ConfigureOpaqueIngressSelectionTree(ctx, r.tree); err != nil {
			return store.PublicIngress{}, store.ErrNodeState
		}
	}
	if err = r.finish(ctx, selected); err != nil {
		return store.PublicIngress{}, err
	}
	return selected, nil
}

// finish is serialized with the manual recovery operation. It takes the same
// admission used by regular traffic before releasing the recovery-only routes.
func (r *ingressRecoveryRuntime) finish(ctx context.Context, expected store.PublicIngress) error {
	if !r.Active() {
		return store.ErrNodeState
	}
	if err := verifyCurrentIngress(ctx, r.control, expected); err != nil {
		return err
	}
	if ctx.Err() != nil || r.runtime.Context().Err() != nil {
		return store.ErrNodeState
	}
	if enabled, err := r.gate.Enabled(); err != nil || enabled {
		return store.ErrNodeState
	}
	r.active.Store(false)
	close(r.done)
	return nil
}

func verifyCurrentIngress(ctx context.Context, control *node.Service, expected store.PublicIngress) error {
	current, lease, err := control.AcquireCurrentIngress(ctx)
	if lease != nil {
		defer lease.Release()
	}
	if err != nil || lease == nil || current != expected || lease.Commit() != nil {
		return store.ErrNodeState
	}
	return nil
}

func (r *ingressRecoveryRuntime) retrySelected() {
	ctx := r.runtime.Context()
	for r.Active() {
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-r.done:
			timer.Stop()
			return
		case <-timer.C:
		}
		if enabled, err := r.gate.Enabled(); err != nil || enabled || !r.Active() {
			continue
		}
		attempt, cancel := context.WithTimeout(ctx, 35*time.Second)
		if r.control.RevalidateSelectedOpaqueIngress(attempt, r.tree, r.initial) == nil && r.mu.TryLock() {
			err := r.finish(attempt, r.initial)
			r.mu.Unlock()
			if err == nil {
				slog.Info("Selected public ingress recovered", "generation", r.initial.Generation)
			}
		}
		cancel()
	}
}

// wrapRecoveryControl never forwards business routes while recovery is active.
// Only the existing authenticated Admin login and the dedicated recovery
// endpoints are reachable at the exact configured management origin.
func wrapRecoveryControl(next http.Handler, recovery *ingressRecoveryRuntime, adminOrigin string, edge *network.Resolver) http.Handler {
	u, err := url.Parse(adminOrigin)
	canonical, endpointErr := node.Endpoint(adminOrigin)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !recovery.Active() {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if r.URL != nil && r.URL.Path == node.IngressCandidateEdgePath {
			next.ServeHTTP(w, r)
			return
		}
		secure := r.TLS != nil
		if !secure && edge != nil {
			identity := edge.Resolve(r)
			secure = identity.FromTrustedProxy && edge.SecureAdmin(r)
		}
		if err != nil || endpointErr != nil || canonical != adminOrigin || u == nil || u.Scheme != "https" || !secure || !strings.EqualFold(r.Host, u.Host) || r.URL == nil || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		if r.Method == http.MethodGet && (r.URL.Path == "/api/v1/media/admin" || r.URL.Path == "/api/v1/media/admin/") {
			http.Redirect(w, r, "/api/v1/media/admin/ingress-recovery", http.StatusSeeOther)
			return
		}
		allowed := r.Method == http.MethodGet && (r.URL.Path == "/api/v1/media/admin/ingress-recovery" || r.URL.Path == "/api/v1/media/admin/ingress-recovery.js" || r.URL.Path == "/api/v1/media/admin/ingress-recovery/state") ||
			r.Method == http.MethodPost && (r.URL.Path == "/api/v1/media/admin/elevate" || r.URL.Path == "/api/v1/media/admin/ingress-recovery/restore")
		if !allowed {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		if r.Method == http.MethodPost {
			origins, sites := r.Header.Values("Origin"), r.Header.Values("Sec-Fetch-Site")
			if len(origins) != 1 || origins[0] != adminOrigin || len(sites) > 1 || len(sites) == 1 && sites[0] != "same-origin" {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func waitIngressRecovery(ctx context.Context, sealed *sealedMasterRuntime) bool {
	if sealed == nil || sealed.recovery == nil {
		return ctx.Err() == nil
	}
	select {
	case <-sealed.recovery.done:
		return ctx.Err() == nil
	case <-ctx.Done():
		return false
	}
}
