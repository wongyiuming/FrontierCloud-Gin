//go:build linux

package main

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// This composes the actual HTTP runtime with the real owner-control and tree
// fences. It does not install an unfinished opaque serving path or claim that
// selection readiness alone is sufficient to enable it in production.
func TestRuntimeControlledOpaquePrerequisite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	router, control, database, identity := nativeHTTPFixtureServices(t, config.DeploymentBusiness)
	// The generic HTTP fixture starts as Standalone. Promote its isolated
	// repository to a synthetic Master, as the node integration fixture does.
	if _, err := database.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: "https://control.example", Allocation: store.GiB, PhysicalFree: 2 * store.GiB}, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err := control.ConfigurePublicOrigin("https://public.example"); err != nil {
		t.Fatal(err)
	}
	ownerDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(ownerDir, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	ownerRoot, err := os.OpenRoot(ownerDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ownerRoot.Close() })
	ownerFence, err := ownerfence.Create(ownerRoot, ownerDir, identity)
	if err != nil {
		t.Fatal(err)
	}
	owner, ok := database.Nodes().(interface {
		ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
		InitializeOwnerControlMarker(context.Context) error
		AcquireOwnerControlShared(context.Context) (store.OwnerControlLease, error)
	})
	if !ok {
		t.Fatal("owner control unavailable")
	}
	if err := owner.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return ownerFence.Acquire(c, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err := owner.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	treeDB, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "tree.db"))+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = treeDB.Close() })
	codec, err := sealedtree.New(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	tree, err := sealedtree.InitializeSQLite(ctx, treeDB, codec, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	treeDir := t.TempDir()
	if err := os.Chmod(treeDir, 0700); err != nil {
		t.Fatal(err)
	}
	treeRoot, err := os.OpenRoot(treeDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = treeRoot.Close() })
	if _, err := sealedtree.InitializeFence(ctx, tree, treeRoot, treeDir); err != nil {
		t.Fatal(err)
	}
	if err := control.ConfigureIngressSelectionReadiness(ctx, func(c context.Context) (node.IngressPrerequisiteLease, error) {
		return node.AcquireCatalogPrerequisite(c, owner.AcquireOwnerControlShared, tree)
	}); err != nil {
		t.Fatal(err)
	}
	var ingressRows int
	if err := database.Database().QueryRowContext(ctx, "SELECT COUNT(*) FROM public_ingress_config").Scan(&ingressRows); err != nil || ingressRows != 0 {
		t.Fatal("fixture must start without a selected ingress", ingressRows, err)
	}
	expected := store.PublicIngress{NodeID: identity.ID, PublicOrigin: "https://public.example", Generation: 1}
	_, first, err := control.AcquireLocalCatalogIngress(ctx, expected, func(context.Context, store.IngressPrerequisite) error { return nil })
	if err == nil || first != nil {
		t.Fatal("uninitialized catalog admission must be unavailable", err)
	}
	_, first, err = control.AcquireCurrentIngress(ctx)
	if err == nil || first != nil {
		t.Fatal("uninitialized general admission must be unavailable", err)
	}
	outerOwner, err := owner.AcquireOwnerControlShared(ctx)
	if err != nil {
		t.Fatal("outer Owner lease", err)
	}
	_, first, err = control.AcquireCurrentIngress(ctx)
	outerOwner.Release()
	if err == nil || first != nil {
		t.Fatal("nested uninitialized admission must be unavailable", err)
	}
	if err := database.Database().QueryRowContext(ctx, "SELECT COUNT(*) FROM public_ingress_config").Scan(&ingressRows); err != nil || ingressRows != 0 {
		t.Fatal("admission initialized ingress", ingressRows, err)
	}
	// Startup performs this explicit initialization with no Owner lease held.
	if _, err := database.Nodes().(store.PublicRoutingRepository).PublicIngress(ctx); err != nil {
		t.Fatal("explicit ingress initialization", err)
	}
	_, first, err = control.AcquireLocalCatalogIngress(ctx, expected, func(context.Context, store.IngressPrerequisite) error { return nil })
	if err != nil || first == nil {
		t.Fatal("initialized catalog admission failed", err)
	}
	if err := first.Commit(); err != nil {
		t.Fatal("initialized catalog admission commit", err)
	}
	_, first, err = control.AcquireCurrentIngress(ctx)
	if err != nil || first == nil {
		t.Fatal("first general admission failed", err)
	}
	if err := first.Commit(); err != nil {
		t.Fatal("first general admission commit", err)
	}
	if err := control.ConfigureOpaqueIngressSelectionTree(ctx, tree); err != nil {
		t.Fatal(err)
	}
	if !control.IngressSelectionAvailable(ctx) {
		t.Fatal("real composite prerequisite unavailable")
	}
	_, lease, err := control.AcquireResourcePrerequisite(ctx)
	if err != nil || lease == nil {
		t.Fatal("resource prerequisite did not acquire", err)
	}
	lease.Release()
	for _, route := range router.Routes() {
		if strings.Contains(route.Path, "/opaque-") || strings.Contains(route.Path, "/master-local") {
			t.Fatalf("readiness installed an unready data route: %s", route.Path)
		}
	}
	// Losing the actual root used by the authenticated owner fence must deny
	// subsequent resource admission, without silently falling back to legacy.
	if err := ownerRoot.Close(); err != nil {
		t.Fatal(err)
	}
	if control.IngressSelectionAvailable(ctx) {
		t.Fatal("closed owner fence remained available")
	}
	if _, lease, err := control.AcquireResourcePrerequisite(ctx); err == nil || lease != nil {
		if lease != nil {
			lease.Release()
		}
		t.Fatal("resource prerequisite admitted without owner fence")
	}
}
