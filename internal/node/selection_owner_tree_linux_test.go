//go:build linux

package node

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Real SQLite repository, node vault, owner flock and encrypted tree. This is
// an isolated fixture; it does not install startup or remote-owner routing.
func TestSelectionUsesExclusiveOwnerThenTreeAndIngress(t *testing.T) {
	ctx := context.Background()
	master, _ := testNode(t, "Master", "https://master.test", nil)
	if err := master.ConfigurePublicOrigin("https://public.test"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fence, err := ownerfence.Create(root, dir, master.identity)
	if err != nil {
		t.Fatal(err)
	}
	config := master.repo.(interface {
		ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
		InitializeOwnerControlMarker(context.Context) error
		AcquireOwnerControlShared(context.Context) (store.OwnerControlLease, error)
	})
	if err := config.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return fence.Acquire(c, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err := config.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	treeDB, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "tree.sqlite"))+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	defer treeDB.Close()
	codec, err := sealedtree.New(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rootID, objectID := strings.Repeat("a", 64), strings.Repeat("b", 64)
	tree, err := sealedtree.InitializeSQLite(ctx, treeDB, codec, rootID)
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
	defer treeRoot.Close()
	if _, err := sealedtree.InitializeFence(ctx, tree, treeRoot, treeDir); err != nil {
		t.Fatal(err)
	}
	if err := tree.CreateDirectoryWithFacts(ctx, sealedtree.Entry{ParentID: rootID, ObjectID: objectID, Kind: "directory", Name: "fixture"}, sealedtree.Facts{ObjectID: objectID}); err != nil {
		t.Fatal(err)
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	var pause atomic.Bool
	ready := func(c context.Context) (IngressPrerequisiteLease, error) {
		value, e := AcquireCatalogPrerequisite(c, config.AcquireOwnerControlShared, tree)
		if e == nil && pause.CompareAndSwap(true, false) {
			close(entered)
			select {
			case <-resume:
			case <-c.Done():
				value.Release()
				return nil, c.Err()
			}
		}
		return value, e
	}
	if err := master.ConfigureIngressSelectionReadiness(ctx, ready); err != nil {
		t.Fatal(err)
	}
	routing := master.repo.(store.PublicRoutingRepository)
	current, err := routing.PublicIngress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := master.ConfigureOpaqueIngressSelectionTree(ctx, tree); err != nil {
		t.Fatal(err)
	}
	identity, err := master.IdentityState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := config.AcquireOwnerControlShared(ctx)
	if err != nil {
		t.Fatal(err)
	}
	blocked, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	_, err = master.SelectPublicIngress(blocked, identity.ID, current.Generation, store.NodeAudit{Actor: "fixture"})
	cancel()
	shared.Release()
	if err == nil {
		t.Fatal("selection bypassed held owner fence")
	}
	after, err := routing.PublicIngress(ctx)
	if err != nil || after.Generation != current.Generation {
		t.Fatal("cancelled selection changed ingress", err)
	}
	pause.Store(true)
	selected := make(chan error, 1)
	go func() {
		_, e := master.SelectPublicIngress(ctx, identity.ID, current.Generation, store.NodeAudit{Actor: "fixture"})
		selected <- e
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("selection did not acquire owner then tree")
	}
	write := make(chan error, 1)
	go func() {
		_, e := tree.SetFacts(ctx, sealedtree.Facts{ObjectID: objectID, Visibility: &sealedtree.VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}}, 1)
		write <- e
	}()
	conflict := make(chan error, 1)
	go func() {
		_, e := routing.CommitMasterPublicIngress(ctx, "https://public.test", current.Generation, store.NodeAudit{Actor: "other"})
		conflict <- e
	}()
	select {
	case e := <-write:
		t.Fatal("tree writer bypassed selection", e)
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case e := <-conflict:
		t.Fatal("ingress writer bypassed owner fence", e)
	case <-time.After(100 * time.Millisecond):
	}
	close(resume)
	select {
	case e := <-selected:
		if e != nil {
			t.Fatal("selection failed", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("selection deadlocked")
	}
	select {
	case e := <-write:
		if e != nil {
			t.Fatal("tree writer failed", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tree writer stranded")
	}
	select {
	case e := <-conflict:
		if e == nil {
			t.Fatal("stale ingress writer succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ingress writer stranded")
	}
	ordered := master.repo.(interface {
		WithOrderedIngressTree(context.Context, *sealedtree.SQLStore, func(context.Context) error) error
	})
	if err := ordered.WithOrderedIngressTree(ctx, tree, func(context.Context) error { return nil }); err == nil {
		t.Fatal("ordered selection scope accepted without Owner exclusive")
	}
	coordinator := master.repo.(store.OwnerControlCoordinator)
	if err := coordinator.WithOwnerControlExclusive(ctx, func(held context.Context) error {
		var expired context.Context
		if err := ordered.WithOrderedIngressTree(held, tree, func(scoped context.Context) error {
			expired = scoped
			validator := master.repo.(interface {
				CheckOrderedIngressTree(context.Context, *sealedtree.SQLStore, store.OwnerControlLease) error
			})
			borrow, err := config.AcquireOwnerControlShared(scoped)
			if err != nil {
				return err
			}
			defer borrow.Release()
			if validator.CheckOrderedIngressTree(scoped, tree, borrow) != nil {
				return errors.New("real scope rejected")
			}
			if validator.CheckOrderedIngressTree(scoped, &sealedtree.SQLStore{}, borrow) == nil {
				return errors.New("foreign tree accepted")
			}
			if validator.CheckOrderedIngressTree(scoped, tree, &compositeFixtureOwner{}) == nil {
				return errors.New("foreign Owner accepted")
			}
			return nil
		}); err != nil {
			return err
		}
		latest, err := routing.PublicIngress(held)
		if err != nil {
			return err
		}
		if _, err := routing.CommitMasterPublicIngress(expired, "https://public.test", latest.Generation, store.NodeAudit{}); err == nil {
			return errors.New("expired ordered scope accepted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
