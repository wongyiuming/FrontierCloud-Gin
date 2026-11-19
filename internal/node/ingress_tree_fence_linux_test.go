//go:build linux

package node

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// This connects real Linux tree and ingress fences only in an isolated
// fixture. Product activation remains closed until all tree contracts exist.
func TestRealTreeFenceOrdersIngressAdmissionAndSelection(t *testing.T) {
	ctx := context.Background()
	master, _ := testNode(t, "Master", "https://master.test", nil)
	if err := master.ConfigurePublicOrigin("https://public.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := master.repo.(store.PublicRoutingRepository).PublicIngress(ctx); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "tree.sqlite")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath)+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tree, err := sealedtree.New(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rootID, objectID := strings.Repeat("a", 64), strings.Repeat("b", 64)
	treeStore, err := sealedtree.InitializeSQLite(ctx, db, tree, rootID)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := sealedtree.InitializeFence(ctx, treeStore, root, dir); err != nil {
		t.Fatal(err)
	}
	if err := treeStore.CreateDirectoryWithFacts(ctx, sealedtree.Entry{ParentID: rootID, ObjectID: objectID, Kind: "directory", Name: "fixture"}, sealedtree.Facts{ObjectID: objectID}); err != nil {
		t.Fatal(err)
	}
	acquired := make(chan struct{}, 4)
	acquire := func(ctx context.Context) (IngressPrerequisiteLease, error) {
		lease, err := treeStore.AcquireReadFence(ctx)
		if err == nil {
			acquired <- struct{}{}
		}
		return lease, err
	}
	if err := master.ConfigureIngressSelectionReadiness(ctx, acquire); err != nil {
		t.Fatal(err)
	}
	<-acquired
	current, admission, err := master.AcquireCurrentIngress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer admission.Release()
	<-acquired
	bound, err := store.BindIngressPrerequisite(ctx, admission)
	if err != nil {
		t.Fatal(err)
	}
	prerequisite, ok := store.IngressPrerequisiteFromContext(bound)
	if !ok {
		t.Fatal("tree prerequisite missing from admitted context")
	}
	treeLease, ok := prerequisite.(*sealedtree.TreeLease)
	if !ok || treeLease.Check(bound) != nil {
		t.Fatal("admitted context did not retain the real tree lease")
	}
	identity, err := master.IdentityState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	selected := make(chan error, 1)
	go func() {
		wait, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		_, err := master.SelectPublicIngress(wait, identity.ID, current.Generation, store.NodeAudit{Actor: "fixture"})
		selected <- err
	}()
	select {
	case <-acquired:
	case <-time.After(5 * time.Second):
		t.Fatal("selection did not acquire the tree fence")
	}
	written := make(chan error, 1)
	go func() {
		_, err := treeStore.SetFacts(ctx, sealedtree.Facts{ObjectID: objectID, Visibility: &sealedtree.VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}}, 1)
		written <- err
	}()
	select {
	case err := <-written:
		t.Fatal("tree writer bypassed ingress authorization", err)
	case <-time.After(150 * time.Millisecond):
	}
	if err := admission.Commit(); err != nil {
		t.Fatal("admission commit", err)
	}
	if treeLease.Check(bound) == nil {
		t.Fatal("retained context extended released tree authority")
	}
	if _, err := store.BindIngressPrerequisite(ctx, admission); err == nil {
		t.Fatal("released ingress lease rebound tree authority")
	}
	select {
	case err := <-selected:
		if err != nil {
			t.Fatal("selection after admission", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tree and ingress locks deadlocked")
	}
	select {
	case err := <-written:
		if err != nil {
			t.Fatal("tree writer did not proceed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tree writer remained blocked")
	}
	relayCtx, relayLease, err := master.AcquireResourcePrerequisite(ctx)
	if err != nil || relayLease == nil {
		t.Fatal("relay tree fence", err)
	}
	<-acquired
	relayView, ok := store.IngressPrerequisiteFromContext(relayCtx)
	if !ok || relayView != relayLease || relayView.Check(relayCtx) != nil {
		t.Fatal("relay context did not carry its held tree fence")
	}
	relayLease.Release()
	if relayView.Check(relayCtx) == nil {
		t.Fatal("relay tree authority remained live after release")
	}
	_, faulted, err := master.AcquireCurrentIngress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer faulted.Release()
	<-acquired
	if err := os.Remove(filepath.Join(dir, "tree-write.fence")); err != nil {
		t.Fatal(err)
	}
	if err := faulted.Commit(); err == nil {
		t.Fatal("replaced tree fence committed ingress admission")
	}
	if _, lease, err := master.AcquireCurrentIngress(ctx); err == nil || lease != nil {
		t.Fatal("missing tree fence admitted a new request")
	}
}
