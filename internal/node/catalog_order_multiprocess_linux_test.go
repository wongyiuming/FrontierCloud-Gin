//go:build linux

package node

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"golang.org/x/sys/unix"
)

func TestCatalogOrderTreeLockChild(t *testing.T) {
	path := os.Getenv("FC_CATALOG_TREE_LOCK_CHILD")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	fmt.Println("child-tree-locked")
	var b [1]byte
	if _, err := os.Stdin.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
}

func TestSelectionOrderLocksChild(t *testing.T) {
	ingressPath := os.Getenv("FC_SELECTION_INGRESS_LOCK_CHILD")
	if ingressPath == "" {
		return
	}
	treePath := os.Getenv("FC_SELECTION_TREE_LOCK_CHILD")
	ingress, err := os.OpenFile(ingressPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ingress.Close()
	tree, err := os.OpenFile(treePath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer tree.Close()
	if err := unix.Flock(int(ingress.Fd()), unix.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	fmt.Println("child-ingress-shared")
	var b [1]byte
	if _, err := os.Stdin.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(tree.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	fmt.Println("child-tree-exclusive")
	if _, err := os.Stdin.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(ingress.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	fmt.Println("child-ingress-released")
	if _, err := os.Stdin.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(tree.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogFinalLockOrderAndCancellationAcrossProcesses(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	master, app := testNode(t, "Master", "https://master.test", nil)
	if err := master.ConfigurePublicOrigin("https://public.test"); err != nil {
		t.Fatal(err)
	}
	routing := master.repo.(store.PublicRoutingRepository)
	expected, err := routing.PublicIngress(ctx)
	if err != nil {
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
	defer ownerRoot.Close()
	fence, err := ownerfence.Create(ownerRoot, ownerDir, master.identity)
	if err != nil {
		t.Fatal(err)
	}
	owner := master.repo.(interface {
		ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
		InitializeOwnerControlMarker(context.Context) error
		AcquireOwnerControlShared(context.Context) (store.OwnerControlLease, error)
	})
	if err := owner.ConfigureOwnerControlFence(func(c context.Context, x bool) (store.OwnerControlLease, error) { return fence.Acquire(c, x) }); err != nil {
		t.Fatal(err)
	}
	if err := owner.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "tree.sqlite"))+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	codec, err := sealedtree.New(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	tree, err := sealedtree.InitializeSQLite(ctx, db, codec, strings.Repeat("a", 64))
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
	if _, err := sealedtree.InitializeFence(ctx, tree, root, dir); err != nil {
		t.Fatal(err)
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	var count atomic.Int32
	var pause atomic.Bool
	acquire := func(c context.Context) (store.OwnerControlLease, error) {
		lease, e := owner.AcquireOwnerControlShared(c)
		if e == nil && pause.Load() && count.Add(1) == 2 {
			close(entered)
			select {
			case <-resume:
			case <-c.Done():
				lease.Release()
				return nil, c.Err()
			}
		}
		return lease, e
	}
	if err := master.ConfigureIngressSelectionReadiness(ctx, func(c context.Context) (IngressPrerequisiteLease, error) {
		return AcquireCatalogPrerequisite(c, acquire, tree)
	}); err != nil {
		t.Fatal(err)
	}
	pause.Store(true)
	wait, stop := context.WithCancel(ctx)
	finished := make(chan error, 1)
	go func() {
		_, lease, e := master.AcquireLocalCatalogIngress(wait, expected, func(context.Context, store.IngressPrerequisite) error { return nil })
		if lease != nil {
			lease.Release()
		}
		finished <- e
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("final Owner acquisition did not start")
	}
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCatalogOrderTreeLockChild$")
	child.Env = append(os.Environ(), "FC_CATALOG_TREE_LOCK_CHILD="+filepath.Join(dir, "tree-write.fence"))
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = stdin.Close()
		if child.ProcessState == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "child-tree-locked" {
		t.Fatal("child did not hold tree")
	}
	close(resume)
	var databasePath string
	if err := app.Database().QueryRowContext(ctx, "SELECT file FROM pragma_database_list WHERE name='main'").Scan(&databasePath); err != nil {
		t.Fatal(err)
	}
	ingressFile, err := os.OpenFile(databasePath+store.PublicIngressLeaseSuffix, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ingressFile.Close()
	deadline := time.Now().Add(4 * time.Second)
	blocked := false
	for time.Now().Before(deadline) {
		e := unix.Flock(int(ingressFile.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if e == unix.EWOULDBLOCK || e == unix.EAGAIN {
			blocked = true
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		_ = unix.Flock(int(ingressFile.Fd()), unix.LOCK_UN)
		time.Sleep(10 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("admission did not acquire ingress before waiting for tree")
	}
	stop()
	select {
	case e := <-finished:
		if e == nil {
			t.Fatal("cancelled admission succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not release ordered locks")
	}
	if err := unix.Flock(int(ingressFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("ingress lock leaked after cancel", err)
	}
	_ = unix.Flock(int(ingressFile.Fd()), unix.LOCK_UN)
	if _, err := stdin.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	pause.Store(false)
	_, lease, err := master.AcquireLocalCatalogIngress(ctx, expected, func(context.Context, store.IngressPrerequisite) error { return nil })
	if err != nil || lease == nil {
		t.Fatal("ordered retry", err)
	}
	if err := lease.Commit(); err != nil {
		t.Fatal("ordered retry commit", err)
	}
	if err := master.ConfigureOpaqueIngressSelectionTree(ctx, tree); err != nil {
		t.Fatal(err)
	}
	// Hold ingress shared in a different process, let the real selection take
	// Owner exclusive, then take tree exclusive. After releasing ingress the
	// selection must take it before it waits on tree; cancellation must unwind.
	selectChild := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSelectionOrderLocksChild$")
	selectChild.Env = append(os.Environ(), "FC_SELECTION_INGRESS_LOCK_CHILD="+databasePath+store.PublicIngressLeaseSuffix, "FC_SELECTION_TREE_LOCK_CHILD="+filepath.Join(dir, "tree-write.fence"))
	selectIn, err := selectChild.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	selectOut, err := selectChild.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := selectChild.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = selectIn.Close()
		if selectChild.ProcessState == nil {
			_ = selectChild.Process.Kill()
			_ = selectChild.Wait()
		}
	}()
	selectScanner := bufio.NewScanner(selectOut)
	if !selectScanner.Scan() || selectScanner.Text() != "child-ingress-shared" {
		t.Fatal("child did not hold ingress")
	}
	selectionCtx, cancelSelection := context.WithCancel(ctx)
	selected := make(chan error, 1)
	go func() {
		_, e := master.SelectPublicIngress(selectionCtx, expected.NodeID, expected.Generation, store.NodeAudit{})
		selected <- e
	}()
	ownerFile, err := os.OpenFile(filepath.Join(ownerDir, ".opaque-aliases", ".owner-control-lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ownerFile.Close()
	ownerBlocked := false
	for deadline := time.Now().Add(4 * time.Second); time.Now().Before(deadline); {
		e := unix.Flock(int(ownerFile.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if e == unix.EWOULDBLOCK || e == unix.EAGAIN {
			ownerBlocked = true
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		_ = unix.Flock(int(ownerFile.Fd()), unix.LOCK_UN)
		time.Sleep(10 * time.Millisecond)
	}
	if !ownerBlocked {
		t.Fatal("selection did not acquire Owner exclusive")
	}
	if _, err := selectIn.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if !selectScanner.Scan() || selectScanner.Text() != "child-tree-exclusive" {
		t.Fatal("child did not hold tree")
	}
	if _, err := selectIn.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if !selectScanner.Scan() || selectScanner.Text() != "child-ingress-released" {
		t.Fatal("child did not release ingress")
	}
	ingressBlocked := false
	for deadline := time.Now().Add(4 * time.Second); time.Now().Before(deadline); {
		e := unix.Flock(int(ingressFile.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if e == unix.EWOULDBLOCK || e == unix.EAGAIN {
			ingressBlocked = true
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		_ = unix.Flock(int(ingressFile.Fd()), unix.LOCK_UN)
		time.Sleep(10 * time.Millisecond)
	}
	if !ingressBlocked {
		t.Fatal("selection did not acquire ingress before waiting for tree")
	}
	cancelSelection()
	select {
	case e := <-selected:
		if e == nil {
			t.Fatal("cancelled selection succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("selection did not release after cancellation")
	}
	if err := unix.Flock(int(ingressFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("selection leaked ingress", err)
	}
	_ = unix.Flock(int(ingressFile.Fd()), unix.LOCK_UN)
	if err := unix.Flock(int(ownerFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("selection leaked Owner", err)
	}
	_ = unix.Flock(int(ownerFile.Fd()), unix.LOCK_UN)
	if _, err := selectIn.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := selectChild.Wait(); err != nil {
		t.Fatal(err)
	}
}
