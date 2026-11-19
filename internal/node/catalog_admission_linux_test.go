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

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// The tree lock is real; routing and the already authenticated relationship
// are fixture implementations. It is not a public proxy integration test.
func TestCatalogAdmissionRealTreeScopeFencesCommit(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "catalog.sqlite"))+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	codec, err := sealedtree.New(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rootID, parentID := strings.Repeat("a", 64), strings.Repeat("b", 64)
	tree, err := sealedtree.InitializeSQLite(ctx, db, codec, rootID)
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
	if err := tree.CreateDirectoryWithFacts(ctx, sealedtree.Entry{ParentID: rootID, ObjectID: parentID, Kind: "directory", Name: "music"}, sealedtree.Facts{ObjectID: parentID}); err != nil {
		t.Fatal(err)
	}
	read, err := tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := tree.CaptureCatalogScopeWithLease(ctx, read, parentID, false)
	read.Release()
	if err != nil {
		t.Fatal(err)
	}
	auth := store.Relationship{ID: strings.Repeat("1", 32), PeerID: strings.Repeat("2", 32), Direction: "downstream", State: "active", Protocol: protocol.Version, Credential: "sealed-fixture", PublicKey: "fixture-key", Endpoint: "https://peer.test", CreatedAt: 5}
	order := []string{}
	repo := &catalogTestRepository{relation: auth, order: &order}
	svc := &Service{repo: repo, peerIngressSelection: true, ingressSelectionReady: func(c context.Context) (IngressPrerequisiteLease, error) {
		return AcquireCatalogPrerequisite(c, func(context.Context) (store.OwnerControlLease, error) { return &compositeFixtureOwner{}, nil }, tree)
	}}
	expected := store.PublicIngress{NodeID: auth.PeerID, Generation: 7, PublicOrigin: "https://entry.test"}
	check := func(c context.Context, lease store.IngressPrerequisite) error {
		v, ok := lease.(interface {
			CheckCatalogScopes(context.Context, *sealedtree.SQLStore, []sealedtree.CatalogScopeCheck) error
		})
		if !ok {
			return store.ErrNodeState
		}
		return v.CheckCatalogScopes(c, tree, []sealedtree.CatalogScopeCheck{{ParentID: parentID, IncludeHidden: false, Proof: proof}})
	}
	_, admitted, err := svc.AcquireCatalogIngress(ctx, auth, expected, check)
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, e := tree.SetFacts(ctx, sealedtree.Facts{ObjectID: parentID, Visibility: &sealedtree.VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}}, 1)
		writeDone <- e
	}()
	select {
	case e := <-writeDone:
		t.Fatal("tree writer escaped final admission", e)
	case <-time.After(100 * time.Millisecond):
	}
	if err := admitted.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-writeDone:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tree writer stuck")
	}
	_, lease, err := svc.AcquireCatalogIngress(ctx, auth, expected, check)
	if err != nil || lease.Commit() == nil {
		t.Fatal("changed ancestor scope admitted", err)
	}
}

type compositeFixtureOwner struct {
	released   bool
	onRelease  func()
	panicCheck bool
	onCheck    func()
}

func (l *compositeFixtureOwner) Check(ctx context.Context) error {
	if l.panicCheck {
		panic("owner check fixture")
	}
	if l.onCheck != nil {
		l.onCheck()
	}
	if l.released {
		return store.ErrNodeState
	}
	return ctx.Err()
}
func (l *compositeFixtureOwner) Binding(ctx context.Context) (string, error) {
	if err := l.Check(ctx); err != nil {
		return "", err
	}
	return strings.Repeat("a", 64), nil
}
func (l *compositeFixtureOwner) Release() {
	if !l.released {
		l.released = true
		if l.onRelease != nil {
			l.onRelease()
		}
	}
}

// Real tree fence with a synthetic owner/ingress fence. Production must still
// verify the actual ownerControl inode, DB marker and every writer/recovery.
func TestCatalogCompositeOwnerTreeIngressOrder(t *testing.T) {
	ctx := context.Background()
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
	id := strings.Repeat("1", 32)
	order := []string{}
	repo := &catalogTestRepository{identityID: id, relation: store.Relationship{PeerID: id}, order: &order}
	var borrowed store.IngressPrerequisite
	var composite *CatalogPrerequisite
	var owner *compositeFixtureOwner
	service := &Service{repo: repo, ingressSelectionReady: func(c context.Context) (IngressPrerequisiteLease, error) {
		value, err := AcquireCatalogPrerequisite(c, func(context.Context) (store.OwnerControlLease, error) {
			order = append(order, "owner")
			owner = &compositeFixtureOwner{onRelease: func() {
				if borrowed != nil && borrowed.Check(ctx) == nil {
					t.Error("tree remained held at owner release")
				}
				if repo.lease != nil && !repo.lease.committed && !repo.lease.released {
					t.Error("ingress remained held at owner release")
				}
				order = append(order, "release-owner")
			}}
			return owner, nil
		}, tree)
		composite = value
		return value, err
	}}
	expected := store.PublicIngress{NodeID: id, Generation: 7, PublicOrigin: "https://entry.test"}
	entered, resume := make(chan struct{}), make(chan struct{})
	resourceReleased := make(chan struct{})
	var admission store.PublicIngressLease
	_, admission, err = service.AcquireLocalCatalogIngress(ctx, expected, func(c context.Context, v store.IngressPrerequisite) error {
		carrier, ok := v.(interface {
			CatalogOwnerBinding(context.Context) (string, error)
		})
		if !ok {
			return store.ErrNodeState
		}
		if _, canRelease := v.(interface{ Release() }); canRelease {
			return store.ErrNodeState
		}
		holder, ok := v.(interface{ HoldCatalogResource(func()) error })
		if !ok || holder.HoldCatalogResource(func() { close(resourceReleased) }) != nil {
			return store.ErrNodeState
		}
		canceler, ok := v.(interface{ CancelCatalogAdmission() })
		if !ok {
			return store.ErrNodeState
		}
		borrowed = v
		owner.onCheck = func() {
			if v.Check(c) == nil || composite.Check(c) == nil {
				t.Error("recursive check accepted")
			}
			composite.Release()
			admission.Release()
			canceler.CancelCatalogAdmission()
		}
		if v.Check(c) != nil {
			return store.ErrNodeState
		}
		owner.onCheck = nil
		binding, e := carrier.CatalogOwnerBinding(c)
		if e != nil || binding != strings.Repeat("a", 64) {
			return store.ErrNodeState
		}
		order = append(order, "scope")
		close(entered)
		<-resume
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(order, ","); got != "owner,release-owner,owner,ingress" {
		t.Fatal("lock order", got)
	}
	committed := make(chan error, 1)
	go func() { committed <- admission.Commit() }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("scope check not entered")
	}
	released := make(chan struct{})
	go func() { composite.Release(); close(released) }()
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("release blocked during final commit")
	}
	if owner.released {
		t.Fatal("concurrent release bypassed final commit guard")
	}
	select {
	case <-resourceReleased:
		t.Fatal("resource released before commit")
	default:
	}
	close(resume)
	select {
	case err := <-committed:
		if err == nil || repo.lease.committed {
			t.Fatal("release before commit did not cancel admission", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("commit deadlocked")
	}
	select {
	case <-resourceReleased:
	default:
		t.Fatal("commit did not release resource")
	}
	if !owner.released || borrowed.Check(ctx) == nil || strings.Join(order, ",") != "owner,release-owner,owner,ingress,scope,release-owner" {
		t.Fatal("reverse release", order)
	}
	admission.Release()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	var failedOwner *compositeFixtureOwner
	_, err = AcquireCatalogPrerequisite(cancelled, func(context.Context) (store.OwnerControlLease, error) {
		failedOwner = &compositeFixtureOwner{}
		return failedOwner, nil
	}, tree)
	if err == nil || !failedOwner.released {
		t.Fatal("cancellation stranded owner")
	}
	reentrantOwner := &compositeFixtureOwner{}
	reentrant, err := AcquireCatalogPrerequisite(ctx, func(context.Context) (store.OwnerControlLease, error) { return reentrantOwner, nil }, tree)
	if err != nil {
		t.Fatal(err)
	}
	reentrantOwner.onCheck = reentrant.Release
	if reentrant.Check(ctx) == nil || !reentrantOwner.released {
		t.Fatal("owner check accepted after reentrant release")
	}
	panicOwner := &compositeFixtureOwner{panicCheck: true}
	func() {
		defer func() {
			if recover() == nil || !panicOwner.released {
				t.Error("owner check panic stranded owner")
			}
		}()
		_, _ = AcquireCatalogPrerequisite(ctx, func(context.Context) (store.OwnerControlLease, error) { return panicOwner, nil }, tree)
	}()
	panicOwner = &compositeFixtureOwner{}
	guard, err := AcquireCatalogPrerequisite(ctx, func(context.Context) (store.OwnerControlLease, error) { return panicOwner, nil }, tree)
	if err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if recover() == nil || !panicOwner.released {
				t.Error("ingress release panic stranded composite")
			}
		}()
		_ = guard.commitCatalog(ctx, func(context.Context, store.IngressPrerequisite) error { return nil }, func() error { return nil }, func() { panic("ingress release fixture") })
	}()
	writerCtx, writerCancel := context.WithTimeout(ctx, time.Second)
	defer writerCancel()
	newID := strings.Repeat("f", 64)
	if err := tree.CreateDirectoryWithFacts(writerCtx, sealedtree.Entry{ParentID: strings.Repeat("a", 64), ObjectID: newID, Kind: "directory", Name: "after-panic"}, sealedtree.Facts{ObjectID: newID}); err != nil {
		t.Fatal("tree writer failed after ingress release panic", err)
	}
	borrowLease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	checkStarted, checkContinue := make(chan struct{}), make(chan struct{})
	borrowOwner := &compositeFixtureOwner{onCheck: func() { close(checkStarted); <-checkContinue }}
	borrow := &catalogBorrow{active: true, owner: borrowOwner, tree: borrowLease}
	checkResult := make(chan error, 1)
	go func() { checkResult <- borrow.Check(ctx) }()
	<-checkStarted
	closed := make(chan struct{})
	go func() { borrow.close(); close(closed) }()
	deadline := time.After(5 * time.Second)
	for {
		borrow.mu.Lock()
		active := borrow.active
		borrow.mu.Unlock()
		if !active {
			break
		}
		select {
		case <-deadline:
			t.Fatal("borrow close did not start")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	close(checkContinue)
	if err := <-checkResult; err == nil {
		t.Fatal("closing borrow returned valid check")
	}
	<-closed
	borrowLease.Release()
	postOwner := &compositeFixtureOwner{}
	postGuard, err := AcquireCatalogPrerequisite(ctx, func(context.Context) (store.OwnerControlLease, error) { return postOwner, nil }, tree)
	if err != nil {
		t.Fatal(err)
	}
	commitStarted, finishCommit := make(chan struct{}), make(chan struct{})
	commitResult := make(chan error, 1)
	go func() {
		commitResult <- postGuard.commitCatalog(ctx, func(context.Context, store.IngressPrerequisite) error { return nil }, func() error {
			close(commitStarted)
			<-finishCommit
			return nil
		}, func() {})
	}()
	<-commitStarted
	postGuard.Release()
	if postOwner.released {
		t.Fatal("post-linearization release unlocked owner during commit")
	}
	close(finishCommit)
	if err := <-commitResult; err != nil || !postOwner.released {
		t.Fatal("post-linearization commit failed or stranded owner", err)
	}
	readOwner := &compositeFixtureOwner{}
	readGuard, err := AcquireCatalogPrerequisite(ctx, func(context.Context) (store.OwnerControlLease, error) { return readOwner, nil }, tree)
	if err != nil {
		t.Fatal(err)
	}
	ingress := &readyIngressLease{ctx: ctx, ready: readGuard, inner: &catalogTestLease{}}
	bound, err := ingress.BindPrerequisite(ctx)
	if err != nil {
		t.Fatal(err)
	}
	readOnly, ok := store.IngressPrerequisiteFromContext(bound)
	if !ok || readOnly.Check(ctx) != nil {
		t.Fatal("missing ingress tree borrow")
	}
	if _, canRelease := readOnly.(interface{ Release() }); canRelease {
		t.Fatal("ingress borrow exposes release")
	}
	reader, ok := readOnly.(interface {
		ReadVisibleObject(context.Context, *sealedtree.SQLStore, string) (sealedtree.VisibleObject, error)
	})
	if !ok {
		t.Fatal("missing bounded tree reader")
	}
	if _, err := reader.ReadVisibleObject(ctx, &sealedtree.SQLStore{}, newID); err == nil {
		t.Fatal("borrow accepted a different tree")
	}
	if err := ingress.Commit(); err != nil {
		t.Fatal(err)
	}
	if readOnly.Check(ctx) == nil || !readOwner.released {
		t.Fatal("ingress borrow survived commit")
	}
	resourceService := &Service{ingressSelectionReady: func(c context.Context) (IngressPrerequisiteLease, error) {
		return AcquireCatalogPrerequisite(c, func(context.Context) (store.OwnerControlLease, error) { return &compositeFixtureOwner{}, nil }, tree)
	}}
	resourceCtx, resourceLease, err := resourceService.AcquireResourcePrerequisite(ctx)
	if err != nil {
		t.Fatal(err)
	}
	resourceBorrow, ok := store.IngressPrerequisiteFromContext(resourceCtx)
	if !ok || resourceBorrow.Check(ctx) != nil {
		t.Fatal("Relay borrow missing")
	}
	if _, ok := resourceBorrow.(interface{ Release() }); ok {
		t.Fatal("Relay borrow exposes release")
	}
	if _, ok := resourceBorrow.(interface {
		ReadVisibleObjectByAlias(context.Context, *sealedtree.SQLStore, string) (sealedtree.VisibleObject, error)
	}); !ok {
		t.Fatal("Relay borrow lacks alias read")
	}
	resourceLease.Release()
	if resourceBorrow.Check(ctx) == nil {
		t.Fatal("Relay borrow survived release")
	}
	newBoundAdmission := func() (*readyIngressLease, store.IngressPrerequisite, *catalogTestLease) {
		t.Helper()
		guard, e := AcquireCatalogPrerequisite(ctx, func(context.Context) (store.OwnerControlLease, error) { return &compositeFixtureOwner{}, nil }, tree)
		if e != nil {
			t.Fatal(e)
		}
		inner := &catalogTestLease{}
		admitted := &readyIngressLease{ctx: ctx, ready: guard, inner: inner}
		bound, e := admitted.BindPrerequisite(ctx)
		if e != nil {
			t.Fatal(e)
		}
		view, ok := store.IngressPrerequisiteFromContext(bound)
		if !ok {
			t.Fatal("precommit borrow missing")
		}
		return admitted, view, inner
	}
	checked, view, inner := newBoundAdmission()
	register, ok := view.(interface {
		RegisterPrecommitCheck(func(context.Context) error, time.Time) error
	})
	if !ok {
		t.Fatal("precommit registration missing")
	}
	stateValid := true
	if err := register.RegisterPrecommitCheck(func(context.Context) error {
		if !stateValid {
			return store.ErrNodeState
		}
		return nil
	}, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	stateValid = false
	if checked.Commit() == nil || inner.committed || !inner.released {
		t.Fatal("changed owner state admitted")
	}
	checked, view, inner = newBoundAdmission()
	register = view.(interface {
		RegisterPrecommitCheck(func(context.Context) error, time.Time) error
	})
	if err := register.RegisterPrecommitCheck(func(context.Context) error { return nil }, time.Now().Add(100*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if checked.Commit() == nil || inner.committed || !inner.released {
		t.Fatal("expired owner heartbeat admitted")
	}
}
