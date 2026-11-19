//go:build linux

package node

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestOpaqueProbeHoldsRealOwnerFenceAndCancellationReleases(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	transport := &localControl{nodes: map[string]*Service{}}
	master, _ := testNode(t, "Master", "https://master.test", transport)
	owner, db := testNode(t, "Follower", "https://owner.test", transport)
	transport.nodes["https://master.test"], transport.nodes["https://owner.test"] = master, owner
	pair, err := owner.CreatePair(ctx, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	id, err := master.ImportPair(ctx, pair, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	mr, err := master.repo.Relationship(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	upstream, err := owner.repo.Relationship(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := master.identity.vault.Unseal(mr.Credential)
	if err != nil {
		t.Fatal(err)
	}
	masterID, err := master.repo.ReadIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ownerID, err := owner.repo.ReadIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	challenge := strings.Repeat("a", 32)
	token, err := protocol.OpaqueIngressProbeToken(credential, id, masterID.ID, ownerID.ID, challenge, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	owner.ConfigureOpaqueReadProbe(func(context.Context) error { return nil })
	if _, err = owner.VerifyOwnedOpaqueMediaProbe(ctx, upstream, challenge, token); err == nil {
		t.Fatal("proof accepted without Owner fence")
	}
	dir := t.TempDir()
	if err = os.Mkdir(filepath.Join(dir, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fence, err := ownerfence.Create(root, dir, owner.identity)
	if err != nil {
		t.Fatal(err)
	}
	coordinator := db.Nodes().(interface {
		ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
		InitializeOwnerControlMarker(context.Context) error
		AcquireOwnerControlShared(context.Context) (store.OwnerControlLease, error)
	})
	if err = coordinator.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return fence.Acquire(c, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err = coordinator.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	owner.ConfigureOpaqueOwnerRequestReadiness(func(c context.Context) (IngressPrerequisiteLease, error) {
		return coordinator.AcquireOwnerControlShared(c)
	})
	started := make(chan struct{})
	owner.ConfigureOpaqueReadProbe(func(c context.Context) error { close(started); <-c.Done(); return c.Err() })
	probeCtx, cancelProbe := context.WithCancel(ctx)
	result := make(chan error, 1)
	go func() { _, e := owner.VerifyOwnedOpaqueMediaProbe(probeCtx, upstream, challenge, token); result <- e }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	blocked, stop := context.WithTimeout(ctx, 100*time.Millisecond)
	if lease, e := fence.Acquire(blocked, true); e == nil {
		lease.Release()
		stop()
		t.Fatal("exclusive writer crossed active probe")
	}
	stop()
	cancelProbe()
	select {
	case e := <-result:
		if e == nil {
			t.Fatal("cancelled probe produced a signed proof")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	lease, err := fence.Acquire(ctx, true)
	if err != nil {
		t.Fatal("cancelled probe retained Owner fence", err)
	}
	lease.Release()
	owner.ConfigureOpaqueReadProbe(func(context.Context) error { return nil })
	if _, err = owner.VerifyOwnedOpaqueMediaProbe(ctx, upstream, challenge, token); err != nil {
		t.Fatal("valid fenced proof", err)
	}
}
