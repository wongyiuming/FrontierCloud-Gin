//go:build linux

package node

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestRecoveryExpectedOwnerBindingPairedAndFenced(t *testing.T) {
	ctx := context.Background()
	transport := &localControl{nodes: map[string]*Service{}}
	master, _ := testNode(t, "Master", "https://master.test", transport)
	follower, db := testNode(t, "Follower", "https://owner.test", transport)
	transport.nodes["https://master.test"], transport.nodes["https://owner.test"] = master, follower
	pair, err := follower.CreatePair(ctx, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	relation, err := master.ImportPair(ctx, pair, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	masterID, err := master.repo.ReadIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ownerID, err := follower.repo.ReadIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rootPath := t.TempDir()
	if err = os.Chmod(rootPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(rootPath, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fence, err := ownerfence.Create(root, rootPath, follower.identity)
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Nodes().(interface {
		ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
		InitializeOwnerControlMarker(context.Context) error
		AcquireOwnerControlShared(context.Context) (store.OwnerControlLease, error)
	})
	if err = repo.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return fence.Acquire(c, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err = repo.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	lease, err := repo.AcquireOwnerControlShared(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	descriptor, err := protocol.IngressMediaDescriptor(10, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := sealedtree.RecoveryMediaPlacement{ObjectID: strings.Repeat("1", 64), Kind: "audio", OwnerID: ownerID.ID, BlobID: strings.Repeat("2", 64), Bytes: 10, NativeSHA256: strings.Repeat("3", 64), ReadAlias: strings.Repeat("4", 64), Descriptor: descriptor}
	p.AliasRevision, err = protocol.OpaquePlacementRevisionFromDescriptor(p.ReadAlias, p.BlobID, p.NativeSHA256, p.Descriptor, p.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	var binding protocol.OpaqueOwnerBinding
	call := func(v sealedtree.RecoveryMediaPlacement, m, r string) error {
		return follower.VisitRecoveryExpectedOwnerBinding(ctx, lease, m, r, v, func(b protocol.OpaqueOwnerBinding) error { binding = b; return nil })
	}
	if err = call(p, masterID.ID, relation); err != nil || !binding.Valid() || binding.MasterID != masterID.ID || binding.OwnerID != ownerID.ID || binding.RelationshipID != relation || binding.Blob != p.BlobID {
		t.Fatal("valid binding", err)
	}
	if call(p, strings.Repeat("f", 32), relation) == nil || call(p, masterID.ID, strings.Repeat("f", 32)) == nil {
		t.Fatal("wrong peer accepted")
	}
	hidden := p
	hidden.AliasRevoked, hidden.AliasRevocationOperationID = true, strings.Repeat("b", 32)
	if err = call(hidden, masterID.ID, relation); err != nil {
		t.Fatal("hidden binding", err)
	}
	hidden.AliasRevocationOperationID = ""
	if call(hidden, masterID.ID, relation) == nil {
		t.Fatal("missing hidden operation accepted")
	}
	recording := p
	recording.Kind, recording.ObjectID = "recording", strings.Repeat("a", 32)
	if err = call(recording, masterID.ID, relation); err != nil {
		t.Fatal("selected recording binding", err)
	}
	changed := p
	changed.NativeSHA256 = strings.Repeat("f", 64)
	if call(changed, masterID.ID, relation) == nil {
		t.Fatal("altered descriptor accepted")
	}
	if err = follower.VisitRecoveryExpectedOwnerBinding(ctx, lease, masterID.ID, relation, p, func(protocol.OpaqueOwnerBinding) error { lease.Release(); return nil }); err == nil {
		t.Fatal("lost Owner authority accepted")
	}
}
