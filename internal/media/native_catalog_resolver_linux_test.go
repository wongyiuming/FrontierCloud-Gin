//go:build linux

package media

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

type realCatalogOwnerBorrow struct{ owner store.OwnerControlLease }

func (b realCatalogOwnerBorrow) Check(ctx context.Context) error { return b.owner.Check(ctx) }
func (b realCatalogOwnerBorrow) CatalogOwnerBinding(ctx context.Context) (string, error) {
	return b.owner.Binding(ctx)
}

func TestNativeCatalogResolverRealOwnerAndMembers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	root, db, svc := masterFixture(t)
	relation := store.Relationship{ID: strings.Repeat("a", 32), PeerID: strings.Repeat("b", 32), Endpoint: "https://owner.test:8443", PublicKey: strings.Repeat("c", 43), Credential: "sealed-fixture", Direction: "downstream", Mode: "Relay", State: "pending", Protocol: protocol.Version, CreatedAt: time.Now().Unix()}
	if err := db.Nodes().PrepareRelationship(ctx, relation, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Nodes().ActivateRelationship(ctx, relation.ID, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	ownerRoot, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer ownerRoot.Close()
	fence, err := ownerfence.Create(ownerRoot, root, svc.identity)
	if err != nil {
		t.Fatal(err)
	}
	owner := db.Nodes().(interface {
		ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
		InitializeOwnerControlMarker(context.Context) error
		AcquireOwnerControlShared(context.Context) (store.OwnerControlLease, error)
	})
	if err := owner.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return fence.Acquire(c, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err := owner.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	resolve, err := svc.NativeCatalogOwnerResolver()
	if err != nil {
		t.Fatal(err)
	}
	masterID := svc.identity.ID
	var ingressRows int
	if err := db.Database().QueryRowContext(ctx, "SELECT COUNT(*) FROM public_ingress_config").Scan(&ingressRows); err != nil || ingressRows != 0 {
		t.Fatal("fixture must start without ingress", ingressRows, err)
	}
	if _, err := resolve(ctx, masterID); err == nil {
		t.Fatal("uninitialized ingress must fail closed")
	}
	if err := db.Database().QueryRowContext(ctx, "SELECT COUNT(*) FROM public_ingress_config").Scan(&ingressRows); err != nil || ingressRows != 0 {
		t.Fatal("resolver initialized ingress", ingressRows, err)
	}
	if _, err := db.Nodes().(store.PublicRoutingRepository).PublicIngress(ctx); err != nil {
		t.Fatal("explicit ingress initialization", err)
	}
	local, err := resolve(ctx, masterID)
	if err != nil || local.Transport != "Local" {
		t.Fatal("Master Local", err)
	}
	remote, err := resolve(ctx, relation.PeerID)
	if err != nil || remote.Transport != "Relay" {
		t.Fatal("offline paired owner", err)
	}
	if _, err := db.Database().ExecContext(ctx, "UPDATE node_relationships SET mode='Direct' WHERE relationship_id=?", relation.ID); err != nil {
		t.Fatal(err)
	}
	direct, err := resolve(ctx, relation.PeerID)
	if err != nil || direct.Transport != "Direct" {
		t.Fatal("paired Direct owner", err)
	}
	if _, err := db.Database().ExecContext(ctx, "UPDATE node_relationships SET mode='Relay' WHERE relationship_id=?", relation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := resolve(ctx, strings.Repeat("d", 32)); err == nil {
		t.Fatal("unknown owner accepted")
	}
	if _, err := db.Database().ExecContext(ctx, "UPDATE cluster_storage_members SET member_kind='S3' WHERE member_id=?", relation.PeerID); err != nil {
		t.Fatal(err)
	}
	if _, err := resolve(ctx, relation.PeerID); err == nil {
		t.Fatal("S3 member accepted as native")
	}
	if _, err := db.Database().ExecContext(ctx, "UPDATE cluster_storage_members SET member_kind='Follower' WHERE member_id=?", relation.PeerID); err != nil {
		t.Fatal(err)
	}
	for _, snapshot := range []CatalogOwnerSnapshot{local, remote} {
		if _, err := snapshot.Acquire(ctx, &borrowedOwnerFixture{value: "forged", live: true}); err == nil {
			t.Fatal("foreign owner binding accepted")
		}
	}
	shared, err := owner.AcquireOwnerControlShared(ctx)
	if err != nil {
		t.Fatal(err)
	}
	routing := db.Nodes().(store.PublicRoutingRepository)
	_, ingress, err := routing.AcquireCurrentIngress(ctx)
	if err != nil {
		shared.Release()
		t.Fatal(err)
	}
	borrow := realCatalogOwnerBorrow{owner: shared}
	localLease, err := local.Acquire(ctx, borrow)
	if err != nil {
		t.Fatal("Master final snapshot", err)
	}
	remoteLease, err := remote.Acquire(ctx, borrow)
	if err != nil {
		t.Fatal("Follower final snapshot", err)
	}
	if localLease.Check(ctx) != nil || remoteLease.Check(ctx) != nil {
		t.Fatal("valid snapshot rejected")
	}
	if _, err := direct.Acquire(ctx, borrow); err == nil {
		t.Fatal("stale Direct mode accepted after policy change")
	}
	if _, err := db.Database().ExecContext(ctx, "UPDATE public_ingress_config SET generation=generation+1 WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	if localLease.Check(ctx) == nil || remoteLease.Check(ctx) == nil {
		t.Fatal("changed ingress generation accepted")
	}
	if _, err := db.Database().ExecContext(ctx, "UPDATE public_ingress_config SET generation=generation-1 WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	// Raw SQL intentionally models a non-cooperating writer; this isolated
	// test never grants raw SQL access as part of the application contract.
	if _, err := db.Database().ExecContext(ctx, "UPDATE node_relationships SET peer_key=? WHERE relationship_id=?", strings.Repeat("e", 43), relation.ID); err != nil {
		t.Fatal(err)
	}
	if remoteLease.Check(ctx) == nil {
		t.Fatal("changed relationship key accepted")
	}
	if localLease.Check(ctx) != nil {
		t.Fatal("unrelated owner identity changed")
	}
	localLease.Release()
	remoteLease.Release()
	ingress.Release()
	shared.Release()
	if remoteLease.Check(ctx) == nil {
		t.Fatal("released owner lease accepted")
	}
}
