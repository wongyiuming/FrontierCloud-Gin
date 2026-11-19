//go:build linux

package media

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestS3CatalogResolverRealPersistedProof(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	root, db, svc, member := s3CatalogFixture(t)
	row := publishS3CatalogObject(t, db, "music/S3Catalog/proof.mp3", nil)
	repo := db.Pool().(store.S3Repository)
	object, err := repo.S3Object(ctx, row.ID)
	if err != nil {
		t.Fatal(err)
	}
	member, err = repo.S3Member(ctx, member.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Nodes().(store.PublicRoutingRepository).PublicIngress(ctx); err != nil {
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
	tree := &sealedtree.SQLStore{}
	combined, err := svc.SealedCatalogOwnerResolver(tree)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = combined(ctx, member.ID); err == nil {
		t.Fatal("S3 catalog enabled without lifecycle gate")
	}
	gate := &s3ReadTestGate{}
	if err = svc.ConfigureOpaqueS3Read(tree, gate); err != nil {
		t.Fatal(err)
	}
	selected, err := combined(ctx, member.ID)
	if err != nil || selected.Transport != "S3" {
		t.Fatal("gated S3 catalog", err)
	}
	meta, err := mediacrypto.NewMetadata(7)
	if err != nil {
		t.Fatal(err)
	}
	physical := strings.Repeat("c", 64)
	selectedObject := strings.Repeat("a", 64)
	selectedPlacement := sealedtree.S3Placement{Version: 1, ObjectID: selectedObject, MemberID: member.ID, ObjectRevision: 1, Encryption: &meta,
		Location: s3store.Config{Endpoint: member.Location.Endpoint, Region: member.Location.Region, Bucket: member.Location.Bucket, Prefix: member.Location.Prefix, AddressStyle: member.Location.Style},
		Proof:    store.S3ObjectProof{MetadataFormat: store.S3OpaqueMetadata, MetadataOwner: strings.Repeat("d", 64), Key: "objects/cc/cc/" + physical + ".blob", SessionID: strings.Repeat("e", 32), ObjectID: strings.Repeat("f", 64), MemberID: member.ID, MediaID: selectedObject, Bytes: meta.CiphertextSize, ETag: `"etag"`, CompositeSHA256: base64.StdEncoding.EncodeToString(make([]byte, 32)) + "-1"}}
	if err = selected.CheckS3(&selectedPlacement); err != nil {
		t.Fatal("selected placement", err)
	}
	wrongPlacement := selectedPlacement
	wrongPlacement.Location.Bucket = "other-bucket"
	if selected.CheckS3(&wrongPlacement) == nil {
		t.Fatal("selected catalog accepted another namespace")
	}
	resolver, err := svc.S3CatalogOwnerResolver()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := resolver(ctx, member.ID)
	if err != nil || snapshot.Transport != "S3" {
		t.Fatal("S3 member", err)
	}
	location := s3store.Config{Endpoint: member.Location.Endpoint, Region: member.Location.Region, Bucket: member.Location.Bucket, Prefix: member.Location.Prefix, AddressStyle: member.Location.Style}
	placement := sealedtree.S3Placement{Version: 1, ObjectID: row.ID, MemberID: member.ID, ObjectRevision: object.Revision, Location: location, Proof: object.Proof}
	if err := snapshot.CheckS3(&placement); err != nil {
		t.Fatal("valid placement", err)
	}
	changed := placement
	changed.Location.Bucket = "wrong-bucket"
	if err := snapshot.CheckS3(&changed); err == nil {
		t.Fatal("foreign namespace accepted")
	}
	shared, err := owner.AcquireOwnerControlShared(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ingressRepo := db.Nodes().(store.ExistingIngressRepository)
	_, ingress, err := ingressRepo.AcquireExistingIngress(ctx)
	if err != nil {
		shared.Release()
		t.Fatal(err)
	}
	borrow := realCatalogOwnerBorrow{owner: shared}
	selectedLease, err := selected.Acquire(ctx, borrow)
	if err != nil {
		t.Fatal("selected owner admission", err)
	}
	gate.denied = true
	if selectedLease.Check(ctx) == nil {
		t.Fatal("selected gate revocation not observed")
	}
	gate.denied = false
	selectedLease.Release()
	if lease, err := snapshot.Acquire(ctx, borrow); err == nil || lease != nil {
		t.Fatal("S3 admission must remain disabled without same-tree writer proof", err)
	}
	// Exercise the point-in-time comparison independently. This synthetic
	// call is not an admission or evidence that legacy writers are fenced.
	s3Repo := svc.pool.(catalogS3Repository)
	routing := svc.nodes.(nativeCatalogRouting)
	view, err := svc.s3CatalogMember(ctx, s3Repo, routing, member.ID)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := shared.Binding(ctx)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := BorrowLocalCatalogOwnerSnapshot(binding)(ctx, borrow)
	if err != nil {
		t.Fatal(err)
	}
	lease := &s3CatalogLease{inner: inner, service: svc, repo: s3Repo, routing: routing, want: view, objects: map[string]s3CatalogProof{row.ID: {proof: object.Proof, revision: object.Revision}}}
	if lease.Check(ctx) != nil {
		t.Fatal("valid persisted proof rejected")
	}
	if _, err := db.Database().ExecContext(ctx, "UPDATE s3_members SET credential_revision=credential_revision+1 WHERE member_id=?", member.ID); err != nil {
		t.Fatal(err)
	}
	if lease.Check(ctx) == nil {
		t.Fatal("changed credential revision accepted")
	}
	if _, err := db.Database().ExecContext(ctx, "UPDATE s3_members SET credential_revision=credential_revision-1 WHERE member_id=?", member.ID); err != nil {
		t.Fatal(err)
	}
	if lease.Check(ctx) != nil {
		t.Fatal("restored credential revision rejected")
	}
	if _, err := db.Database().ExecContext(ctx, "UPDATE s3_objects SET revision=revision+1 WHERE media_id=?", row.ID); err != nil {
		t.Fatal(err)
	}
	if lease.Check(ctx) == nil {
		t.Fatal("changed object revision accepted")
	}
	lease.Release()
	ingress.Release()
	shared.Release()
	if lease.Check(ctx) == nil {
		t.Fatal("released lease accepted")
	}
}
