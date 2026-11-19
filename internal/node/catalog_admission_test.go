package node

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type catalogTestLease struct{ released, committed bool }

func (l *catalogTestLease) Commit() error {
	if l.released {
		return errors.New("released")
	}
	l.committed = true
	return nil
}
func (l *catalogTestLease) Release() { l.released = true }

type catalogTestPrerequisite struct{ released bool }

func TestCatalogPrerequisiteZeroValueFailsClosed(t *testing.T) {
	var prerequisite CatalogPrerequisite
	if prerequisite.Check(context.Background()) == nil {
		t.Fatal("zero composite accepted")
	}
	released := false
	if prerequisite.commitCatalog(context.Background(), func(context.Context, store.IngressPrerequisite) error { return nil }, func() error { return nil }, func() { released = true }) == nil || !released {
		t.Fatal("zero composite did not fail closed")
	}
	prerequisite.Release()
}

func (l *catalogTestPrerequisite) Check(context.Context) error {
	if l.released {
		return errors.New("released")
	}
	return nil
}
func (l *catalogTestPrerequisite) Release() { l.released = true }
func (l *catalogTestPrerequisite) commitCatalog(ctx context.Context, check func(context.Context, store.IngressPrerequisite) error, commit func() error, release func()) error {
	defer l.Release()
	defer release()
	if err := l.Check(ctx); err != nil {
		return err
	}
	if err := check(ctx, l); err != nil {
		return err
	}
	return commit()
}

type catalogTestRepository struct {
	store.NodeRepository
	store.PublicRoutingRepository
	relation   store.Relationship
	identityID string
	order      *[]string
	lease      *catalogTestLease
}

func (r *catalogTestRepository) AcquireCurrentIngress(context.Context) (store.PublicIngress, store.PublicIngressLease, error) {
	*r.order = append(*r.order, "ingress")
	r.lease = &catalogTestLease{}
	return store.PublicIngress{NodeID: r.relation.PeerID, Generation: 7, PublicOrigin: "https://entry.test"}, r.lease, nil
}
func (r *catalogTestRepository) PublicIngress(context.Context) (store.PublicIngress, error) {
	return store.PublicIngress{NodeID: r.relation.PeerID, Generation: 7, PublicOrigin: "https://entry.test"}, nil
}
func (r *catalogTestRepository) ExistingPublicIngress(ctx context.Context) (store.PublicIngress, error) {
	return r.PublicIngress(ctx)
}
func (r *catalogTestRepository) AcquireExistingIngress(ctx context.Context) (store.PublicIngress, store.PublicIngressLease, error) {
	return r.AcquireCurrentIngress(ctx)
}
func (r *catalogTestRepository) ReadIdentity(context.Context) (store.NodeIdentity, error) {
	return store.NodeIdentity{Role: "Master", ID: r.identityID}, nil
}

func TestLocalCatalogAdmissionRejectsSyntheticPrerequisite(t *testing.T) {
	ctx := context.Background()
	id := strings.Repeat("a", 32)
	order := []string{}
	repo := &catalogTestRepository{identityID: id, relation: store.Relationship{PeerID: id}, order: &order}
	var ready *catalogTestPrerequisite
	svc := &Service{repo: repo, ingressSelectionReady: func(context.Context) (IngressPrerequisiteLease, error) {
		ready = &catalogTestPrerequisite{}
		return ready, nil
	}}
	expected := store.PublicIngress{NodeID: id, Generation: 7, PublicOrigin: "https://entry.test"}
	_, lease, err := svc.AcquireLocalCatalogIngress(ctx, expected, func(context.Context, store.IngressPrerequisite) error { t.Error("scope called"); return nil })
	if err == nil || lease != nil || ready == nil || !ready.released || repo.lease != nil {
		t.Fatal("synthetic admission accepted", err)
	}
}
func (r *catalogTestRepository) Relationship(context.Context, string) (store.Relationship, error) {
	*r.order = append(*r.order, "relationship")
	return r.relation, nil
}

func TestCatalogAdmissionRejectsSyntheticPrerequisite(t *testing.T) {
	ctx := context.Background()
	auth := store.Relationship{ID: strings.Repeat("1", 32), PeerID: strings.Repeat("2", 32), Direction: "downstream", State: "active", Protocol: protocol.Version, Credential: "sealed-fixture", PublicKey: "fixture-key", Endpoint: "https://peer.test", CreatedAt: 5}
	order := []string{}
	repo := &catalogTestRepository{relation: auth, order: &order}
	var ready *catalogTestPrerequisite
	svc := &Service{repo: repo, peerIngressSelection: true, ingressSelectionReady: func(context.Context) (IngressPrerequisiteLease, error) {
		ready = &catalogTestPrerequisite{}
		return ready, nil
	}}
	expected := store.PublicIngress{NodeID: auth.PeerID, Generation: 7, PublicOrigin: "https://entry.test"}
	_, lease, err := svc.AcquireCatalogIngress(ctx, auth, expected, func(context.Context, store.IngressPrerequisite) error { t.Error("scope called"); return nil })
	if err == nil || lease != nil || ready == nil || !ready.released || repo.lease != nil {
		t.Fatal("synthetic admission accepted", err)
	}
}

func TestCatalogRelationshipRejectsIdentityChanges(t *testing.T) {
	base := store.Relationship{ID: strings.Repeat("1", 32), PeerID: strings.Repeat("2", 32), Direction: "downstream", State: "active", Protocol: protocol.Version, Credential: "sealed-fixture", PublicKey: "fixture-key", Endpoint: "https://peer.test", Mode: "Relay", CreatedAt: 5}
	if !sameCatalogRelationship(base, base) {
		t.Fatal("identical relationship rejected")
	}
	for _, change := range []func(*store.Relationship){
		func(r *store.Relationship) { r.ID = strings.Repeat("3", 32) },
		func(r *store.Relationship) { r.PeerID = strings.Repeat("4", 32) },
		func(r *store.Relationship) { r.Credential = "changed" },
		func(r *store.Relationship) { r.PublicKey = "changed" },
		func(r *store.Relationship) { r.Endpoint = "https://other.test" },
		func(r *store.Relationship) { r.State = "revoked" },
		func(r *store.Relationship) { r.Mode = "Direct" },
		func(r *store.Relationship) { r.CreatedAt++ },
	} {
		changed := base
		change(&changed)
		if sameCatalogRelationship(base, changed) {
			t.Fatal("changed relationship accepted")
		}
	}
}
