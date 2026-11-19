package node

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// A non-reentrant synthetic lock makes a missing inherited repository lease
// time out; actual OS locking is tested separately by the ownerfence package.
type orderedControlFixture struct {
	slot   chan struct{}
	active atomic.Bool
}

type orderedControlLease struct{ fixture *orderedControlFixture }

func (l *orderedControlLease) Check(ctx context.Context) error {
	if !l.fixture.active.Load() {
		return errors.New("control fence released")
	}
	return ctx.Err()
}
func (l *orderedControlLease) Binding(ctx context.Context) (string, error) {
	if err := l.Check(ctx); err != nil {
		return "", err
	}
	return strings.Repeat("a", 64), nil
}
func (l *orderedControlLease) Release() {
	if l.fixture.active.Swap(false) {
		<-l.fixture.slot
	}
}
func (f *orderedControlFixture) acquire(ctx context.Context, exclusive bool) (store.OwnerControlLease, error) {
	if !exclusive {
		return nil, errors.New("expected exclusive control fence")
	}
	select {
	case f.slot <- struct{}{}:
		f.active.Store(true)
		return &orderedControlLease{fixture: f}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type orderedControlVolume struct{ fixture *orderedControlFixture }

func (v *orderedControlVolume) ControlLease(context.Context) (func(), error) {
	return func() {}, nil
}
func (v *orderedControlVolume) PhysicalCapacity(context.Context) (int64, int64, error) {
	return 20 * store.GiB, 10 * store.GiB, nil
}
func (v *orderedControlVolume) WithPromotion(_ context.Context, role string, apply func(store.NodePromotion) error) error {
	if !v.fixture.active.Load() {
		return errors.New("volume acquired before owner control fence")
	}
	return apply(store.NodePromotion{Role: role, PhysicalFree: 10 * store.GiB})
}

func TestOwnerControlFencePrecedesVolumeIdentityAndRelationshipWrites(t *testing.T) {
	for _, action := range []string{"promote", "storage-bootstrap", "reinitialize", "receive-revocation", "active-revocation"} {
		t.Run(action, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			transport := &localControl{nodes: map[string]*Service{}}
			role := "Standalone"
			if action == "reinitialize" || action == "receive-revocation" || action == "active-revocation" {
				role = "Follower"
			}
			s, db := testNode(t, role, "https://owner.test", transport)
			transport.nodes["https://owner.test"] = s
			var relation store.Relationship
			if action == "receive-revocation" || action == "active-revocation" {
				master, _ := testNode(t, "Master", "https://master.test", transport)
				transport.nodes["https://master.test"] = master
				pair, err := s.CreatePair(ctx, store.NodeAudit{})
				if err != nil {
					t.Fatal(err)
				}
				id, err := master.ImportPair(ctx, pair, store.NodeAudit{})
				if err != nil {
					t.Fatal(err)
				}
				relation, err = s.repo.Relationship(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
			}
			fence := &orderedControlFixture{slot: make(chan struct{}, 1)}
			config, ok := db.Nodes().(interface {
				ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
				InitializeOwnerControlMarker(context.Context) error
			})
			if !ok {
				t.Fatal("repository missing owner control fence")
			}
			if err := config.ConfigureOwnerControlFence(fence.acquire); err != nil {
				t.Fatal(err)
			}
			if err := config.InitializeOwnerControlMarker(ctx); err != nil {
				t.Fatal(err)
			}
			s.ConfigureVolumes(db.Pool(), &orderedControlVolume{fixture: fence}, recordingRoot(t))
			var err error
			switch action {
			case "promote":
				_, err = s.Promote(ctx, "Follower", "https://owner.test", 0, store.NodeAudit{})
			case "storage-bootstrap":
				err = s.InitializeStorage(ctx, "https://owner.test")
			case "reinitialize":
				identity, readErr := s.repo.ReadIdentity(ctx)
				if readErr != nil {
					t.Fatal(readErr)
				}
				_, err = s.Reinitialize(ctx, identity.ID, store.NodeAudit{})
			case "receive-revocation":
				err = s.ReceiveRevocation(ctx, relation)
			case "active-revocation":
				err = s.Revoke(ctx, relation.ID, store.NodeAudit{})
			}
			if err != nil {
				t.Fatalf("ordered %s: %v", action, err)
			}
			if fence.active.Load() || len(fence.slot) != 0 {
				t.Fatal("owner control fence was not released")
			}
		})
	}
}
