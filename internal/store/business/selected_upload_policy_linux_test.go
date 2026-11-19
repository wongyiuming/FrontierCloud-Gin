//go:build linux

package business_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestSelectedUploadOwnerPolicyFencesAppliedRevision(t *testing.T) {
	ctx := context.Background()
	db := database(t)
	nodes := db.Nodes()
	ownerID, masterID, relID := strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32)
	if _, err := nodes.InitializeIdentity(ctx, store.NodeIdentity{ID: ownerID, Role: "Standalone", PrivateKey: "fixture"}); err != nil {
		t.Fatal(err)
	}
	raw := db.(interface{ Database() *sql.DB }).Database()
	if _, err := raw.Exec("UPDATE node_identity SET `role`='Follower',endpoint='https://owner.test' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	pair := store.PairPackage{Nonce: strings.Repeat("4", 32), TokenHash: strings.Repeat("a", 64), ExpiresAt: now + 300}
	if _, err := nodes.IssuePair(ctx, pair, now, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	relation := store.Relationship{ID: relID, PeerID: masterID, Endpoint: "https://master.test", PublicKey: strings.Repeat("A", 43), Credential: "sealed-fixture", Direction: "upstream", Mode: "Relay", State: "pending", Protocol: 2, CreatedAt: now}
	if err := nodes.ConsumePair(ctx, pair, relation, now, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err := nodes.ActivateRelationship(ctx, relID, store.NodeAudit{}); err != nil {
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
	fence, err := ownerfence.Create(root, dir, ownerFixtureCodec{})
	if err != nil {
		t.Fatal(err)
	}
	coordinator := nodes.(interface {
		ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
		InitializeOwnerControlMarker(context.Context) error
		AcceptNativeDirectApplication(context.Context, string, int64, string) error
		AcceptNativeTransportApplication(context.Context, string, int64, string) error
	})
	if err = coordinator.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return fence.Acquire(c, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err = coordinator.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	if err = coordinator.AcceptNativeDirectApplication(ctx, relID, 7, "https://owner.test"); err != nil {
		t.Fatal(err)
	}
	policy := store.SelectedUploadPolicy{RelationshipID: relID, MasterID: masterID, OwnerID: ownerID, Transport: "Direct", Revision: 7, ResourceOrigin: "https://owner.test"}
	repo := nodes.(store.SelectedUploadOwnerPolicyRepository)
	for name, mutate := range map[string]func(*store.SelectedUploadPolicy){
		"owner":     func(v *store.SelectedUploadPolicy) { v.OwnerID = strings.Repeat("9", 32) },
		"master":    func(v *store.SelectedUploadPolicy) { v.MasterID = strings.Repeat("8", 32) },
		"revision":  func(v *store.SelectedUploadPolicy) { v.Revision++ },
		"origin":    func(v *store.SelectedUploadPolicy) { v.ResourceOrigin = "https://different.test" },
		"transport": func(v *store.SelectedUploadPolicy) { v.Transport, v.ResourceOrigin = "Relay", "" },
	} {
		t.Run(name, func(t *testing.T) {
			wrong := policy
			mutate(&wrong)
			if lease, err := repo.AcquireSelectedUploadOwnerPolicy(ctx, wrong); !errors.Is(err, store.ErrNodeState) || lease != nil {
				t.Fatal("mismatched owner policy accepted", err)
			}
		})
	}
	lease, err := repo.AcquireSelectedUploadOwnerPolicy(ctx, policy)
	if err != nil {
		t.Fatal(err)
	}
	changed := make(chan error, 1)
	writerCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	go func() { changed <- coordinator.AcceptNativeTransportApplication(writerCtx, relID, 8, "Relay") }()
	select {
	case err := <-changed:
		lease.Release()
		t.Fatal("policy changed while upload held owner lease", err)
	case <-time.After(120 * time.Millisecond):
	}
	if err = lease.Check(ctx); err != nil {
		lease.Release()
		t.Fatal("held owner lease lost", err)
	}
	lease.Release()
	if err = <-changed; err != nil {
		t.Fatal("policy writer did not resume after drain", err)
	}
	if old, err := repo.AcquireSelectedUploadOwnerPolicy(ctx, policy); !errors.Is(err, store.ErrNodeState) || old != nil {
		t.Fatal("old Direct revision accepted after Relay application", err)
	}
	policy.Transport, policy.Revision, policy.ResourceOrigin = "Relay", 8, ""
	current, err := repo.AcquireSelectedUploadOwnerPolicy(ctx, policy)
	if err != nil {
		t.Fatal("applied Relay rejected", err)
	}
	current.Release()
}
