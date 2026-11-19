//go:build linux

package business_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
)

type ownerFixtureCodec struct{}

type ownerBadLease struct{ released bool }

func (l *ownerBadLease) Check(context.Context) error             { return nil }
func (l *ownerBadLease) Binding(context.Context) (string, error) { return strings.Repeat("a", 64), nil }
func (l *ownerBadLease) Release()                                { l.released = true }

func (ownerFixtureCodec) SealOpaqueOwnerRecord(_ string, data []byte) (string, error) {
	return base64.StdEncoding.EncodeToString(data), nil
}

func TestFollowerHeartbeatRefreshesCapacityDuringOwnerStream(t *testing.T) {
	ctx := context.Background()
	db := database(t)
	repo := db.Nodes().(*business.Repository)
	localID := strings.Repeat("a", 32)
	peerID := strings.Repeat("b", 32)
	relID := strings.Repeat("c", 32)
	now := time.Now().Unix()
	if _, err := repo.InitializeIdentity(ctx, store.NodeIdentity{ID: localID, Role: "Standalone", PrivateKey: "encrypted-fixture", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	sqlDB := db.(interface{ Database() *sql.DB }).Database()
	if _, err := sqlDB.Exec("UPDATE node_identity SET `role`='Follower',endpoint='https://follower.test' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	pair := store.PairPackage{Nonce: strings.Repeat("d", 32), TokenHash: strings.Repeat("e", 64), ExpiresAt: now + 300}
	if _, err := repo.IssuePair(ctx, pair, now, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	relation := store.Relationship{ID: relID, PeerID: peerID, Endpoint: "https://master.test", PublicKey: strings.Repeat("A", 43), Credential: "encrypted-fixture", Direction: "upstream", Mode: "Relay", State: "pending", Protocol: 2, CreatedAt: now}
	if err := repo.ConsumePair(ctx, pair, relation, now, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err := repo.ActivateRelationship(ctx, relID, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	var applied store.ResourceConfiguration
	applied.Storage.Enabled = true
	applied.Storage.Allocation = 3 * store.GiB
	applied.Backup.Enabled = true
	if err := repo.AcceptFollowerConfiguration(ctx, relID, applied, 10*store.GiB); err != nil {
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
	if err := repo.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return fence.Acquire(c, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	stream, err := repo.AcquireOwnerControlShared(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Release()
	heartbeat, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := repo.AcceptFollowerConfiguration(heartbeat, relID, applied, 9*store.GiB); err != nil {
		t.Fatal("unchanged heartbeat blocked by active stream", err)
	}
	changed := applied
	changed.Storage.Allocation++
	limited, stop := context.WithTimeout(ctx, 150*time.Millisecond)
	defer stop()
	if err := repo.AcceptFollowerConfiguration(limited, relID, changed, 8*store.GiB); !errors.Is(err, store.ErrNodeState) || limited.Err() != context.DeadlineExceeded {
		t.Fatal("configuration change did not wait for stream to drain", err)
	}
	var allocation, free int64
	if err := sqlDB.QueryRow("SELECT allocated_bytes,physical_free_bytes FROM cluster_storage_members WHERE member_id=?", localID).Scan(&allocation, &free); err != nil {
		t.Fatal(err)
	}
	if allocation != applied.Storage.Allocation || free != 9*store.GiB {
		t.Fatalf("unexpected applied allocation and observed free space %d %d", allocation, free)
	}
	stream.Release()
	if err := repo.AcceptFollowerConfiguration(ctx, relID, changed, 8*store.GiB); err != nil {
		t.Fatal("configuration could not be applied after the stream released its fence", err)
	}
}

func TestOwnerControlFenceRejectsInvalidLeaseAndReleasesOnError(t *testing.T) {
	for _, typedNil := range []bool{true, false} {
		db := database(t)
		bad := &ownerBadLease{}
		config := db.Nodes().(interface {
			ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
		})
		if err := config.ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error) {
			if typedNil {
				var value *ownerBadLease
				return value, nil
			}
			return bad, errors.New("injected acquisition failure")
		}); err != nil {
			t.Fatal(err)
		}
		_, err := db.Nodes().InitializeIdentity(context.Background(), store.NodeIdentity{ID: strings.Repeat("a", 32), Role: "Standalone", PrivateKey: "fixture", CreatedAt: 123})
		if !errors.Is(err, store.ErrNodeState) || (!typedNil && !bad.released) {
			t.Fatal("invalid lease was accepted or leaked", err)
		}
	}
}
func (ownerFixtureCodec) OpenOpaqueOwnerRecord(_ string, data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

func TestOwnerControlFenceOrdersIdentityAndRelationshipWriters(t *testing.T) {
	ctx := context.Background()
	db := database(t)
	if _, err := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: strings.Repeat("1", 32), Role: "Standalone", PrivateKey: "fixture", CreatedAt: 123}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: "https://master.test", Allocation: store.GiB, PhysicalFree: 10 * store.GiB}, store.NodeAudit{}); err != nil {
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
	config := db.Nodes().(interface {
		ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
		InitializeOwnerControlMarker(context.Context) error
		AcquireOwnerControlShared(context.Context) (store.OwnerControlLease, error)
		VerifyOwnerControlBinding(context.Context, string) error
	})
	var lastExclusive store.OwnerControlLease
	if err := config.ConfigureOwnerControlFence(func(ctx context.Context, exclusive bool) (store.OwnerControlLease, error) {
		lease, err := fence.Acquire(ctx, exclusive)
		if exclusive && err == nil {
			lastExclusive = lease
		}
		return lease, err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("partial fence initialization allowed writer", err)
	}
	if lease, err := config.AcquireOwnerControlShared(ctx); !errors.Is(err, store.ErrNodeState) || lease != nil {
		t.Fatal("partial fence authorized owner handler", err)
	}
	if err := config.VerifyOwnerControlBinding(ctx, strings.Repeat("1", 64)); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("missing owner marker accepted", err)
	}
	if err := config.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal("marker initialization", err)
	}
	if err := config.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal("marker replay", err)
	}
	shared, err := config.AcquireOwnerControlShared(ctx)
	if err != nil {
		t.Fatal("matching marker rejected", err)
	}
	binding, err := shared.Binding(ctx)
	if err != nil || config.VerifyOwnerControlBinding(ctx, binding) != nil {
		t.Fatal("matching owner marker rejected", err)
	}
	if err = config.VerifyOwnerControlBinding(ctx, strings.Repeat("0", 64)); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("wrong owner binding accepted", err)
	}
	shared.Release()
	other := business.New(db.(interface{ Database() *sql.DB }).Database(), db.Backend())
	if err = other.VerifyOwnerControlBinding(ctx, binding); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("unconfigured repository observed marker as authorized", err)
	}
	if _, err := other.InitializeIdentity(ctx, store.NodeIdentity{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("unconfigured repository bypassed marker", err)
	}
	ran := false
	if err := other.WithOwnerControlExclusive(ctx, func(context.Context) error { ran = true; return nil }); !errors.Is(err, store.ErrNodeState) || ran {
		t.Fatal("unconfigured pre-volume callback ran", err)
	}
	wrongDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(wrongDir, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	wrongRoot, err := os.OpenRoot(wrongDir)
	if err != nil {
		t.Fatal(err)
	}
	defer wrongRoot.Close()
	wrong, err := ownerfence.Create(wrongRoot, wrongDir, ownerFixtureCodec{})
	if err != nil {
		t.Fatal(err)
	}
	if err := other.ConfigureOwnerControlFence(func(ctx context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return wrong.Acquire(ctx, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err := other.InitializeOwnerControlMarker(ctx); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("mismatched marker replaced", err)
	}
	if _, err := other.InitializeIdentity(ctx, store.NodeIdentity{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("mismatched fence accepted", err)
	}
	if lease, err := other.AcquireOwnerControlShared(ctx); !errors.Is(err, store.ErrNodeState) || lease != nil {
		t.Fatal("mismatched owner handler accepted", err)
	}
	reader, err := fence.Acquire(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	rel := store.Relationship{ID: strings.Repeat("2", 32), PeerID: strings.Repeat("3", 32), Endpoint: "https://owner.test", PublicKey: strings.Repeat("A", 43), Credential: "fixture", Direction: "downstream", Mode: "Relay", State: "pending", Protocol: 2, CreatedAt: 123}
	for name, operation := range map[string]func(context.Context) error{
		"identity initialization": func(c context.Context) error {
			_, e := db.Nodes().InitializeIdentity(c, store.NodeIdentity{})
			return e
		},
		"identity reset": func(c context.Context) error {
			_, e := db.Nodes().ResetIdentity(c, strings.Repeat("1", 32), "Master", store.NodeIdentity{ID: strings.Repeat("4", 32), Role: "Standalone", PrivateKey: "fixture"}, store.NodeAudit{})
			return e
		},
		"relationship activation": func(c context.Context) error {
			return db.Nodes().ActivateRelationship(c, rel.ID, store.NodeAudit{})
		},
	} {
		blocked, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
		err := operation(blocked)
		expired := errors.Is(blocked.Err(), context.DeadlineExceeded)
		cancel()
		if !expired || !errors.Is(err, store.ErrNodeState) {
			reader.Release()
			t.Fatalf("%s bypassed owner fence: %v", name, err)
		}
	}
	blocked, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
	err = db.Nodes().PrepareRelationship(blocked, rel, store.NodeAudit{})
	expired := errors.Is(blocked.Err(), context.DeadlineExceeded)
	cancel()
	reader.Release()
	if !expired || !errors.Is(err, store.ErrNodeState) {
		t.Fatal("relationship writer bypassed owner fence", err)
	}
	if err := db.Nodes().PrepareRelationship(ctx, rel, store.NodeAudit{}); err != nil {
		t.Fatal("writer did not resume", err)
	}
	coordinator := db.Nodes().(store.OwnerControlCoordinator)
	var expiredLeaseContext context.Context
	if err := coordinator.WithOwnerControlExclusive(ctx, func(held context.Context) error {
		expiredLeaseContext = held
		return db.Nodes().ActivateRelationship(held, rel.ID, store.NodeAudit{})
	}); err != nil {
		t.Fatal("nested writer failed under same exclusive lease", err)
	}
	if err := db.Nodes().SetRelationshipMode(expiredLeaseContext, rel.ID, "Direct", false, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("released exclusive lease context accepted", err)
	}
	if lease, err := config.AcquireOwnerControlShared(expiredLeaseContext); !errors.Is(err, store.ErrNodeState) || lease != nil {
		t.Fatal("released exclusive context borrowed owner fence", err)
	}
	var escaped store.OwnerControlLease
	if err := coordinator.WithOwnerControlExclusive(ctx, func(held context.Context) error {
		borrow, err := config.AcquireOwnerControlShared(held)
		if err != nil {
			return err
		}
		escaped = borrow
		if err := borrow.Check(held); err != nil {
			return err
		}
		if _, err := borrow.Binding(held); err != nil {
			return err
		}
		if foreign, err := other.AcquireOwnerControlShared(held); !errors.Is(err, store.ErrNodeState) || foreign != nil {
			return errors.New("foreign repository accepted exclusive context")
		}
		second, err := config.AcquireOwnerControlShared(held)
		if err != nil {
			return err
		}
		second.Release()
		if err := second.Check(held); !errors.Is(err, store.ErrNodeState) {
			return errors.New("released borrow remained valid")
		}
		blocked, cancel := context.WithTimeout(ctx, 120*time.Millisecond)
		defer cancel()
		competing, err := fence.Acquire(blocked, true)
		if err == nil {
			competing.Release()
			return errors.New("borrow release unlocked exclusive fence")
		}
		return borrow.Check(held)
	}); err != nil {
		t.Fatal("exclusive borrow", err)
	}
	if err := escaped.Check(ctx); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("borrow escaped exclusive callback", err)
	}
	if _, err := escaped.Binding(ctx); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("borrow binding survived exclusive callback", err)
	}
	escaped.Release()
	var panicBorrow store.OwnerControlLease
	func() {
		defer func() {
			if recover() == nil {
				t.Error("expected injected callback panic")
			}
		}()
		_ = coordinator.WithOwnerControlExclusive(ctx, func(held context.Context) error {
			var e error
			panicBorrow, e = config.AcquireOwnerControlShared(held)
			if e != nil {
				t.Fatal(e)
			}
			panic("injected callback panic")
		})
	}()
	if err := panicBorrow.Check(ctx); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("borrow survived callback panic", err)
	}
	if err := coordinator.WithOwnerControlExclusive(ctx, func(held context.Context) error {
		borrow, err := config.AcquireOwnerControlShared(held)
		if err != nil {
			return err
		}
		lastExclusive.Release()
		if err := borrow.Check(held); err == nil {
			return errors.New("borrow survived underlying exclusive lease release")
		}
		return nil
	}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("released parent was accepted", err)
	}
	if err := coordinator.WithOwnerControlExclusive(ctx, func(held context.Context) error {
		raw := db.(interface{ Database() *sql.DB }).Database()
		existing, err := config.AcquireOwnerControlShared(held)
		if err != nil {
			return err
		}
		var original string
		if err := raw.QueryRowContext(held, "SELECT fence_tag FROM sealed_tree_owner_fence WHERE singleton=1").Scan(&original); err != nil {
			return err
		}
		if _, err := raw.ExecContext(held, "UPDATE sealed_tree_owner_fence SET fence_tag=? WHERE singleton=1", strings.Repeat("f", 64)); err != nil {
			return err
		}
		defer raw.ExecContext(ctx, "UPDATE sealed_tree_owner_fence SET fence_tag=? WHERE singleton=1", original)
		if existing.Check(held) == nil {
			return errors.New("existing borrow accepted replaced marker")
		}
		if _, err := existing.Binding(held); err == nil {
			return errors.New("existing borrow returned binding after marker replacement")
		}
		if borrow, err := config.AcquireOwnerControlShared(held); !errors.Is(err, store.ErrNodeState) || borrow != nil {
			return errors.New("borrow accepted replaced marker")
		}
		return nil
	}); err != nil {
		t.Fatal("marker replacement", err)
	}
	if err := coordinator.WithOwnerControlExclusive(ctx, func(held context.Context) error {
		raw := db.(interface{ Database() *sql.DB }).Database()
		existing, err := config.AcquireOwnerControlShared(held)
		if err != nil {
			return err
		}
		var original string
		if err := raw.QueryRowContext(held, "SELECT fence_tag FROM sealed_tree_owner_fence WHERE singleton=1").Scan(&original); err != nil {
			return err
		}
		if _, err := raw.ExecContext(held, "DELETE FROM sealed_tree_owner_fence WHERE singleton=1"); err != nil {
			return err
		}
		defer raw.ExecContext(ctx, "INSERT INTO sealed_tree_owner_fence(singleton,fence_tag) VALUES(1,?)", original)
		if existing.Check(held) == nil {
			return errors.New("existing borrow accepted missing marker")
		}
		if borrow, err := config.AcquireOwnerControlShared(held); !errors.Is(err, store.ErrNodeState) || borrow != nil {
			return errors.New("borrow accepted missing marker")
		}
		return nil
	}); err != nil {
		t.Fatal("marker deletion", err)
	}
	var workers sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, 8)
	if err := coordinator.WithOwnerControlExclusive(ctx, func(held context.Context) error {
		borrow, err := config.AcquireOwnerControlShared(held)
		if err != nil {
			return err
		}
		var active sync.WaitGroup
		activeErrors := make(chan error, 8)
		for range 8 {
			active.Add(1)
			go func() {
				defer active.Done()
				activeErrors <- borrow.Check(held)
			}()
		}
		active.Wait()
		close(activeErrors)
		for e := range activeErrors {
			if e != nil {
				return e
			}
		}
		for range 8 {
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-start
				results <- borrow.Check(ctx)
			}()
		}
		return nil
	}); err != nil {
		t.Fatal("cross-goroutine borrow setup", err)
	}
	close(start)
	workers.Wait()
	close(results)
	for err := range results {
		if !errors.Is(err, store.ErrNodeState) {
			t.Fatal("borrow succeeded after callback ended", err)
		}
	}
}
