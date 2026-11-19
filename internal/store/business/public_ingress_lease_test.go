package business_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

func TestIngressLeaseChild(t *testing.T) {
	path := os.Getenv("FRONTIERCLOUD_TEST_INGRESS_DB")
	if path == "" {
		return
	}
	db, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := db.Nodes().(store.PublicRoutingRepository)
	if err := repo.ConfigurePublicOrigin("https://public.test"); err != nil {
		t.Fatal(err)
	}
	_, release, err := repo.AcquireCurrentIngress(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release.Release()
	fmt.Println("INGRESS_LEASE_HELD")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}

func TestIngressLeaseAcrossProcesses(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	repo, _ := routingFixture(t, db)
	if _, err := repo.PublicIngress(ctx); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestIngressLeaseChild$", "-test.timeout=15s")
	child.Env = append(os.Environ(), "FRONTIERCLOUD_TEST_INGRESS_DB="+path)
	child.Stderr = os.Stderr
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _, _ = child.Process.Wait() })
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == "INGRESS_LEASE_HELD" {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("child failed to hold ingress lease")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("child lease timeout")
	}
	blocked, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	_, err = repo.CommitMasterPublicIngress(blocked, "https://public.test", 1, store.NodeAudit{})
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cross-process selection bypassed lease", err)
	}
	if _, err := fmt.Fprintln(stdin, "release"); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	selected, err := repo.CommitMasterPublicIngress(ctx, "https://public.test", 1, store.NodeAudit{})
	if err != nil || selected.Generation != 2 {
		t.Fatal(selected, err)
	}
}

func TestIngressLeaseOrdersSelectionAndRelationshipChanges(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	first, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err := first.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	routing, _ := routingFixture(t, first)
	initial, err := routing.PublicIngress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	other := second.Nodes().(store.PublicRoutingRepository)
	if err := other.ConfigurePublicOrigin("https://public.test"); err != nil {
		t.Fatal(err)
	}
	current, release, err := routing.AcquireCurrentIngress(ctx)
	if err != nil || current != initial || release == nil {
		t.Fatal(current, err)
	}
	defer release.Release()

	// Each state-changing path must enter the same exclusive gate before it can
	// touch SQL, even through another Store/connection pool.
	checks := []func(context.Context) error{
		func(c context.Context) error {
			_, e := other.CommitMasterPublicIngress(c, "https://public.test", 1, store.NodeAudit{})
			return e
		},
		func(c context.Context) error {
			return second.Nodes().RevokeRelationship(c, routingRelation, false, store.NodeAudit{})
		},
		func(c context.Context) error {
			configuration := store.ResourceConfiguration{}
			configuration.Storage.Enabled, configuration.Storage.Allocation = true, 2*store.GiB
			return second.Pool().ConfigureMember(c, routingFollower, configuration, store.NodeAudit{})
		},
		func(c context.Context) error {
			return second.Pool().AdoptMasterLocal(c, 0, 0, nil)
		},
		func(c context.Context) error {
			_, e := second.Pool().(store.RetirementFenceRepository).BeginRetirement(c, routingRelation, routingFollower, store.NodeAudit{})
			return e
		},
		func(c context.Context) error {
			_, e := second.Pool().(store.RetirementFenceRepository).CompleteRetirement(c, routingRelation, routingFollower, store.NodeAudit{})
			return e
		},
		func(c context.Context) error {
			_, e := second.Nodes().ResetIdentity(c, routingMaster, "Master", store.NodeIdentity{ID: strings.Repeat("d", 32), Role: "Standalone", PrivateKey: "sealed"}, store.NodeAudit{})
			return e
		},
	}
	results := make(chan error, len(checks))
	for _, check := range checks {
		go func(check func(context.Context) error) {
			blocked, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
			defer cancel()
			results <- check(blocked)
		}(check)
	}
	for range checks {
		if e := <-results; !errors.Is(e, context.DeadlineExceeded) {
			t.Fatalf("state mutation bypassed lease: %v", e)
		}
	}
	if err := release.Commit(); err != nil {
		t.Fatal("admission commit failed", err)
	}
	if err := second.Pool().AdoptMasterLocal(ctx, 0, 0, nil); err != nil {
		t.Fatal("local adoption did not proceed after admission", err)
	}
	if err := release.Commit(); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("repeated commit succeeded", err)
	}
	release.Release() // the release is idempotent
	selected, err := other.CommitMasterPublicIngress(ctx, "https://public.test", 1, store.NodeAudit{Actor: "admin"})
	if err != nil || selected.NodeID != routingMaster || selected.Generation != 2 {
		t.Fatal(selected, err)
	}
	if _, err := other.CommitMasterPublicIngress(ctx, "https://public.test", 1, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("stale generation accepted", err)
	}
	selected, err = other.CommitMasterPublicIngress(ctx, "https://public.test", 2, store.NodeAudit{})
	if err != nil || selected.Generation != 3 {
		t.Fatal("selection did not advance", selected, err)
	}
	if err := second.Nodes().RevokeRelationship(ctx, routingRelation, false, store.NodeAudit{}); err != nil {
		t.Fatal("revocation did not proceed", err)
	}
	state, err := second.Nodes().Relationship(ctx, routingRelation)
	if err != nil || state.State != "revoked" {
		t.Fatal(state, err)
	}
}

func TestNativePolicyWaitsForIngressAdmissionAcrossStores(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	first, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err = first.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	routing, _ := routingFixture(t, first)
	if _, err = routing.ConfirmNativeTransport(ctx, routingMaster, "Direct", 0, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	second, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	other := second.Nodes().(store.PublicRoutingRepository)
	if err = other.ConfigurePublicOrigin("https://public.test"); err != nil {
		t.Fatal(err)
	}
	_, lease, err := routing.AcquireCurrentIngress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	type result struct {
		policy store.NativeTransportPolicy
		err    error
	}
	started, done := make(chan struct{}), make(chan result, 1)
	go func() {
		close(started)
		wait, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		policy, e := other.ConfirmNativeTransport(wait, routingMaster, "Relay", 1, store.NodeAudit{Actor: "admin"})
		done <- result{policy, e}
	}()
	<-started
	select {
	case value := <-done:
		t.Fatalf("policy changed before admission committed: %+v", value)
	case <-time.After(150 * time.Millisecond):
	}
	current, err := routing.NativeTransport(ctx, routingMaster)
	if err != nil || current.ConfiguredTransport != "Direct" || current.Revision != 1 || current.EffectiveTransport != "Local" {
		t.Fatal("held admission lost original policy", current, err)
	}
	if err = lease.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case value := <-done:
		if value.err != nil || value.policy.ConfiguredTransport != "Relay" || value.policy.Revision != 2 || value.policy.EffectiveTransport != "Local" {
			t.Fatal("policy did not commit after admission", value.policy, value.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("policy did not proceed after admission committed")
	}
}

func TestPeerIngressSelectionWaitsForExistingAdmission(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	first, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err = first.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	routing, _ := routingFixture(t, first)
	initial, err := routing.PublicIngress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Nodes().RecordHeartbeat(ctx, routingRelation, true, 1, map[string]any{"public_ingress_candidate_origin": "https://candidate.test", "capabilities": []string{"public-ingress-proxy-v1"}}, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	relation, err := first.Nodes().Relationship(ctx, routingRelation)
	if err != nil {
		t.Fatal(err)
	}
	evidence := store.PeerIngressEvidence{MemberID: relation.PeerID, RelationshipID: relation.ID, PublicKey: relation.PublicKey, ControlEndpoint: relation.Endpoint, PublicOrigin: "https://candidate.test", CredentialDigest: store.PeerCredentialDigest(relation.Credential), CreatedAt: relation.CreatedAt, LastHeartbeat: relation.LastHeartbeat}
	second, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	first.Nodes().(store.PeerIngressRepository).EnablePeerIngress()
	second.Nodes().(store.PeerIngressRepository).EnablePeerIngress()
	if err := second.Nodes().(store.PublicRoutingRepository).ConfigurePublicOrigin("https://public.test"); err != nil {
		t.Fatal(err)
	}
	_, lease, err := routing.AcquireCurrentIngress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	started, done := make(chan struct{}), make(chan error, 1)
	go func() {
		close(started)
		wait, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		_, err := second.Nodes().(store.PeerIngressRepository).CommitPeerPublicIngress(wait, evidence, initial.Generation, store.NodeAudit{})
		done <- err
	}()
	<-started
	select {
	case e := <-done:
		t.Fatal("selection bypassed admission", e)
	case <-time.After(150 * time.Millisecond):
	}
	if current, err := routing.PublicIngress(ctx); err != nil || current != initial {
		t.Fatal("ingress changed inside admission", current, err)
	}
	if err := lease.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("selection remained blocked")
	}
	if current, err := routing.PublicIngress(ctx); err != nil || current.NodeID != routingFollower || current.Generation != initial.Generation+1 {
		t.Fatal("selection missing after admission", current, err)
	}
}

func TestResourceOriginHeartbeatWaitsForIngressAdmission(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	first, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err = first.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	routing, _ := routingFixture(t, first)
	second, err := sqlitestore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_, lease, err := routing.AcquireCurrentIngress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	started, done := make(chan struct{}), make(chan error, 1)
	go func() {
		close(started)
		wait, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		done <- second.Nodes().RecordHeartbeat(wait, routingRelation, true, 1, map[string]any{"native_resource_origin": "https://changed.test"}, time.Now().Unix())
	}()
	<-started
	select {
	case e := <-done:
		t.Fatal("origin observation bypassed admission", e)
	case <-time.After(150 * time.Millisecond):
	}
	if err := lease.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-done:
		if e != nil {
			t.Fatal("heartbeat did not proceed", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("heartbeat remained blocked")
	}
	relation, err := second.Nodes().Relationship(ctx, routingRelation)
	if err != nil || relation.Summary["native_resource_origin"] != "https://changed.test" {
		t.Fatal("heartbeat update lost", relation.Summary, err)
	}
}

func TestIngressInitializationRequiresPublicOriginAndRejectsDrift(t *testing.T) {
	ctx := context.Background()
	db := database(t)
	routing, raw := routingFixture(t, db)
	if _, err := raw.Exec("DELETE FROM public_ingress_config"); err != nil {
		t.Fatal(err)
	}
	// A fresh repository has no configured origin. The control Endpoint alone
	// must never create public routing state.
	other := business.New(raw, db.Backend())
	if _, err := other.PublicIngress(ctx); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("initialized from control endpoint", err)
	}
	if _, release, err := other.AcquireCurrentIngress(ctx); err == nil || release != nil {
		t.Fatal("unconfigured lease admitted", err)
	}
	for _, invalid := range []string{"http://public.test", "https://public.test/path", "https://public.test:8443", "https://localhost", "https://public.test@other.test"} {
		if err := other.ConfigurePublicOrigin(invalid); !errors.Is(err, store.ErrNodeState) {
			t.Fatal("invalid public origin", invalid, err)
		}
	}
	ingress, err := routing.PublicIngress(ctx)
	if err != nil || ingress.PublicOrigin != "https://public.test" {
		t.Fatal(ingress, err)
	}
	if err := other.ConfigurePublicOrigin("https://changed.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := other.PublicIngress(ctx); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("origin drift accepted", err)
	}
	if _, release, err := other.AcquireCurrentIngress(ctx); err == nil || release != nil {
		t.Fatal("origin drift lease admitted", err)
	}
	selected, err := other.CommitMasterPublicIngress(ctx, "https://changed.test", ingress.Generation, store.NodeAudit{})
	if err != nil || selected.NodeID != routingMaster || selected.Generation != ingress.Generation+1 {
		t.Fatal(selected, err)
	}
	if _, err := routing.PublicIngress(ctx); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("old runtime origin accepted", err)
	}
}

func TestIngressSelectionCASAndUnsupportedBackend(t *testing.T) {
	ctx := context.Background()
	db := database(t)
	repo, raw := routingFixture(t, db)
	if _, err := repo.PublicIngress(ctx); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, err := repo.CommitMasterPublicIngress(ctx, "https://public.test", 1, store.NodeAudit{})
			results <- err
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else if !errors.Is(err, store.ErrNodeState) {
			t.Fatal(err)
		}
	}
	current, err := repo.PublicIngress(ctx)
	if err != nil || wins != 1 || current.Generation != 2 {
		t.Fatal(wins, current, err)
	}
	// An unknown backend cannot silently admit a shared lease.
	unsupported := business.New(raw, "unsupported")
	if err := unsupported.ConfigurePublicOrigin("https://public.test"); err != nil {
		t.Fatal(err)
	}
	if _, release, err := unsupported.AcquireCurrentIngress(ctx); !errors.Is(err, store.ErrNodeState) || release != nil {
		t.Fatal("unsupported backend admitted shared lease", err)
	}
	if db.Backend() == "sqlite" {
		if _, err := raw.Exec("CREATE TRIGGER ingress_selection_audit_fault BEFORE INSERT ON node_audit BEGIN SELECT RAISE(ABORT,'audit unavailable'); END"); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.CommitMasterPublicIngress(ctx, "https://public.test", 2, store.NodeAudit{}); err == nil {
			t.Fatal("unaudited selection accepted")
		}
		still, err := repo.PublicIngress(ctx)
		if err != nil || still != current {
			t.Fatal("audit failure changed selection", still, err)
		}
	}
	if _, err := raw.Exec("UPDATE public_ingress_config SET node_id=? WHERE singleton=1", routingFollower); err != nil {
		t.Fatal(err)
	}
	if _, release, err := repo.AcquireCurrentIngress(ctx); !errors.Is(err, store.ErrNodeState) || release != nil {
		t.Fatal("peer ingress admitted without eligibility protocol", err)
	}
}
