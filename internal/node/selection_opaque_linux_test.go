//go:build linux

package node

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Real paired node signatures/HMAC, encrypted tree, SQLite and an actual
// local synthetic file read and actual node-vault-backed owner fence. The
// transport to the owner is a fixture, not full deployment readiness proof.
func TestOpaqueTreeSelectionRequiresV5OwnerRead(t *testing.T) {
	ctx := context.Background()
	transport := &localControl{nodes: map[string]*Service{}}
	master, md := testNode(t, "Master", "https://node.test", transport)
	follower, fd := testNode(t, "Follower", "https://follower.test", transport)
	master.ConfigureVolumes(md.Pool(), &testVolume{}, recordingRoot(t))
	follower.ConfigureVolumes(fd.Pool(), &testVolume{}, recordingRoot(t))
	follower.ConfigurePlainReadProbe(func(context.Context) error { return nil })
	transport.nodes["https://node.test"], transport.nodes["https://follower.test"] = master, follower
	if err := follower.ConfigureFollowerIngressCandidate("https://candidate.test"); err != nil {
		t.Fatal(err)
	}
	pair, err := follower.CreatePair(ctx, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	id, err := master.ImportPair(ctx, pair, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if err := master.ConfigurePublicOrigin("https://public.test"); err != nil {
		t.Fatal(err)
	}
	routing := md.Nodes().(store.PublicRoutingRepository)
	before, err := routing.PublicIngress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	relation, err := master.repo.Relationship(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := master.Tick(ctx, relation); err != nil {
		t.Fatal(err)
	}
	ownerDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(ownerDir, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	ownerRoot, err := os.OpenRoot(ownerDir)
	if err != nil {
		t.Fatal(err)
	}
	defer ownerRoot.Close()
	ownerFence, err := ownerfence.Create(ownerRoot, ownerDir, master.identity)
	if err != nil {
		t.Fatal(err)
	}
	ownerConfig := md.Nodes().(interface {
		ConfigureOwnerControlFence(func(context.Context, bool) (store.OwnerControlLease, error)) error
		InitializeOwnerControlMarker(context.Context) error
		AcquireOwnerControlShared(context.Context) (store.OwnerControlLease, error)
	})
	if err := ownerConfig.ConfigureOwnerControlFence(func(c context.Context, exclusive bool) (store.OwnerControlLease, error) {
		return ownerFence.Acquire(c, exclusive)
	}); err != nil {
		t.Fatal(err)
	}
	if err := ownerConfig.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	server, roots := privateCA(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != IngressCandidateEdgePath {
			http.NotFound(w, r)
			return
		}
		body, e := io.ReadAll(io.LimitReader(r.Body, 1025))
		if e != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		signed, e := master.VerifyCandidateEdge(r.Context(), r.Header, body)
		if e != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(signed)
	}))
	follower.transport = testTransport(t, server, roots)
	probeControl := &candidateMasterControl{resourceOriginControl: &resourceOriginControl{localControl: transport, resource: follower}, follower: follower}
	master.transport = probeControl
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
	if err := master.ConfigureIngressSelectionReadiness(ctx, func(c context.Context) (IngressPrerequisiteLease, error) {
		return AcquireCatalogPrerequisite(c, ownerConfig.AcquireOwnerControlShared, tree)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := master.SelectPublicIngress(ctx, relation.PeerID, before.Generation, store.NodeAudit{}); err == nil {
		t.Fatal("composite without opaque tree gate selected peer")
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	probeControl.afterProbe = func() { close(entered); <-resume }
	racing := make(chan error, 1)
	go func() {
		_, e := master.SelectPublicIngress(ctx, relation.PeerID, before.Generation, store.NodeAudit{})
		racing <- e
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("selection preflight did not start")
	}
	if err := master.ConfigureOpaqueIngressSelectionTree(ctx, tree); err != nil {
		t.Fatal(err)
	}
	close(resume)
	select {
	case err := <-racing:
		if err == nil {
			t.Fatal("v4 selection crossed opaque gate installation")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("racing selection deadlocked")
	}
	probeControl.afterProbe = nil
	if current, err := routing.PublicIngress(ctx); err != nil || current != before {
		t.Fatal("racing gate changed ingress", err)
	}
	if err := master.ConfigureOpaqueIngressSelectionTree(ctx, tree); err == nil {
		t.Fatal("opaque tree gate reconfigured")
	}
	if origin, err := master.CheckPublicIngressCandidate(ctx, relation.PeerID); err == nil || origin != "" {
		t.Fatal("candidate check accepted missing v5 owner proof", origin, err)
	}
	if _, err := master.SelectPublicIngress(ctx, relation.PeerID, before.Generation, store.NodeAudit{}); err == nil {
		t.Fatal("missing v5 owner probe selected")
	}
	fixture := filepath.Join(t.TempDir(), "synthetic-opaque")
	if err := os.WriteFile(fixture, []byte("v5 fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	var broken, checkProbeLockOrder atomic.Bool
	var reads atomic.Int32
	enableOpaqueProbeFixture(follower)
	follower.ConfigureOpaqueReadProbe(func(probeCtx context.Context) error {
		reads.Add(1)
		if broken.Load() {
			return errors.New("fixture read unavailable")
		}
		if checkProbeLockOrder.Load() {
			c, cancel := context.WithTimeout(probeCtx, time.Second)
			defer cancel()
			lease, err := ownerFence.Acquire(c, true)
			if err != nil {
				return errors.New("candidate network probe held the Master Owner lease")
			}
			lease.Release()
		}
		data, e := os.ReadFile(fixture)
		if e != nil || string(data) != "v5 fixture" {
			return errors.New("fixture read failed")
		}
		return nil
	})
	broken.Store(true)
	if origin, err := master.CheckPublicIngressCandidate(ctx, relation.PeerID); err == nil || origin != "" {
		t.Fatal("candidate check accepted failed v5 owner read", origin, err)
	}
	if _, err := master.SelectPublicIngress(ctx, relation.PeerID, before.Generation, store.NodeAudit{}); err == nil {
		t.Fatal("failed v5 owner read selected")
	}
	if current, err := routing.PublicIngress(ctx); err != nil || current != before {
		t.Fatal("failed v5 probe changed ingress", err)
	}
	broken.Store(false)
	checkProbeLockOrder.Store(true)
	beforeCheck := reads.Load()
	if origin, err := master.CheckPublicIngressCandidate(ctx, relation.PeerID); err != nil || origin != "https://candidate.test" || reads.Load() != beforeCheck+1 {
		t.Fatal("candidate check did not verify a current v5 owner read", origin, err)
	}
	checkProbeLockOrder.Store(false)
	if current, err := routing.PublicIngress(ctx); err != nil || current != before {
		t.Fatal("successful candidate check changed ingress", err)
	}
	broken.Store(true)
	if _, err := master.SelectPublicIngress(ctx, relation.PeerID, before.Generation, store.NodeAudit{}); err == nil {
		t.Fatal("selection reused the earlier successful candidate check")
	}
	broken.Store(false)
	selected, err := master.SelectPublicIngress(ctx, relation.PeerID, before.Generation, store.NodeAudit{})
	if err != nil || selected.NodeID != relation.PeerID || selected.Generation != before.Generation+1 || reads.Load() < 2 {
		t.Fatal("valid v5 owner proof not selected", err)
	}
	restarted := NewService(master.repo, master.identity, master.transport)
	restarted.ConfigureVolumes(md.Pool(), &testVolume{}, recordingRoot(t))
	if err := restarted.ConfigureIngressSelectionReadiness(ctx, func(c context.Context) (IngressPrerequisiteLease, error) {
		return AcquireCatalogPrerequisite(c, ownerConfig.AcquireOwnerControlShared, tree)
	}); err != nil {
		t.Fatal(err)
	}
	observed, err := master.repo.Relationship(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := md.Nodes().RecordHeartbeat(ctx, id, true, 1, observed.Summary, time.Now().Unix()-121); err != nil {
		t.Fatal(err)
	}
	if err := restarted.ConfigureOpaqueIngressSelectionTree(ctx, tree); err == nil {
		t.Fatal("startup accepted a stale selected peer")
	}
	broken.Store(true)
	if err := restarted.RevalidateSelectedOpaqueIngress(ctx, tree, selected); err == nil || restarted.OpaqueIngressSelectionTreeMatches(tree) {
		t.Fatal("recovery accepted selected peer without v5 read", err)
	}
	if current, err := routing.PublicIngress(ctx); err != nil || current != selected {
		t.Fatal("failed revalidation changed selected ingress", err)
	}
	broken.Store(false)
	stale := selected
	stale.Generation--
	if err := restarted.RevalidateSelectedOpaqueIngress(ctx, tree, stale); err == nil || restarted.OpaqueIngressSelectionTreeMatches(tree) {
		t.Fatal("recovery accepted a different generation", err)
	}
	if err := restarted.RevalidateSelectedOpaqueIngress(ctx, tree, selected); err != nil || !restarted.OpaqueIngressSelectionTreeMatches(tree) {
		t.Fatal("recovered peer did not pass v5 revalidation", err)
	}
	revalidated, lease, err := restarted.AcquireCurrentIngress(ctx)
	if err != nil || lease == nil {
		t.Fatal("revalidated ingress did not admit traffic", err)
	}
	err = lease.Commit()
	lease.Release()
	if err != nil || revalidated != selected {
		t.Fatal("recovery admitted a different ingress", revalidated, err)
	}
	if current, err := routing.PublicIngress(ctx); err != nil || current != selected {
		t.Fatal("revalidation changed selected ingress", err)
	}
	if err := restarted.ConfigurePublicOrigin("https://public.test"); err != nil {
		t.Fatal(err)
	}
	broken.Store(true) // Recovery may not depend on the unavailable peer.
	if err := restarted.RevalidateSelectedOpaqueIngress(ctx, tree, selected); err == nil {
		t.Fatal("recovery reused its installed tree as a fresh peer proof")
	}
	identity, err := restarted.IdentityState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.RecoverMasterIngress(ctx, tree, relation.PeerID, selected.Generation, store.NodeAudit{}); err == nil {
		t.Fatal("recovery selected a peer")
	}
	if _, err := restarted.RecoverMasterIngress(ctx, tree, identity.ID, selected.Generation+1, store.NodeAudit{}); err == nil {
		t.Fatal("recovery bypassed generation CAS")
	}
	recovered, err := restarted.RecoverMasterIngress(ctx, tree, identity.ID, selected.Generation, store.NodeAudit{Actor: "recovery-test"})
	if err != nil || recovered.NodeID != identity.ID || recovered.Generation != selected.Generation+1 || recovered.PublicOrigin != "https://public.test" {
		t.Fatal("Master-only fenced recovery", recovered, err)
	}
}
