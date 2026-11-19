package node

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestPeerIngressObservationRequiresAuthenticatedHeartbeatAndIsMonotonic(t *testing.T) {
	ctx := context.Background()
	transport := &localControl{nodes: map[string]*Service{}}
	master, md := testNode(t, "Master", "https://master.test", transport)
	follower, fd := testNode(t, "Follower", "https://follower.test", transport)
	master.ConfigureVolumes(md.Pool(), &testVolume{}, recordingRoot(t))
	follower.ConfigureVolumes(fd.Pool(), &testVolume{}, recordingRoot(t))
	transport.nodes["https://master.test"], transport.nodes["https://follower.test"] = master, follower
	pkg, err := follower.CreatePair(ctx, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	id, err := master.ImportPair(ctx, pkg, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	mr, err := master.repo.Relationship(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := follower.IdentityState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := follower.CurrentPeerIngress(ctx); !errors.Is(err, store.ErrNodeState) {
		t.Fatalf("activated without heartbeat: %v", err)
	}
	message := func(owner, origin string, generation int64) map[string]any {
		return map[string]any{"public_ingress": map[string]any{"node_id": owner, "public_origin": origin, "generation": generation}}
	}
	if _, err = master.Call(ctx, mr, "/internal/v1/heartbeat", message(peer.ID, "https://entry.test", 4)); err != nil {
		t.Fatal(err)
	}
	want := store.PublicIngress{NodeID: peer.ID, PublicOrigin: "https://entry.test", Generation: 4}
	check := func() {
		t.Helper()
		got, rel, err := follower.CurrentPeerIngress(ctx)
		if err != nil || got != want || rel.ID != id {
			t.Fatalf("observation=%+v relation=%s err=%v", got, rel.ID, err)
		}
	}
	check()
	follower.peerIngressMu.Lock()
	follower.peerIngress.observedAt = time.Now().Add(-peerIngressObservationTTL)
	follower.peerIngressMu.Unlock()
	if _, _, err = follower.ObservedPublicIngress(ctx); !errors.Is(err, store.ErrNodeState) {
		t.Fatalf("expired origin observation admitted: %v", err)
	}
	if _, err = master.Call(ctx, mr, "/internal/v1/heartbeat", message(peer.ID, "https://entry.test", 4)); err != nil {
		t.Fatal(err)
	}
	check()
	for _, input := range []map[string]any{
		message(peer.ID, "https://old.test", 3),
		message(peer.ID, "https://conflict.test", 4),
		message(peer.ID, "http://insecure.test", 5),
	} {
		if _, err = master.Call(ctx, mr, "/internal/v1/heartbeat", input); err != nil {
			t.Fatalf("invalid observation disrupted heartbeat: %v", err)
		}
		check()
	}
	forged := protocol.Encode([]byte(strings.Repeat("x", 48)))
	if _, err = transport.Request(ctx, mr.Endpoint, "/internal/v1/heartbeat", "POST", message(peer.ID, "https://forged.test", 7), mr.ID, forged); err == nil {
		t.Fatal("forged heartbeat accepted")
	}
	check()
	// The process-local observation must not survive a service restart.
	restarted := NewService(fd.Nodes(), follower.identity, transport)
	if _, _, err = restarted.CurrentPeerIngress(ctx); !errors.Is(err, store.ErrNodeState) {
		t.Fatalf("restart retained observation: %v", err)
	}
	if _, err = master.Call(ctx, mr, "/internal/v1/heartbeat", message(strings.Repeat("f", 32), "https://other.test", 5)); err != nil {
		t.Fatal(err)
	}
	if _, _, err = follower.CurrentPeerIngress(ctx); !errors.Is(err, store.ErrNodeState) {
		t.Fatalf("old peer remained active: %v", err)
	}
	observed, _, err := follower.ObservedPublicIngress(ctx)
	if err != nil || observed.NodeID != strings.Repeat("f", 32) || observed.Generation != 5 {
		t.Fatalf("resource node failed to observe current origin: %+v %v", observed, err)
	}
	if _, err = master.Call(ctx, mr, "/internal/v1/heartbeat", message(peer.ID, "https://entry.test", 4)); err != nil {
		t.Fatal(err)
	}
	if _, _, err = follower.CurrentPeerIngress(ctx); !errors.Is(err, store.ErrNodeState) {
		t.Fatalf("stale observation reactivated peer: %v", err)
	}
}

func TestPeerIngressObservationIsBoundToCurrentPair(t *testing.T) {
	ctx := context.Background()
	peer, repo := ingressTestService(t, "Follower")
	relA := store.Relationship{ID: strings.Repeat("a", 32), PeerID: strings.Repeat("b", 32), Endpoint: "https://first.test", Direction: "upstream", State: "active", Protocol: protocol.Version}
	repo.relation = relA
	wire := func(generation int64) map[string]any {
		return map[string]any{"node_id": repo.row.ID, "public_origin": "https://entry.test", "generation": generation}
	}
	peer.observePeerIngress(ctx, relA, wire(9))
	if _, _, err := peer.CurrentPeerIngress(ctx); err != nil {
		t.Fatal(err)
	}
	// Revocation immediately invalidates the observation, without requiring a
	// notification through the revoked upstream relationship.
	repo.relation.State = "revoked"
	if _, _, err := peer.CurrentPeerIngress(ctx); !errors.Is(err, store.ErrNodeState) {
		t.Fatalf("revoked relation still admitted: %v", err)
	}
	relB := store.Relationship{ID: strings.Repeat("c", 32), PeerID: relA.PeerID, Endpoint: relA.Endpoint, Direction: "upstream", State: "active", Protocol: protocol.Version}
	repo.relation = relB
	if _, _, err := peer.CurrentPeerIngress(ctx); !errors.Is(err, store.ErrNodeState) {
		t.Fatalf("new relation inherited old observation: %v", err)
	}
	peer.observePeerIngress(ctx, relA, wire(10))
	if _, _, err := peer.CurrentPeerIngress(ctx); !errors.Is(err, store.ErrNodeState) {
		t.Fatalf("old pair advanced observation: %v", err)
	}
	peer.observePeerIngress(ctx, relB, wire(1))
	if _, _, err := peer.CurrentPeerIngress(ctx); !errors.Is(err, store.ErrNodeState) {
		t.Fatalf("new relationship rolled back Master ingress generation: %v", err)
	}
	peer.observePeerIngress(ctx, relB, wire(10))
	ingress, relation, err := peer.CurrentPeerIngress(ctx)
	if err != nil || ingress.Generation != 10 || relation.ID != relB.ID {
		t.Fatalf("new pair rejected: %+v %+v %v", ingress, relation, err)
	}
}
