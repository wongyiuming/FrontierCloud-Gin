package node

import (
	"context"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestNativeTransportHeartbeatRequiresBothReadinessAndRevision(t *testing.T) {
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
	if err = md.Nodes().SetRelationshipMode(ctx, id, "Direct", false, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	rel, err := master.repo.Relationship(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	routing := md.Nodes().(store.PublicRoutingRepository)
	if err = routing.ConfigurePublicOrigin("https://public.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = routing.ConfirmNativeTransport(ctx, rel.PeerID, "Relay", 0, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	tick := func() {
		t.Helper()
		var err error
		rel, err = master.repo.Relationship(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if err = master.Tick(ctx, rel); err != nil {
			t.Fatal(err)
		}
	}
	policy := func() store.NativeTransportPolicy {
		t.Helper()
		p, err := routing.NativeTransport(ctx, rel.PeerID)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	tick() // Capability discovery, with neither verifier configured.
	if p := policy(); p.AppliedTransport != "" || p.State != "blocked" || p.PeerApplicationStatus != "pending" {
		t.Fatal(p)
	}
	ready := func(context.Context, store.Relationship, string) error { return nil }
	master.ConfigureNativeTransportReadiness(ready)
	tick() // Follower cannot claim readiness without its own verifier.
	if p := policy(); p.AppliedTransport != "" || p.State != "blocked" || p.PeerApplicationStatus != "failed" {
		t.Fatal(p)
	}
	rel, _ = master.repo.Relationship(ctx, id)
	if rel.Status != "online" {
		t.Fatal("blocked policy damaged heartbeat", rel.Status)
	}
	follower.ConfigureNativeTransportReadiness(ready)
	tick()
	if p := policy(); p.State != "applied" || p.PeerApplicationStatus != "applied" || p.AppliedTransport != "Relay" || p.LegacyTransport != "Direct" || p.EffectiveTransport != "Direct" {
		t.Fatal(p)
	}
	rel, _ = master.repo.Relationship(ctx, id)
	if rel.Mode != "Direct" {
		t.Fatal("relationship mode changed", rel.Mode)
	}
	if _, err = routing.ConfirmNativeTransport(ctx, rel.PeerID, "Direct", 1, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	tick()
	if p := policy(); p.State != "blocked" || p.AppliedTransport != "Relay" {
		t.Fatal("Direct unexpectedly applied", p)
	}
	followerRel, err := follower.repo.Relationship(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	stale := follower.acceptNativeTransportRequest(ctx, followerRel, map[string]any{"transport": "Relay", "revision": int64(0)})
	if stale["state"] != "blocked" {
		t.Fatal(stale)
	}
}
