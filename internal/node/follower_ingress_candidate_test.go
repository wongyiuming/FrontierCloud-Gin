package node

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestFollowerIngressCandidateIdentityIsSeparateAndDoesNotSelect(t *testing.T) {
	ctx := context.Background()
	transport := &localControl{nodes: map[string]*Service{}}
	master, md := testNode(t, "Master", "https://control-master.test", transport)
	follower, fd := testNode(t, "Follower", "https://control-peer.test", transport)
	master.ConfigureVolumes(md.Pool(), &testVolume{}, recordingRoot(t))
	follower.ConfigureVolumes(fd.Pool(), &testVolume{}, recordingRoot(t))
	transport.nodes["https://control-master.test"], transport.nodes["https://control-peer.test"] = master, follower
	if err := master.ConfigureFollowerIngressCandidate("https://public-peer.test"); err == nil {
		t.Fatal("Master advertised a Follower candidate")
	}
	if err := follower.ConfigureFollowerResourceOrigin("https://resource-peer.test"); err != nil {
		t.Fatal(err)
	}
	if err := follower.ConfigureFollowerIngressCandidate("https://public-peer.test/path"); err == nil {
		t.Fatal("invalid candidate accepted")
	}
	pkg, err := follower.CreatePair(ctx, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	id, err := master.ImportPair(ctx, pkg, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	routing := md.Nodes().(store.PublicRoutingRepository)
	if err = routing.ConfigurePublicOrigin("https://public-master.test"); err != nil {
		t.Fatal(err)
	}
	initial, err := routing.PublicIngress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tick := func() {
		t.Helper()
		relation, e := master.repo.Relationship(ctx, id)
		if e != nil {
			t.Fatal(e)
		}
		if e = master.Tick(ctx, relation); e != nil {
			t.Fatal(e)
		}
	}
	tick()
	if _, err := master.ObservedFollowerIngressCandidate(ctx, id); !errors.Is(err, ErrIngressEndpointUnprepared) {
		t.Fatal("resource address inferred as ingress")
	}
	if err = follower.ConfigureFollowerIngressCandidate("https://public-peer.test"); err != nil {
		t.Fatal(err)
	}
	tick()
	master.transport = &resourceOriginControl{localControl: transport, resource: follower}
	if origin, err := master.VerifyFollowerIngressIdentity(ctx, id); err != nil || origin != "https://public-peer.test" {
		t.Fatal("candidate identity", origin, err)
	}
	relation, err := master.repo.Relationship(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	peerIngress := store.PublicIngress{NodeID: relation.PeerID, PublicOrigin: "https://public-peer.test", Generation: 2}
	if err := master.MasterRelayObservationValid(ctx, peerIngress); err != nil {
		t.Fatal("valid Relay observation", err)
	}
	peerIngress.PublicOrigin = "https://wrong.test"
	if err := master.MasterRelayObservationValid(ctx, peerIngress); err == nil {
		t.Fatal("changed Relay origin accepted")
	}
	if current, err := routing.PublicIngress(ctx); err != nil || current != initial {
		t.Fatal("candidate verification selected ingress", current, err)
	}
	master.transport = &resourceOriginControl{localControl: transport, resource: master}
	if _, err := master.VerifyFollowerIngressIdentity(ctx, id); err == nil {
		t.Fatal("wrong peer identity accepted")
	}
	if _, err := md.Database().Exec("UPDATE node_relationships SET last_heartbeat=? WHERE relationship_id=?", time.Now().Unix()-121, id); err != nil {
		t.Fatal(err)
	}
	if _, err := master.ObservedFollowerIngressCandidate(ctx, id); err == nil {
		t.Fatal("stale candidate accepted")
	}
}
