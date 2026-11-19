package node

import (
	"context"
	"errors"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestLegacyModeRejectsUnacknowledgedChange(t *testing.T) {
	ctx := context.Background()
	transport := &localControl{nodes: map[string]*Service{}}
	master, db := testNode(t, "Master", "https://master.test", transport)
	follower, followerDB := testNode(t, "Follower", "https://follower.test", transport)
	master.ConfigureVolumes(db.Pool(), &testVolume{}, recordingRoot(t))
	follower.ConfigureVolumes(followerDB.Pool(), &testVolume{}, recordingRoot(t))
	transport.nodes["https://master.test"] = master
	transport.nodes["https://follower.test"] = follower
	packageValue, err := follower.CreatePair(ctx, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	id, err := master.ImportPair(ctx, packageValue, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	before, err := db.Nodes().Relationship(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	routing := db.Nodes().(store.PublicRoutingRepository)
	if err := routing.ConfigurePublicOrigin("https://master.test"); err != nil {
		t.Fatal(err)
	}
	policy, err := routing.ConfirmNativeTransport(ctx, before.PeerID, before.Mode, 0, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if err := master.SetMode(ctx, id, before.Mode, store.NodeAudit{}); err != nil {
		t.Fatal("current mode is an idempotent compatibility request", err)
	}
	other := "Direct"
	if before.Mode == other {
		other = "Relay"
	}
	if err := master.SetMode(ctx, id, other, store.NodeAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("unacknowledged mode change accepted", err)
	}
	after, err := db.Nodes().Relationship(ctx, id)
	if err != nil || after.Mode != before.Mode || after.State != before.State || after.Status != before.Status || after.LastHeartbeat != before.LastHeartbeat || after.Failures != before.Failures {
		t.Fatal("mode rejection changed routing or connectivity", before, after, err)
	}
	currentPolicy, err := routing.NativeTransport(ctx, before.PeerID)
	if err != nil || currentPolicy != policy {
		t.Fatal("mode rejection changed configured policy", policy, currentPolicy, err)
	}
	peer, err := followerDB.Nodes().Relationship(ctx, id)
	if err != nil || peer.Mode != before.Mode || peer.State != "active" {
		t.Fatal("mode rejection changed the peer", peer, err)
	}
}
