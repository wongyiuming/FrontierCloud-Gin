package node

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/logarchive"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestLogGrantBindsMasterNodeOriginAndExpiryWithoutKey(t *testing.T) {
	ctx := context.Background()
	transport := &localControl{nodes: map[string]*Service{}}
	master, _ := testNode(t, "Master", "https://log-master.test", transport)
	peer, _ := testNode(t, "Follower", "https://log-peer.test", transport)
	transport.nodes["https://log-master.test"], transport.nodes["https://log-peer.test"] = master, peer
	pkg, e := peer.CreatePair(ctx, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	id, e := master.ImportPair(ctx, pkg, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	rel, e := master.repo.Relationship(ctx, id)
	if e != nil {
		t.Fatal(e)
	}
	target := logarchive.Target{MemberID: rel.PeerID, RelationshipID: id, Origin: "https://logs.test"}
	ref := logarchive.Reference{ID: strings.Repeat("a", 32), SHA256: strings.Repeat("b", 64), Bytes: 80}
	grant, e := master.LogReadGrant(ctx, target, ref, "https://admin.test")
	if e != nil {
		t.Fatal(e)
	}
	// Exercise actual JSON number decoding rather than a same-process map.
	raw, _ := json.Marshal(grant)
	var wire Envelope
	decode := func(out *Envelope) error {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		return decoder.Decode(out)
	}
	if e = decode(&wire); e != nil {
		t.Fatal(e)
	}
	got, read, e := peer.VerifyLogReadGrant(ctx, wire, "https://admin.test")
	if e != nil || got != master.identity.ID || read != ref {
		t.Fatal("valid grant refused", e)
	}
	if strings.Contains(string(raw), "wrapped") || strings.Contains(string(raw), "key") {
		t.Fatal("read grant disclosed a data key")
	}
	if _, _, e = peer.VerifyLogReadGrant(ctx, wire, "https://other.test"); e == nil {
		t.Fatal("cross-origin grant accepted")
	}
	for _, field := range []string{"node", "relationship", "master", "id", "sha256"} {
		var changed Envelope
		decode(&changed)
		changed.Payload[field] = strings.Repeat("c", 32)
		if _, _, e = peer.VerifyLogReadGrant(ctx, changed, "https://admin.test"); e == nil {
			t.Fatal("tampered grant accepted", field)
		}
	}
	row, _ := master.repo.ReadIdentity(ctx)
	for _, interval := range [][2]int64{{-301, -1}, {0, 301}, {30, 100}} {
		var changed Envelope
		decode(&changed)
		now := time.Now().Unix()
		changed.Payload["issued"] = now + interval[0]
		changed.Payload["expires"] = now + interval[1]
		changed, e = master.identity.signed(row, changed.Payload)
		if e != nil {
			t.Fatal(e)
		}
		if _, _, e = peer.VerifyLogReadGrant(ctx, changed, "https://admin.test"); e == nil {
			t.Fatal("invalid grant lifetime accepted", interval)
		}
	}
}
