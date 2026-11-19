package node

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type selectedProbeControl struct {
	*localControl
	tamper        string
	probes        int
	replay        bool
	last          map[string]any
	masterElapsed time.Duration
	delay         time.Duration
	started       chan struct{}
	after         func()
	skew          int64
}

func (c *selectedProbeControl) Request(ctx context.Context, origin, route, method string, value any, relationship, credential string) (map[string]any, error) {
	if route != "/internal/v1/selected-admin-origin" {
		return c.localControl.Request(ctx, origin, route, method, value, relationship, credential)
	}
	c.probes++
	if c.started != nil {
		select {
		case c.started <- struct{}{}:
		default:
		}
	}
	if c.delay > 0 {
		timer := time.NewTimer(c.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if c.replay && c.last != nil {
		return c.last, nil
	}
	started := time.Now()
	defer func() { c.masterElapsed += time.Since(started) }()
	master := c.nodes[origin]
	if master == nil {
		return nil, errors.New("offline")
	}
	raw, err := protocol.Canonical(value)
	if err != nil {
		return nil, err
	}
	headers, err := protocol.AuthHeaders(credential, relationship, method, route, raw, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	rel, err := master.Authenticate(ctx, h, method, route, raw, false, false)
	if err != nil {
		return nil, err
	}
	request, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("bad request")
	}
	signed, err := master.SignSelectedAdminOrigin(ctx, rel, textField(request, "challenge"))
	if err != nil {
		return nil, err
	}
	if c.skew != 0 {
		signed.Payload["issued_at"] = signed.Payload["issued_at"].(int64) + c.skew
		signed.Payload["expires_at"] = signed.Payload["expires_at"].(int64) + c.skew
		row, e := master.repo.ReadIdentity(ctx)
		if e != nil {
			return nil, e
		}
		signed, err = master.identity.signed(row, signed.Payload)
		if err != nil {
			return nil, err
		}
	}
	if c.tamper != "" {
		signed.Payload[c.tamper] = "https://forged.test"
	}
	result := signed.wire()
	c.last = result
	if c.after != nil {
		c.after()
	}
	return result, nil
}

func TestSelectedAdminOriginFreshAuthenticatedChallenge(t *testing.T) {
	ctx := context.Background()
	base := &localControl{nodes: map[string]*Service{}}
	master, md := testNode(t, "Master", "https://master.test", base)
	follower, fd := testNode(t, "Follower", "https://owner.test", base)
	master.ConfigureVolumes(md.Pool(), &testVolume{}, recordingRoot(t))
	follower.ConfigureVolumes(fd.Pool(), &testVolume{}, recordingRoot(t))
	base.nodes["https://master.test"], base.nodes["https://owner.test"] = master, follower
	for _, invalid := range []string{"http://master.test", "https://master.test/path", "https://a@master.test", "https://master.test?x=1", "https://master.test:443"} {
		if master.ConfigureSelectedAdminOrigin(ctx, invalid) == nil {
			t.Fatalf("invalid origin accepted: %q", invalid)
		}
	}
	if follower.ConfigureSelectedAdminOrigin(ctx, "https://master.test") == nil {
		t.Fatal("Follower configured Master origin")
	}
	if err := master.ConfigureSelectedAdminOrigin(ctx, "https://master.test"); err != nil {
		t.Fatal(err)
	}
	pkg, err := follower.CreatePair(ctx, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	id, err := master.ImportPair(ctx, pkg, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	wire := &selectedProbeControl{localControl: base}
	follower.transport = wire
	for i := 0; i < 2; i++ {
		got, e := follower.FreshSelectedAdminOrigin(ctx, id)
		if e != nil || got != "https://master.test" {
			t.Fatal(got, e)
		}
	}
	if wire.probes != 2 {
		t.Fatal("origin was cached", wire.probes)
	}
	if _, e := follower.FreshSelectedAdminOrigin(ctx, strings.Repeat("f", 32)); e == nil {
		t.Fatal("other relationship accepted")
	}
	for _, skew := range []int64{-20, 20} {
		wire.skew = skew
		if _, e := follower.FreshSelectedAdminOrigin(ctx, id); e != nil {
			t.Fatalf("modest clock skew %d rejected: %v", skew, e)
		}
	}
	for _, skew := range []int64{-40, 40} {
		wire.skew = skew
		if _, e := follower.FreshSelectedAdminOrigin(ctx, id); e == nil {
			t.Fatalf("large clock skew %d accepted", skew)
		}
	}
	wire.skew = 0
	// Refresh a matching signed response before checking replay rejection.
	if _, e := follower.FreshSelectedAdminOrigin(ctx, id); e != nil {
		t.Fatal(e)
	}
	wire.replay = true
	if _, e := follower.FreshSelectedAdminOrigin(ctx, id); e == nil {
		t.Fatal("replayed proof with different nonce accepted")
	}
	wire.replay = false
	wire.tamper = "origin"
	if _, e := follower.FreshSelectedAdminOrigin(ctx, id); e == nil {
		t.Fatal("altered signed origin accepted")
	}
	wire.tamper = ""
	master.masterAdminOrigin = "https://new-master.test" // simulates configured Master restart at a new address
	if got, e := follower.FreshSelectedAdminOrigin(ctx, id); e != nil || got != "https://new-master.test" {
		t.Fatal("config change not reflected", got, e)
	}
	delete(base.nodes, "https://master.test")
	if _, e := follower.FreshSelectedAdminOrigin(ctx, id); e == nil {
		t.Fatal("unreachable Master served cached origin")
	}
	base.nodes["https://master.test"] = master
	wire.after = func() {
		if e := follower.repo.RevokeRelationship(ctx, id, true, store.NodeAudit{}); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := follower.FreshSelectedAdminOrigin(ctx, id); e == nil {
		t.Fatal("revoked relationship accepted after response")
	}
}
