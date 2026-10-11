package node

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type certificateWire struct{ localControl }

func (l *certificateWire) Request(ctx context.Context, origin, route, method string, value any, relationship, credential string) (map[string]any, error) {
	if route != "/internal/v1/certificate" {
		return l.localControl.Request(ctx, origin, route, method, value, relationship, credential)
	}
	body, e := protocol.Canonical(value)
	if e != nil {
		return nil, e
	}
	headers, e := protocol.AuthHeaders(credential, relationship, method, route, body, time.Now().Unix())
	if e != nil {
		return nil, e
	}
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	s := l.nodes[origin]
	r, e := s.Authenticate(ctx, h, method, route, body, false, false)
	if e != nil {
		return nil, e
	}
	var request certificate.Request
	if e = json.Unmarshal(body, &request); e != nil {
		return nil, e
	}
	v, e := s.ReceiveCertificate(ctx, r, request)
	if e != nil {
		return nil, e
	}
	b, _ := json.Marshal(v)
	var result map[string]any
	json.Unmarshal(b, &result)
	return result, nil
}

type fakeCertificate struct {
	calls            atomic.Int32
	entered, release chan struct{}
	fail             bool
}

func (f *fakeCertificate) Control(ctx context.Context, r certificate.Request) (certificate.View, error) {
	f.calls.Add(1)
	if f.entered != nil {
		close(f.entered)
		select {
		case <-f.release:
		case <-ctx.Done():
			return certificate.View{}, ctx.Err()
		}
	}
	if f.fail {
		return certificate.View{}, errors.New("unavailable agent")
	}
	return certificate.View{Hostname: "storage.fixture.test", Managed: true, AutoRenew: true, State: "ACTIVE", NotAfter: 12345, Download: &certificate.DownloadEnvelope{Ciphertext: "opaque-fixture"}}, nil
}
func TestMasterSignedCertificateDownloadRolesSerialAndAudit(t *testing.T) {
	ctx := context.Background()
	wire := &certificateWire{localControl: localControl{nodes: map[string]*Service{}}}
	master, masterDB := testNode(t, "Master", "https://master.fixture.test", wire)
	follower, _ := testNode(t, "Follower", "https://storage.fixture.test:8443", wire)
	wire.nodes["https://master.fixture.test"] = master
	wire.nodes["https://storage.fixture.test:8443"] = follower
	signed, e := follower.CreatePair(ctx, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	id, e := master.ImportPair(ctx, signed, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	agent := &fakeCertificate{}
	facts := func() certificate.View {
		return certificate.View{Hostname: "storage.fixture.test", State: "ACTIVE", NotAfter: 12345}
	}
	master.ConfigureNetwork(0, nil, nil, masterDB.Admin())
	follower.ConfigureNetwork(3480, agent, facts, nil)
	v, e := master.Certificate(ctx, id, certificate.Request{Action: "download", BrowserPublicKey: "opaque-browser-key", BrowserNonce: strings.Repeat("a", 43)}, store.NodeAudit{Actor: "session-hash", RequestID: "certificate-control-test"})
	if e != nil || v["auto_renew"] != true || v["not_after"] != float64(12345) {
		t.Fatal("signed control lost served TLS facts", v, e)
	}
	var count int
	if e = masterDB.Database().QueryRow("SELECT count(*) FROM admin_audit_log WHERE action='node_certificate_download'").Scan(&count); e != nil || count != 1 {
		t.Fatal("missing before-dispatch audit", count, e)
	}
	agent.entered = make(chan struct{})
	agent.release = make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, e := master.Certificate(ctx, id, certificate.Request{Action: "download", BrowserPublicKey: "opaque-browser-key", BrowserNonce: strings.Repeat("a", 43)}, store.NodeAudit{})
		done <- e
	}()
	<-agent.entered
	if _, e = master.Certificate(ctx, id, certificate.Request{Action: "status"}, store.NodeAudit{}); e == nil {
		t.Fatal("concurrent certificate dispatch admitted")
	}
	close(agent.release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	agent.entered = nil
	agent.fail = true
	v, e = master.Certificate(ctx, id, certificate.Request{Action: "status"}, store.NodeAudit{})
	if e != nil || v["state"] != "ACTIVE" {
		t.Fatal("agent outage poisoned existing TLS observation", v, e)
	}
	for _, action := range []string{"renew", "auto", "upload", "export-private-path"} {
		if _, e = master.Certificate(ctx, id, certificate.Request{Action: action}, store.NodeAudit{}); e == nil {
			t.Fatal("manual certificate management returned", action)
		}
	}
	before := agent.calls.Load()
	if _, e = follower.Certificate(ctx, id, certificate.Request{Action: "download", BrowserPublicKey: "opaque-browser-key", BrowserNonce: strings.Repeat("a", 43)}, store.NodeAudit{}); e == nil {
		t.Fatal("Follower gained Master authority")
	}
	if e = master.Revoke(ctx, id, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	if _, e = master.Certificate(ctx, id, certificate.Request{Action: "download", BrowserPublicKey: "opaque-browser-key", BrowserNonce: strings.Repeat("a", 43)}, store.NodeAudit{}); e == nil || agent.calls.Load() != before {
		t.Fatal("revoked relationship reached agent", e)
	}
}
func TestSTUNIncludesAllActiveStorageAndSignedCustomPort(t *testing.T) {
	ctx := context.Background()
	wire := &localControl{nodes: map[string]*Service{}}
	master, md := testNode(t, "Master", "https://master.fixture.test", wire)
	wire.nodes["https://master.fixture.test"] = master
	var revokeID string
	for _, host := range []string{"a", "b", "c", "d", "e", "f"} {
		origin := "https://" + host + ".fixture.test:8443"
		follower, fd := testNode(t, "Follower", origin, wire)
		follower.ConfigureVolumes(fd.Pool(), &testVolume{}, recordingRoot(t))
		wire.nodes[origin] = follower
		follower.ConfigureNetwork(3480, nil, nil, nil)
		signed, e := follower.CreatePair(ctx, store.NodeAudit{})
		if e != nil {
			t.Fatal(e)
		}
		id, e := master.ImportPair(ctx, signed, store.NodeAudit{})
		if e != nil {
			t.Fatal(e)
		}
		if host == "a" {
			revokeID = id
		}
	}
	relations, _ := master.repo.Relationships(ctx, false)
	master.ConfigureVolumes(md.Pool(), &testVolume{}, recordingRoot(t))
	for _, r := range relations {
		if e := master.Tick(ctx, r); e != nil {
			t.Fatal(e)
		}
	}
	first, e := master.STUNURLs(ctx, "master.fixture.test", 3478)
	if e != nil || len(first) != 7 {
		t.Fatal("storage nodes truncated", first, e)
	}
	again, _ := master.STUNURLs(ctx, "master.fixture.test", 3478)
	if !reflect.DeepEqual(first, again) {
		t.Fatal("STUN order random")
	}
	found := false
	for _, v := range first {
		if v == "stun:a.fixture.test:3480" {
			found = true
		}
	}
	if !found {
		t.Fatal("signed storage STUN port ignored", first)
	}
	if e = master.Revoke(ctx, revokeID, store.NodeAudit{}); e != nil {
		t.Fatal(e)
	}
	after, e := master.STUNURLs(ctx, "master.fixture.test", 3478)
	if e != nil || len(after) != 6 {
		t.Fatal("revoked STUN retained", after, e)
	}
	relations, _ = master.repo.Relationships(ctx, false)
	for _, r := range relations {
		if r.State != "active" {
			continue
		}
		follower := wire.nodes[r.Endpoint]
		follower.SetSTUNPort(0)
		if e = master.Tick(ctx, r); e != nil {
			t.Fatal(e)
		}
		unavailable, e := master.STUNURLs(ctx, "master.fixture.test", 3478)
		if e != nil || len(unavailable) != 5 {
			t.Fatal("unbound responder fell back to legacy port", unavailable, e)
		}
		follower.SetSTUNPort(3480)
		if e = master.Tick(ctx, r); e != nil {
			t.Fatal(e)
		}
		recovered, e := master.STUNURLs(ctx, "master.fixture.test", 3478)
		if e != nil || len(recovered) != 6 {
			t.Fatal("rebound responder missing", recovered, e)
		}
		break
	}
}
