package node

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type resourceOriginControl struct {
	*localControl
	resource *Service
}

type readinessControl struct {
	*resourceOriginControl
	seen string
	fail bool
}

func (c *resourceOriginControl) ProbeNativePlainMedia(ctx context.Context, origin, relationship, credential, challenge, token string) (map[string]any, error) {
	values, err := protocol.AuthHeaders(credential, relationship, http.MethodGet, NativePlainMediaProbePath, nil, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	headers := http.Header{}
	for name, value := range values {
		headers.Set(name, value)
	}
	relation, err := c.resource.Authenticate(ctx, headers, http.MethodGet, NativePlainMediaProbePath, nil, false, false)
	if err != nil {
		return nil, err
	}
	signed, err := c.resource.VerifyOwnedPlainMediaProbe(ctx, relation, challenge, token)
	if err != nil {
		return nil, err
	}
	return signed.wire(), nil
}

func (c *resourceOriginControl) ProbeNativeOpaqueMedia(ctx context.Context, origin, relationship, credential, challenge, token string) (map[string]any, error) {
	values, err := protocol.AuthHeaders(credential, relationship, http.MethodGet, NativeOpaqueMediaProbePath, nil, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	headers := http.Header{}
	for name, value := range values {
		headers.Set(name, value)
	}
	relation, err := c.resource.Authenticate(ctx, headers, http.MethodGet, NativeOpaqueMediaProbePath, nil, false, false)
	if err != nil {
		return nil, err
	}
	signed, err := c.resource.VerifyOwnedOpaqueMediaProbe(ctx, relation, challenge, token)
	if err != nil {
		return nil, err
	}
	return signed.wire(), nil
}

func (c *readinessControl) ProbeNativeMediaEndpoint(_ context.Context, origin string) error {
	c.seen = origin
	if c.fail {
		return errors.New("unavailable")
	}
	return nil
}

func TestFollowerResourceIdentityUsesVerifiedTLSAndPairedKey(t *testing.T) {
	ctx := context.Background()
	transport := &localControl{nodes: map[string]*Service{}}
	master, md := testNode(t, "Master", "https://master.test", transport)
	follower, fd := testNode(t, "Follower", "https://control.test", transport)
	master.ConfigureVolumes(md.Pool(), &testVolume{}, recordingRoot(t))
	follower.ConfigureVolumes(fd.Pool(), &testVolume{}, recordingRoot(t))
	transport.nodes["https://master.test"], transport.nodes["https://control.test"] = master, follower
	if err := follower.ConfigureFollowerResourceOrigin("https://node.test"); err != nil {
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
	rel, err := master.repo.Relationship(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err = master.Tick(ctx, rel); err != nil {
		t.Fatal(err)
	}
	server, roots := privateCA(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/v1/identity" {
			http.NotFound(w, r)
			return
		}
		signed, signErr := follower.SignedIdentity(r.Context(), r.URL.Query().Get("challenge"))
		if signErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(signed)
	}))
	master.transport = testTransport(t, server, roots)
	if origin, err := master.VerifyFollowerResourceIdentity(ctx, id); err != nil || origin != "https://node.test" {
		t.Fatal("verified TLS origin", origin, err)
	}
	master.transport = testTransport(t, server, x509.NewCertPool())
	if _, err := master.VerifyFollowerResourceIdentity(ctx, id); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
}

func TestFollowerDirectHandshakeRequiresReadinessAndBoundOrigin(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		name := "admin-confirmed"
		if automatic {
			name = "paired-profile"
		}
		t.Run(name, func(t *testing.T) { testFollowerDirectHandshake(t, automatic) })
	}
}

func testFollowerDirectHandshake(t *testing.T, automatic bool) {
	ctx := context.Background()
	transport := &localControl{nodes: map[string]*Service{}}
	master, md := testNode(t, "Master", "https://master.test", transport)
	follower, fd := testNode(t, "Follower", "https://follower.test", transport)
	master.ConfigureVolumes(md.Pool(), &testVolume{}, recordingRoot(t))
	follower.ConfigureVolumes(fd.Pool(), &testVolume{}, recordingRoot(t))
	transport.nodes["https://master.test"], transport.nodes["https://follower.test"] = master, follower
	if err := follower.ConfigureFollowerResourceOrigin("https://resource.test"); err != nil {
		t.Fatal(err)
	}
	if automatic {
		if err := follower.ConfigureStorageTransport("direct"); err != nil {
			t.Fatal(err)
		}
		master.EnableInitialNativeTransport()
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
	if err = routing.ConfigurePublicOrigin("https://public.test"); err != nil {
		t.Fatal(err)
	}
	rel, err := master.repo.Relationship(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if automatic {
		if rel.Mode != "Direct" {
			t.Fatal("the signed Direct profile did not survive pairing")
		}
	} else {
		if _, err = master.ConfirmNativeTransport(ctx, rel.PeerID, "Direct", 0, store.NodeAudit{}); err != nil {
			t.Fatal(err)
		}
		select {
		case <-master.wakeup:
		default:
			t.Fatal("saved policy did not wake control loop")
		}
	}
	master.transport = &resourceOriginControl{localControl: transport, resource: follower}
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
	policy := func() store.NativeTransportPolicy {
		t.Helper()
		value, e := routing.NativeTransport(ctx, rel.PeerID)
		if e != nil {
			t.Fatal(e)
		}
		return value
	}
	tick()
	if p := policy(); p.AppliedTransport != "" || automatic && p.Revision != 0 {
		t.Fatal("advertisement applied policy", p)
	}
	ready := func(context.Context, store.Relationship, string) error { return nil }
	master.ConfigureNativeTransportReadiness(ready)
	tick()
	if p := policy(); p.AppliedTransport != "" || p.PeerApplicationStatus != "failed" {
		t.Fatal("missing Follower readiness", p)
	}
	follower.ConfigureNativeTransportReadiness(ready)
	tick()
	if p := policy(); p.State != "applied" || p.AppliedTransport != "Direct" || p.AppliedOrigin != "https://resource.test" {
		t.Fatal("Direct acknowledgement", p)
	}
	if _, err := md.Database().Exec("UPDATE node_relationships SET last_heartbeat=? WHERE relationship_id=?", time.Now().Unix()-121, id); err != nil {
		t.Fatal(err)
	}
	if p := policy(); p.State == "applied" {
		t.Fatal("stale Direct observation remained applied", p)
	}
	if _, err := md.Database().Exec("UPDATE node_relationships SET last_heartbeat=? WHERE relationship_id=?", time.Now().Unix(), id); err != nil {
		t.Fatal(err)
	}
	if err := md.Nodes().RecordHeartbeat(ctx, id, true, 1, map[string]any{"native_resource_origin": "https://replacement.test"}, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if p := policy(); p.State == "applied" || p.AppliedOrigin != "https://resource.test" {
		t.Fatal("changed origin retained Direct application", p)
	}
	record := md.Nodes().(interface {
		RecordNativeDirectApplication(context.Context, string, int64, string) error
	})
	if err := record.RecordNativeDirectApplication(ctx, id, 1, "https://resource.test"); err == nil {
		t.Fatal("stale origin receipt accepted")
	}
}

func (c *resourceOriginControl) Request(ctx context.Context, origin, route, method string, value any, relationship, credential string) (map[string]any, error) {
	if route == NativePlainProbePath {
		body, err := protocol.Canonical(value)
		if err != nil {
			return nil, err
		}
		auth, err := protocol.AuthHeaders(credential, relationship, method, route, body, time.Now().Unix())
		if err != nil {
			return nil, err
		}
		headers := http.Header{}
		for name, value := range auth {
			headers.Set(name, value)
		}
		relation, err := c.resource.Authenticate(ctx, headers, method, route, body, false, false)
		if err != nil {
			return nil, err
		}
		request, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("invalid probe fixture")
		}
		signed, err := c.resource.VerifyOwnedPlainProbe(ctx, relation, textField(request, "challenge"), textField(request, "token"))
		if err != nil {
			return nil, err
		}
		return signed.wire(), nil
	}
	if strings.HasPrefix(route, "/internal/v1/identity?") {
		u, err := url.Parse(route)
		if err != nil {
			return nil, err
		}
		signed, err := c.resource.SignedIdentity(ctx, u.Query().Get("challenge"))
		if err != nil {
			return nil, err
		}
		return signed.wire(), nil
	}
	return c.localControl.Request(ctx, origin, route, method, value, relationship, credential)
}

func TestFollowerResourceOriginIsExplicitAuthenticatedObservation(t *testing.T) {
	ctx := context.Background()
	transport := &localControl{nodes: map[string]*Service{}}
	master, md := testNode(t, "Master", "https://master.test", transport)
	follower, fd := testNode(t, "Follower", "https://follower.test", transport)
	follower.ConfigurePlainReadProbe(func(context.Context) error { return nil })
	follower.ConfigureOpaqueReadProbe(func(context.Context) error { return nil })
	enableOpaqueProbeFixture(follower)
	master.ConfigureVolumes(md.Pool(), &testVolume{}, recordingRoot(t))
	follower.ConfigureVolumes(fd.Pool(), &testVolume{}, recordingRoot(t))
	transport.nodes["https://master.test"], transport.nodes["https://follower.test"] = master, follower
	if err := master.ConfigureFollowerResourceOrigin("https://resource.test"); err == nil {
		t.Fatal("Master advertised Follower origin")
	}
	for _, value := range []string{"http://resource.test", "https://resource.test/path", "https://resource.test:8443", "https://resource.test:443", "https://localhost", "https://user@resource.test"} {
		if err := follower.ConfigureFollowerResourceOrigin(value); err == nil {
			t.Fatalf("invalid resource origin %q accepted", value)
		}
	}
	pkg, err := follower.CreatePair(ctx, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	id, err := master.ImportPair(ctx, pkg, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	tick := func() {
		t.Helper()
		rel, e := master.repo.Relationship(ctx, id)
		if e != nil {
			t.Fatal(e)
		}
		if e = master.Tick(ctx, rel); e != nil {
			t.Fatal(e)
		}
	}
	tick()
	if _, err = master.ObservedFollowerResourceOrigin(ctx, id); err == nil {
		t.Fatal("control address inferred as resource origin")
	}
	if err = follower.ConfigureFollowerResourceOrigin("https://resource.test"); err != nil {
		t.Fatal(err)
	}
	if err = follower.ConfigureFollowerResourceOrigin("https://other.test"); err == nil {
		t.Fatal("startup-only origin changed")
	}
	tick()
	if origin, err := master.ObservedFollowerResourceOrigin(ctx, id); err != nil || origin != "https://resource.test" {
		t.Fatal("authenticated observation", origin, err)
	}
	probe := &readinessControl{resourceOriginControl: &resourceOriginControl{localControl: transport, resource: follower}}
	master.transport = probe
	if origin, err := master.VerifyFollowerResourceIdentity(ctx, id); err != nil || origin != "https://resource.test" {
		t.Fatal("resource endpoint identity", origin, err)
	}
	relation, err := master.repo.Relationship(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := master.VerifyNativeTransportReadiness(ctx, relation, "Direct"); err != nil || probe.seen != "https://resource.test" {
		t.Fatal("Direct readiness", probe.seen, err)
	}
	if err := master.VerifyNativeTransportReadiness(ctx, relation, "Relay"); err != nil || probe.seen != "https://follower.test" {
		t.Fatal("Relay readiness", probe.seen, err)
	}
	if err := master.VerifyNativeOpaqueTransportReadiness(ctx, relation, "Relay"); err != nil || probe.seen != relation.Endpoint {
		t.Fatal("paired Relay v5 readiness", probe.seen, err)
	}
	follower.ConfigureOpaqueReadProbe(nil)
	if err := master.VerifyNativeOpaqueTransportReadiness(ctx, relation, "Relay"); err == nil {
		t.Fatal("Relay applied without a v5 Owner reader proof")
	}
	follower.ConfigureOpaqueReadProbe(func(context.Context) error { return nil })
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := master.VerifyNativeOpaqueTransportReadiness(cancelled, relation, "Relay"); err == nil {
		t.Fatal("cancelled Relay readiness succeeded")
	}
	follower.ConfigurePlainReadProbe(func(context.Context) error { return errors.New("synthetic reader failed") })
	if err := master.VerifyNativeTransportReadiness(ctx, relation, "Direct"); err == nil {
		t.Fatal("failed v4 reader probe applied Direct")
	}
	follower.ConfigurePlainReadProbe(nil)
	if err := master.VerifyNativeTransportReadiness(ctx, relation, "Relay"); err == nil {
		t.Fatal("missing v4 capability applied Relay")
	}
	follower.ConfigurePlainReadProbe(func(context.Context) error { return nil })
	probe.fail = true
	if err := master.VerifyNativeTransportReadiness(ctx, relation, "Direct"); err == nil {
		t.Fatal("failed media probe accepted")
	}
	master.transport = &resourceOriginControl{localControl: transport, resource: master}
	if _, err := master.VerifyFollowerResourceIdentity(ctx, id); err == nil {
		t.Fatal("different identity accepted at resource origin")
	}
	if _, err := md.Database().Exec("UPDATE node_relationships SET last_heartbeat=? WHERE relationship_id=?", time.Now().Unix()-121, id); err != nil {
		t.Fatal(err)
	}
	if _, err = master.ObservedFollowerResourceOrigin(ctx, id); err == nil {
		t.Fatal("stale origin accepted")
	}
}

func TestFollowerResourceOriginRequiresInitializedRole(t *testing.T) {
	service, db := testNode(t, "Standalone", "", nil)
	if err := ValidateFollowerResourceOrigin("https://resource.test"); err != nil {
		t.Fatal(err)
	}
	if err := service.ConfigureFollowerResourceOrigin("https://resource.test"); err == nil {
		t.Fatal("Standalone advertised Follower origin")
	}
	if _, err := db.Database().Exec("UPDATE node_identity SET `role`='Follower',endpoint='https://control.test' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	if err := service.ConfigureFollowerResourceOrigin("https://resource.test"); err != nil {
		t.Fatal("initialized Follower rejected", err)
	}
}
