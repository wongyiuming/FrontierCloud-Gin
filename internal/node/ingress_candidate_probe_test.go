package node

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type candidateMasterControl struct {
	*resourceOriginControl
	follower   *Service
	afterProbe func()
}

func (c *candidateMasterControl) ProbeNativeOpaqueMedia(ctx context.Context, origin, relationship, credential, challenge, token string) (map[string]any, error) {
	if origin != "https://candidate.test" {
		return nil, errors.New("wrong fixture origin")
	}
	values, err := protocol.AuthHeaders(credential, relationship, http.MethodGet, NativeOpaqueMediaProbePath, nil, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	headers := http.Header{}
	for key, value := range values {
		headers.Set(key, value)
	}
	relation, err := c.follower.Authenticate(ctx, headers, http.MethodGet, NativeOpaqueMediaProbePath, nil, false, false)
	if err != nil {
		return nil, err
	}
	signed, err := c.follower.VerifyOwnedOpaqueMediaProbe(ctx, relation, challenge, token)
	if err != nil {
		return nil, err
	}
	return signed.wire(), nil
}

func (c *candidateMasterControl) CandidatePublic(ctx context.Context, origin string, body []byte, headers http.Header) (map[string]any, error) {
	if origin != "https://candidate.test" {
		return nil, errors.New("wrong candidate origin")
	}
	signed, err := c.follower.VerifyCandidatePublicProbe(ctx, "candidate.test", headers, body)
	if err != nil {
		return nil, err
	}
	return signed.wire(), nil
}

type candidatePrerequisiteLease struct {
	ready    *bool
	releases *int
	released bool
}

func (l *candidatePrerequisiteLease) Check(ctx context.Context) error {
	if !*l.ready {
		return errors.New("prerequisite lost")
	}
	return ctx.Err()
}
func (l *candidatePrerequisiteLease) Release() {
	if !l.released {
		l.released = true
		*l.releases++
	}
}

func (c *candidateMasterControl) Request(ctx context.Context, origin, route, method string, value any, relationship, credential string) (map[string]any, error) {
	if route != "/internal/v1/public-ingress-probe" && route != NativePlainProbePath {
		return c.resourceOriginControl.Request(ctx, origin, route, method, value, relationship, credential)
	}
	body, err := protocol.Canonical(value)
	if err != nil {
		return nil, err
	}
	auth, err := protocol.AuthHeaders(credential, relationship, method, route, body, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	headers := http.Header{}
	for key, value := range auth {
		headers.Set(key, value)
	}
	relation, err := c.follower.Authenticate(ctx, headers, method, route, body, false, false)
	if err != nil {
		return nil, err
	}
	request, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("invalid fixture body")
	}
	if route == NativePlainProbePath {
		signed, err := c.follower.VerifyOwnedPlainProbe(ctx, relation, textField(request, "challenge"), textField(request, "token"))
		if err != nil {
			return nil, err
		}
		return signed.wire(), nil
	}
	signed, err := c.follower.ProbeMasterIngressEdge(ctx, relation, textField(request, "challenge"))
	if err != nil {
		return nil, err
	}
	if c.afterProbe != nil {
		c.afterProbe()
	}
	return signed.wire(), nil
}

func TestCandidateProxyPreflightAndExplicitSelection(t *testing.T) {
	ctx := context.Background()
	transport := &localControl{nodes: map[string]*Service{}}
	master, md := testNode(t, "Master", "https://node.test", transport)
	follower, fd := testNode(t, "Follower", "https://follower.test", transport)
	follower.ConfigurePlainReadProbe(func(context.Context) error { return nil })
	master.ConfigureVolumes(md.Pool(), &testVolume{}, recordingRoot(t))
	follower.ConfigureVolumes(fd.Pool(), &testVolume{}, recordingRoot(t))
	transport.nodes["https://node.test"], transport.nodes["https://follower.test"] = master, follower
	if err := follower.ConfigureFollowerIngressCandidate("https://candidate.test"); err != nil {
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
	routing := md.Nodes().(store.PublicRoutingRepository)
	if err := master.ConfigurePublicOrigin("https://public.test"); err != nil {
		t.Fatal(err)
	}
	before, err := routing.PublicIngress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	relation, err := master.repo.Relationship(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err = master.Tick(ctx, relation); err != nil {
		t.Fatal(err)
	}
	server, roots := privateCA(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != IngressCandidateEdgePath {
			http.NotFound(w, r)
			return
		}
		body, readErr := io.ReadAll(io.LimitReader(r.Body, 1025))
		if readErr != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		signed, verifyErr := master.VerifyCandidateEdge(r.Context(), r.Header, body)
		if verifyErr != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(signed)
	}))
	follower.transport = testTransport(t, server, roots)
	probeControl := &candidateMasterControl{resourceOriginControl: &resourceOriginControl{localControl: transport, resource: follower}, follower: follower}
	master.transport = probeControl
	if origin, err := master.VerifyFollowerIngressProxy(ctx, id); err != nil || origin != "https://candidate.test" {
		t.Fatal("candidate probe", origin, err)
	}
	follower.ConfigurePlainReadProbe(nil)
	if _, err := master.VerifyFollowerIngressProxy(ctx, id); err == nil {
		t.Fatal("candidate without v4 reader proof accepted")
	}
	follower.ConfigurePlainReadProbe(func(context.Context) error { return nil })
	if after, err := routing.PublicIngress(ctx); err != nil || after != before {
		t.Fatal("probe selected ingress", after, err)
	}
	follower.transport = testTransport(t, server, x509.NewCertPool())
	if _, err := master.VerifyFollowerIngressProxy(ctx, id); err == nil {
		t.Fatal("untrusted Master certificate accepted")
	}
	follower.transport = testTransport(t, server, roots)
	upstream, err := follower.repo.Relationship(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := follower.identity.vault.Unseal(upstream.Credential)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := follower.repo.ReadIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(candidateEdgeProof{PeerID: identity.ID, Origin: "https://candidate.test", Challenge: strings.Repeat("a", 32)})
	values, err := protocol.AuthHeaders(credential, id, http.MethodPost, ingressCandidateProofDomain, body, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	headers := http.Header{}
	for name, value := range values {
		headers.Set(name, value)
	}
	client := follower.transport.(candidateEdgeTransport)
	if _, err := client.CandidateEdge(ctx, upstream.Endpoint, body, headers); err != nil {
		t.Fatal("first candidate proof", err)
	}
	if _, err := client.CandidateEdge(ctx, upstream.Endpoint, body, headers); err == nil {
		t.Fatal("candidate proof replay accepted")
	}
	if _, err := master.SelectPublicIngress(ctx, relation.PeerID, before.Generation, store.NodeAudit{}); err == nil {
		t.Fatal("selection bypassed closed runtime gate")
	}
	releases := 0
	ready := true
	var afterReady func()
	if err := master.ConfigureIngressSelectionReadiness(ctx, func(context.Context) (IngressPrerequisiteLease, error) {
		if !ready {
			return nil, errors.New("unavailable")
		}
		if afterReady != nil {
			afterReady()
		}
		return &candidatePrerequisiteLease{ready: &ready, releases: &releases}, nil
	}); err != nil {
		t.Fatal(err)
	}
	probeControl.afterProbe = func() { ready = false }
	if _, err := master.SelectPublicIngress(ctx, relation.PeerID, before.Generation, store.NodeAudit{}); err == nil {
		t.Fatal("lost prerequisite allowed selection")
	}
	if current, err := routing.PublicIngress(ctx); err != nil || current != before {
		t.Fatal("lost prerequisite changed ingress", current, err)
	}
	ready, probeControl.afterProbe = true, nil
	masterBefore, err := master.repo.ReadIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	afterReady = func() {
		afterReady = nil
		if _, err := md.Database().ExecContext(ctx, "UPDATE node_identity SET created_at=created_at+1 WHERE singleton=1"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := master.SelectPublicIngress(ctx, relation.PeerID, before.Generation, store.NodeAudit{}); err == nil {
		t.Fatal("replaced Master identity instance accepted")
	}
	if _, err := md.Database().ExecContext(ctx, "UPDATE node_identity SET created_at=? WHERE singleton=1", masterBefore.CreatedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := master.SelectPublicIngressAtOrigin(ctx, relation.PeerID, before.Generation, "https://changed.test", store.NodeAudit{}); err == nil {
		t.Fatal("different address was accepted for the confirmed candidate")
	}
	if current, err := routing.PublicIngress(ctx); err != nil || current != before {
		t.Fatal("address mismatch changed ingress", current, err)
	}
	selected, err := master.SelectPublicIngressAtOrigin(ctx, relation.PeerID, before.Generation, "https://candidate.test", store.NodeAudit{Actor: "admin"})
	if err != nil || selected.NodeID != relation.PeerID || selected.PublicOrigin != "https://candidate.test" || selected.Generation != before.Generation+1 {
		t.Fatal("explicit candidate selection", selected, err)
	}
	// A prerequisite that fails after network preflight acquires no lease.
	if releases != 3 {
		t.Fatal("runtime readiness lease not released", releases)
	}
	_, admittedLease, err := master.AcquireCurrentIngress(ctx)
	if err != nil {
		t.Fatal("selected ingress admission", err)
	}
	ready = false
	if _, deniedLease, err := master.AcquireCurrentIngress(ctx); err == nil || deniedLease != nil {
		t.Fatal("failed tree prerequisite admitted ingress")
	}
	if err := admittedLease.Commit(); err == nil {
		t.Fatal("lost prerequisite allowed admission commit")
	}
	if releases != 4 {
		t.Fatal("admission readiness lease not released", releases)
	}
	ready = true
	if _, err := master.SelectPublicIngress(ctx, relation.PeerID, before.Generation, store.NodeAudit{}); err == nil {
		t.Fatal("stale ingress revision accepted")
	}
	masterIdentity, err := master.IdentityState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ready = false
	if master.IngressSelectionAvailable(ctx) {
		t.Fatal("failed prerequisite shown as available")
	}
	if _, err := master.SelectPublicIngress(ctx, masterIdentity.ID, selected.Generation, store.NodeAudit{}); err == nil {
		t.Fatal("failed prerequisite allowed selection")
	}
	ready = true
	back, err := master.SelectPublicIngress(ctx, masterIdentity.ID, selected.Generation, store.NodeAudit{Actor: "admin"})
	if err != nil || back.NodeID != masterIdentity.ID || back.PublicOrigin != "https://public.test" || back.Generation != selected.Generation+1 {
		t.Fatal("explicit public ingress selection for Master", back, err)
	}
}

func TestSelectionRechecksSignedProbeAndExpiry(t *testing.T) {
	ctx := context.Background()
	follower, _ := testNode(t, "Follower", "https://follower.test", nil)
	row, err := follower.repo.ReadIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key, err := follower.public(row)
	if err != nil {
		t.Fatal(err)
	}
	challenge := strings.Repeat("a", 32)
	payload := map[string]any{"node_id": row.ID, "role": "Follower", "endpoint": row.Endpoint, "public_key": key, "challenge": challenge, "protocol": protocol.Version, "capabilities": []string{protocol.PublicIngressProxyCapability}}
	proof, err := follower.identity.signed(row, payload)
	if err != nil {
		t.Fatal(err)
	}
	relation := store.Relationship{PeerID: row.ID, Endpoint: row.Endpoint, PublicKey: key}
	start := time.Now()
	if err := validateSelectionProbe(relation, challenge, proof, start, start); err != nil {
		t.Fatal("valid probe rejected", err)
	}
	if validateSelectionProbe(relation, challenge, proof, start, start.Add(time.Duration(protocol.TokenSeconds)*time.Second+time.Nanosecond)) == nil {
		t.Fatal("expired probe accepted")
	}
	if validateSelectionProbe(relation, strings.Repeat("b", 32), proof, start, start) == nil {
		t.Fatal("different challenge accepted")
	}
	changed := relation
	changed.Endpoint = "https://other.test"
	if validateSelectionProbe(changed, challenge, proof, start, start) == nil {
		t.Fatal("different endpoint accepted")
	}
	proof.Payload["role"] = "Master"
	if validateSelectionProbe(relation, challenge, proof, start, start) == nil {
		t.Fatal("tampered signed probe accepted")
	}
	payload["role"] = "Follower"
	payload["native_plain_probe"] = "verified-v5-opaque"
	payload["capabilities"] = []string{protocol.NativeOpaqueProofCapability}
	opaque, err := follower.identity.signed(row, payload)
	if err != nil {
		t.Fatal(err)
	}
	if validateSelectionOpaqueProbe(relation, challenge, opaque, start, start) != nil {
		t.Fatal("valid v5 proof rejected")
	}
	if validateSelectionOpaqueProbe(relation, challenge, opaque, start, start.Add(time.Duration(protocol.TokenSeconds)*time.Second+time.Nanosecond)) == nil {
		t.Fatal("expired v5 proof accepted")
	}
	opaque.Payload["native_plain_probe"] = "verified-v4-control"
	if validateSelectionOpaqueProbe(relation, challenge, opaque, start, start) == nil {
		t.Fatal("tampered v5 proof accepted")
	}
}

func TestCandidatePublicListenerUsesTLSAndRejectsReplay(t *testing.T) {
	ctx := context.Background()
	transport := &localControl{nodes: map[string]*Service{}}
	master, _ := testNode(t, "Master", "https://master.test", transport)
	follower, _ := testNode(t, "Follower", "https://follower.test", transport)
	transport.nodes["https://master.test"], transport.nodes["https://follower.test"] = master, follower
	if err := follower.ConfigureFollowerIngressCandidate("https://node.test"); err != nil {
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
	relation, err := master.repo.Relationship(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := master.IdentityState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := master.identity.vault.Unseal(relation.Credential)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(candidateListenerProof{MasterID: identity.ID, PeerID: relation.PeerID, Origin: "https://node.test", Challenge: strings.Repeat("a", 32)})
	if err != nil {
		t.Fatal(err)
	}
	sign := func() http.Header {
		t.Helper()
		values, err := protocol.AuthHeaders(credential, id, http.MethodPost, ingressCandidateListenerDomain, body, time.Now().Unix())
		if err != nil {
			t.Fatal(err)
		}
		headers := http.Header{}
		for name, value := range values {
			headers.Set(name, value)
		}
		return headers
	}
	server, roots := privateCA(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != IngressCandidatePublicPath {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1025))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		signed, err := follower.VerifyCandidatePublicProbe(r.Context(), r.Host, r.Header, body)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(signed)
	}))
	client := testTransport(t, server, roots)
	headers := sign()
	if _, err := client.CandidatePublic(ctx, "https://node.test", body, headers); err != nil {
		t.Fatal("paired public listener", err)
	}
	if _, err := client.CandidatePublic(ctx, "https://node.test", body, headers); err == nil {
		t.Fatal("public listener proof replay accepted")
	}
	untrusted := testTransport(t, server, x509.NewCertPool())
	if _, err := untrusted.CandidatePublic(ctx, "https://node.test", body, sign()); err == nil {
		t.Fatal("untrusted candidate certificate accepted")
	}
	if _, err := client.CandidatePublic(ctx, "https://wrong-name.test", body, sign()); err == nil {
		t.Fatal("wrong candidate hostname accepted")
	}
}
