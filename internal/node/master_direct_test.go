package node

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type masterDirectFixtureRepo struct {
	store.NodeRepository
	store.PublicRoutingRepository
	current    store.PublicIngress
	policy     store.NativeTransportPolicy
	commitFail bool
}

type masterPolicyFixtureLease struct{ fail bool }

func (l *masterPolicyFixtureLease) Commit() error {
	if l.fail {
		return errors.New("lease commit failed")
	}
	return nil
}
func (*masterPolicyFixtureLease) Release() {}

func (r *masterDirectFixtureRepo) AcquireCurrentIngress(context.Context) (store.PublicIngress, store.PublicIngressLease, error) {
	return r.current, &masterPolicyFixtureLease{fail: r.commitFail}, nil
}

func (r *masterDirectFixtureRepo) PublicIngress(context.Context) (store.PublicIngress, error) {
	return r.current, nil
}
func (r *masterDirectFixtureRepo) NativeTransport(context.Context, string) (store.NativeTransportPolicy, error) {
	return r.policy, nil
}

func TestMasterDirectGrantRequiresAppliedPolicyAndVerifiedAdmission(t *testing.T) {
	ctx := context.Background()
	s, db := testNode(t, "Master", "https://control.test", nil)
	identity, err := s.IdentityState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ingressID := strings.Repeat("a", 32)
	r := &masterDirectFixtureRepo{NodeRepository: db.Nodes(), PublicRoutingRepository: db.Nodes().(store.PublicRoutingRepository),
		current: store.PublicIngress{NodeID: ingressID, PublicOrigin: "https://entry.test", Generation: 9},
		policy:  store.NativeTransportPolicy{MemberID: identity.ID, ConfiguredTransport: "Direct", AppliedTransport: "Direct", State: "applied", Revision: 7}}
	s.repo = r
	verified, err := network.WithAuthenticatedIngress(ctx, network.AuthenticatedIngress{NodeID: ingressID, PublicOrigin: r.current.PublicOrigin, Generation: 9, ClientIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	resource, object, revision, descriptor := strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64)
	issue := func(ctx context.Context, origin string) (string, error) {
		return s.IssueMasterDirectCapability(ctx, origin, resource, object, revision, descriptor)
	}
	if _, err = issue(ctx, "https://resource.test"); !errors.Is(err, ErrCapability) {
		t.Fatal("unverified grant", err)
	}
	if _, err = issue(verified, "https://resource.test"); !errors.Is(err, ErrCapability) {
		t.Fatal("missing admission", err)
	}
	admitted, admission := network.WithPublicAdmission(verified)
	defer admission.Abort()
	if _, err = issue(admitted, "https://resource.test"); !errors.Is(err, ErrCapability) {
		t.Fatal("missing browser session admitted", err)
	}
	manager, err := mediacrypto.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	client, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := "browser:v2:" + strings.Repeat("c", 64)
	session, err := manager.NewSession(binding, base64.StdEncoding.EncodeToString(client.PublicKey().Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	admitted, err = manager.WithDirectSession(admitted, binding, session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "http://resource.test", "https://resource.test/path", "https://resource.test:443"} {
		if _, err = issue(admitted, bad); !errors.Is(err, ErrCapability) {
			t.Fatal("bad resource origin", bad, err)
		}
	}
	r.policy.AppliedTransport, r.policy.State = "", "retained"
	if _, err = issue(admitted, "https://resource.test"); !errors.Is(err, ErrCapability) {
		t.Fatal("unapplied policy admitted", err)
	}
	r.policy.AppliedTransport, r.policy.State = "Direct", "applied"
	if err := s.ConfigureMasterResourceReadiness("https://resource.test", func(context.Context, store.PublicIngress, string, string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.PrepareMasterResourcePolicy(ctx); err != nil {
		t.Fatal(err)
	}
	token, err := issue(admitted, "https://resource.test")
	if err != nil {
		t.Fatal(err)
	}
	claim, err := s.VerifyMasterDirectCapability(ctx, token, "https://resource.test", resource)
	if err != nil || claim.IngressID != ingressID || claim.Generation != 9 || claim.PublicOrigin != r.current.PublicOrigin || claim.ObjectID != object || claim.Revision != revision || claim.Descriptor != descriptor || claim.PolicyRevision != 7 {
		t.Fatal("incorrect claim", claim, err)
	}
	if _, err = s.VerifyMasterDirectCapability(ctx, token, "https://other.test", resource); !errors.Is(err, ErrCapability) {
		t.Fatal("wrong target accepted", err)
	}
	if _, err = s.VerifyMasterDirectCapability(ctx, token, "https://resource.test", strings.Repeat("f", 64)); !errors.Is(err, ErrCapability) {
		t.Fatal("wrong resource accepted", err)
	}
	parts := strings.Split(token, ".")
	parts[1] = protocol.Encode([]byte(strings.Repeat("x", 64)))
	if _, err = s.VerifyMasterDirectCapability(ctx, strings.Join(parts, "."), "https://resource.test", resource); !errors.Is(err, ErrCapability) {
		t.Fatal("forged token accepted", err)
	}
	if _, err = s.verifyMasterDirectCapability(ctx, token, "https://resource.test", resource, claim.ExpiresAt); !errors.Is(err, ErrCapability) {
		t.Fatal("expired token accepted", err)
	}
	// A switch cannot mint another grant under stale context. An already issued
	// grant can drain until its original expiry without renewing its lifetime.
	r.current.Generation++
	r.policy.ConfiguredTransport, r.policy.AppliedTransport = "Relay", "Relay"
	if _, err = issue(admitted, "https://resource.test"); !errors.Is(err, ErrCapability) {
		t.Fatal("stale ingress minted grant", err)
	}
	if _, err = s.verifyMasterDirectCapability(ctx, token, "https://resource.test", resource, time.Now().Unix()); err != nil {
		t.Fatal("previous grant did not drain", err)
	}
	manager.RevokeBinding(binding)
	if manager.CheckDirectSession(session.SessionID) {
		t.Fatal("revoked session remained valid")
	}
	admission.Abort()
	if network.HasActivePublicAdmission(admitted) {
		t.Fatal("aborted admission remains active")
	}
}
