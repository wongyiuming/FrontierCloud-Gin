package node

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type followerRelayFixtureRepo struct {
	*masterDirectFixtureRepo
	relation store.Relationship
}

func (r *followerRelayFixtureRepo) Relationship(_ context.Context, id string) (store.Relationship, error) {
	if id != r.relation.ID {
		return store.Relationship{}, store.ErrNodeState
	}
	return r.relation, nil
}

func TestFollowerRelayGrantIsDistinctAndFenced(t *testing.T) {
	ctx := context.Background()
	s, db := testNode(t, "Master", "https://master.test", nil)
	identity, err := s.IdentityState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ingress, owner, relationID := strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32)
	r := &followerRelayFixtureRepo{masterDirectFixtureRepo: &masterDirectFixtureRepo{NodeRepository: db.Nodes(), PublicRoutingRepository: db.Nodes().(store.PublicRoutingRepository),
		current: store.PublicIngress{NodeID: ingress, PublicOrigin: "https://entry.test", Generation: 4},
		policy:  store.NativeTransportPolicy{MemberID: owner, ConfiguredTransport: "Relay", AppliedTransport: "Relay", State: "applied", Revision: 9}},
		relation: store.Relationship{ID: relationID, PeerID: owner, Direction: "downstream", State: "active", Protocol: protocol.Version}}
	s.repo = r
	verified, err := network.WithAuthenticatedIngress(ctx, network.AuthenticatedIngress{NodeID: ingress, PublicOrigin: r.current.PublicOrigin, Generation: r.current.Generation, ClientIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	resource, object, revision, descriptor := strings.Repeat("d", 64), strings.Repeat("e", 64), strings.Repeat("f", 64), strings.Repeat("0", 64)
	issue := func(c context.Context) (string, error) {
		return s.IssueFollowerRelayCapability(c, relationID, owner, resource, object, revision, descriptor)
	}
	if _, err = issue(verified); !errors.Is(err, ErrCapability) {
		t.Fatal("missing admission", err)
	}
	admitted, admission := network.WithPublicAdmission(verified)
	defer admission.Abort()
	if _, err = issue(admitted); !errors.Is(err, ErrCapability) {
		t.Fatal("missing session", err)
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
	if _, err = issue(admitted); !errors.Is(err, ErrCapability) {
		t.Fatal("durable receipt bypassed missing runtime readiness", err)
	}
	s.ConfigureNativeTransportReadiness(func(context.Context, store.Relationship, string) error { return nil })
	token, err := issue(admitted)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := s.VerifyFollowerRelayCapability(verified, token, resource)
	if err != nil || claim.OwnerID != owner || claim.RelationshipID != relationID || claim.Descriptor != descriptor || claim.Revision != revision || claim.SessionID != session.SessionID || claim.MasterID != identity.ID || claim.ExpiresAt > session.ExpiresAt {
		t.Fatal("wrong claim", claim, err)
	}
	if _, err = protocol.VerifyIngressMediaToken(protocol.Encode(make([]byte, 48)), token, 1); err == nil {
		t.Fatal("relay grant accepted as owner capability")
	}
	// An opaque relay grant has its own signed kind and uses only the random
	// wire alias. Legacy and opaque readers cannot interchange the grants.
	alias := strings.Repeat("1", 64)
	opaque := claim
	opaque.Kind, opaque.ResourceID, opaque.ObjectID = "opaque-follower-relay-read", alias, alias
	private, err := s.identity.vault.Unseal(identity.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(value FollowerRelayClaim) string {
		t.Helper()
		signature, e := protocol.Sign(private, value.signedPayload())
		if e != nil {
			t.Fatal(e)
		}
		raw, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(raw), resource) || strings.Contains(string(raw), object) {
			t.Fatal("historical ID entered opaque relay claim")
		}
		return protocol.Encode(raw) + "." + signature
	}
	opaqueToken := sign(opaque)
	if _, err := s.VerifyOpaqueFollowerRelayCapability(verified, opaqueToken, alias); err != nil {
		t.Fatal("opaque relay rejected", err)
	}
	if _, err := s.VerifyFollowerRelayCapability(verified, opaqueToken, alias); err == nil {
		t.Fatal("legacy relay accepted opaque grant")
	}
	if _, err := s.VerifyOpaqueFollowerRelayCapability(verified, token, resource); err == nil {
		t.Fatal("opaque relay accepted legacy grant")
	}
	opaque.ObjectID = strings.Repeat("2", 64)
	if _, err := s.VerifyOpaqueFollowerRelayCapability(verified, sign(opaque), alias); err == nil {
		t.Fatal("opaque relay accepted two distinct identifiers")
	}
	if _, err = s.VerifyFollowerRelayCapability(ctx, token, resource); !errors.Is(err, ErrCapability) {
		t.Fatal("unauthenticated reader", err)
	}
	if _, err = s.VerifyFollowerRelayCapability(verified, token, strings.Repeat("1", 64)); !errors.Is(err, ErrCapability) {
		t.Fatal("wrong resource", err)
	}
	r.policy.AppliedTransport = "Direct"
	if _, err = issue(admitted); !errors.Is(err, ErrCapability) {
		t.Fatal("unapplied Relay minted", err)
	}
	if _, err = s.VerifyFollowerRelayCapability(verified, token, resource); err != nil {
		t.Fatal("already-issued grant did not drain", err)
	}
	r.current.Generation++
	if _, err = issue(admitted); !errors.Is(err, ErrCapability) {
		t.Fatal("stale ingress minted", err)
	}
	r.relation.State = "revoked"
	if _, err = s.VerifyFollowerRelayCapability(verified, token, resource); !errors.Is(err, ErrCapability) {
		t.Fatal("revoked relationship accepted", err)
	}
}
