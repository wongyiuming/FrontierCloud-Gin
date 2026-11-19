package node

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestMasterLocalLyricGrantIsDistinctAndBoundToIngress(t *testing.T) {
	ctx := context.Background()
	s, db := testNode(t, "Master", "https://master.test", nil)
	identity, err := s.IdentityState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	repo := &masterDirectFixtureRepo{NodeRepository: db.Nodes(), PublicRoutingRepository: db.Nodes().(store.PublicRoutingRepository),
		current: store.PublicIngress{NodeID: identity.ID, PublicOrigin: "https://master.test", Generation: 9}}
	s.repo = repo
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
	admitted, admission := network.WithPublicAdmission(ctx)
	defer admission.Abort()
	local, err := network.WithLocalPublicIngress(admitted, network.LocalPublicIngress{NodeID: identity.ID, PublicOrigin: repo.current.PublicOrigin, Generation: repo.current.Generation})
	if err != nil {
		t.Fatal(err)
	}
	local, err = manager.WithDirectSession(local, binding, session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	alias, track, revision, descriptor := strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64)
	token, err := s.IssueMasterLocalLyricCapability(local, alias, track, revision, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := s.VerifyMasterLocalLyricCapability(local, token, alias)
	if err != nil || claim.IngressID != identity.ID || claim.ObjectID != track || claim.Generation != 9 || claim.SessionID != session.SessionID {
		t.Fatalf("Local claim: %+v %v", claim, err)
	}
	if _, ok := network.AuthenticatedIngressFromContext(local); ok {
		t.Fatal("Local admission impersonated a peer")
	}
	mediaToken, err := s.IssueMasterLocalMediaCapability(local, alias, revision, descriptor, session.ExpiresAt)
	if err != nil {
		t.Fatal("Local media token", err)
	}
	if _, err := s.VerifyMasterLocalMediaCapability(local, mediaToken, alias); err != nil {
		t.Fatal("Local media verification", err)
	}
	if _, err := s.VerifyMasterLocalMediaCapability(local, token, alias); !errors.Is(err, ErrCapability) {
		t.Fatal("lyric token accepted as Local media", err)
	}
	if _, err := s.VerifyMasterLocalLyricCapability(local, mediaToken, alias); !errors.Is(err, ErrCapability) {
		t.Fatal("media token accepted as Local lyric", err)
	}
	if _, err := s.VerifyMasterDirectCapability(local, mediaToken, "https://master.test", alias); !errors.Is(err, ErrCapability) {
		t.Fatal("Local media token accepted as Direct", err)
	}
	if _, err := s.VerifyMasterRelayCapability(local, mediaToken, alias); !errors.Is(err, ErrCapability) {
		t.Fatal("Local media token accepted as Relay", err)
	}
	if _, err := s.VerifyMasterDirectCapability(local, token, "https://master.test", alias); !errors.Is(err, ErrCapability) {
		t.Fatal("Local token accepted as Direct", err)
	}
	if _, err := s.VerifyMasterRelayCapability(local, token, alias); !errors.Is(err, ErrCapability) {
		t.Fatal("Local token accepted as Relay", err)
	}
	if _, err := s.VerifyMasterLocalLyricCapability(ctx, token, alias); !errors.Is(err, ErrCapability) {
		t.Fatal("Local token accepted without admission", err)
	}
	repo.current.Generation++
	if _, err := s.VerifyMasterLocalLyricCapability(local, token, alias); !errors.Is(err, ErrCapability) {
		t.Fatal("old Local token opened after ingress selection", err)
	}
	if _, err := s.VerifyMasterLocalMediaCapability(local, mediaToken, alias); !errors.Is(err, ErrCapability) {
		t.Fatal("old Local media token opened after ingress selection", err)
	}
	if _, err := s.IssueMasterLocalLyricCapability(local, alias, track, revision, descriptor); !errors.Is(err, ErrCapability) {
		t.Fatal("old admission minted Local grant", err)
	}
	repo.current.Generation--
	manager.RevokeBinding(binding)
	if _, err := s.IssueMasterLocalLyricCapability(local, alias, track, revision, descriptor); !errors.Is(err, ErrCapability) {
		t.Fatal("revoked session minted Local grant", err)
	}
}
