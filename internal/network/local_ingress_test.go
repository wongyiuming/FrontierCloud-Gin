package network

import (
	"context"
	"strings"
	"testing"
)

func TestLocalPublicIngressRequiresLiveSeparateAdmission(t *testing.T) {
	value := LocalPublicIngress{NodeID: strings.Repeat("a", 32), Generation: 1, PublicOrigin: "https://master.example"}
	if _, err := WithLocalPublicIngress(context.Background(), value); err == nil {
		t.Fatal("local assertion accepted without admission")
	}
	ctx, admission := WithPublicAdmission(context.Background())
	local, err := WithLocalPublicIngress(ctx, value)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := LocalPublicIngressFromContext(local); !ok || got != value {
		t.Fatal("local admission state unavailable")
	}
	if _, ok := AuthenticatedIngressFromContext(local); ok {
		t.Fatal("local admission impersonated a peer")
	}
	peer, err := WithAuthenticatedIngress(ctx, AuthenticatedIngress{NodeID: value.NodeID, Generation: 1, PublicOrigin: value.PublicOrigin, ClientIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WithLocalPublicIngress(peer, value); err == nil {
		t.Fatal("peer assertion accepted as local")
	}
	admission.Abort()
	if _, ok := LocalPublicIngressFromContext(local); ok {
		t.Fatal("released admission retained local authority")
	}
}
