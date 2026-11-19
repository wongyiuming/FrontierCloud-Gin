package network

import (
	"context"
	"strings"
	"testing"
)

func TestLocalCatalogPreflightIsNotAdmissionOrPeerAuthority(t *testing.T) {
	value := LocalPublicIngress{NodeID: strings.Repeat("a", 32), Generation: 1, PublicOrigin: "https://public.test"}
	ctx, err := WithLocalCatalogPreflight(context.Background(), value)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := LocalCatalogPreflightFromContext(ctx); !ok || got != value {
		t.Fatal("preflight missing")
	}
	if HasActivePublicAdmission(ctx) {
		t.Fatal("preflight became admission")
	}
	if _, ok := LocalPublicIngressFromContext(ctx); ok {
		t.Fatal("preflight became local ingress authority")
	}
	if _, _, ok := PublicIngressIdentityFromContext(ctx); ok {
		t.Fatal("preflight became public resource authority")
	}
	called := false
	if present, registered := RegisterPublicAdmissionAbort(ctx, func() { called = true }); present || registered || called {
		t.Fatal("preflight registered authorization")
	}
	if _, err := WithLocalPublicIngress(ctx, value); err == nil {
		t.Fatal("preflight created admitted context")
	}
	active, admission := WithPublicAdmission(context.Background())
	defer admission.Abort()
	if _, err := WithLocalCatalogPreflight(active, value); err == nil {
		t.Fatal("preflight mixed with admission")
	}
	admission.Abort()
	if _, err := WithLocalCatalogPreflight(active, value); err == nil {
		t.Fatal("preflight mixed with ended admission")
	}
	decorated, another := WithPublicAdmission(ctx)
	defer another.Abort()
	if _, ok := LocalCatalogPreflightFromContext(decorated); ok {
		t.Fatal("admitted context retained preflight")
	}
	peer, err := WithAuthenticatedIngress(context.Background(), AuthenticatedIngress{NodeID: value.NodeID, Generation: 1, PublicOrigin: value.PublicOrigin, ClientIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WithLocalCatalogPreflight(peer, value); err == nil {
		t.Fatal("peer spoofed local preflight")
	}
}
