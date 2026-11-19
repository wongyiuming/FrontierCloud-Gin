package network

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"strings"
)

// AuthenticatedIngress is an assertion verified by Master, not an HTTP header.
// Direct Master requests do not have this assertion.
type AuthenticatedIngress struct {
	NodeID       string
	Generation   int64
	PublicOrigin string
	ClientIP     string
}

type ingressContextKey struct{}

// WithAuthenticatedIngress must be called only after node authentication and
// authoritative current-ingress checks succeed while the state lease is held.
func WithAuthenticatedIngress(ctx context.Context, v AuthenticatedIngress) (context.Context, error) {
	invalid := errors.New("invalid authenticated ingress context")
	if ctx == nil || len(v.NodeID) != 32 || v.Generation <= 0 {
		return nil, invalid
	}
	for _, c := range v.NodeID {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, invalid
		}
	}
	u, err := url.Parse(v.PublicOrigin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != v.PublicOrigin || u.Host != strings.ToLower(u.Host) {
		return nil, invalid
	}
	ip, err := Normalize(v.ClientIP)
	address, addrErr := netip.ParseAddr(ip)
	if err != nil || ip != v.ClientIP || addrErr != nil || address.Unmap().IsUnspecified() {
		return nil, invalid
	}
	return context.WithValue(ctx, ingressContextKey{}, v), nil
}

func AuthenticatedIngressFromContext(ctx context.Context) (AuthenticatedIngress, bool) {
	if ctx == nil {
		return AuthenticatedIngress{}, false
	}
	v, ok := ctx.Value(ingressContextKey{}).(AuthenticatedIngress)
	return v, ok
}
