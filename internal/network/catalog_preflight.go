package network

import (
	"context"
	"errors"
	"net/url"
	"strings"
)

type localCatalogPreflightKey struct{}

// WithLocalCatalogPreflight records a trusted Master-local presentation
// snapshot for private, read-only catalog preparation. It intentionally does
// not create PublicAdmission and is never an authority to issue a capability.
// Only the local handler that has verified TLS, Host and the initial selected
// Master snapshot may use it; no HTTP header can construct this context.
func WithLocalCatalogPreflight(ctx context.Context, value LocalPublicIngress) (context.Context, error) {
	bad := errors.New("invalid catalog preflight")
	if ctx == nil || ctx.Value(publicAdmissionKey{}) != nil || len(value.NodeID) != 32 || value.Generation <= 0 {
		return nil, bad
	}
	if _, peer := AuthenticatedIngressFromContext(ctx); peer {
		return nil, bad
	}
	for _, c := range value.NodeID {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, bad
		}
	}
	u, err := url.Parse(value.PublicOrigin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != value.PublicOrigin || u.Host != strings.ToLower(u.Host) {
		return nil, bad
	}
	return context.WithValue(ctx, localCatalogPreflightKey{}, value), nil
}

func LocalCatalogPreflightFromContext(ctx context.Context) (LocalPublicIngress, bool) {
	if ctx == nil || ctx.Value(publicAdmissionKey{}) != nil {
		return LocalPublicIngress{}, false
	}
	if _, peer := AuthenticatedIngressFromContext(ctx); peer {
		return LocalPublicIngress{}, false
	}
	value, ok := ctx.Value(localCatalogPreflightKey{}).(LocalPublicIngress)
	return value, ok
}
