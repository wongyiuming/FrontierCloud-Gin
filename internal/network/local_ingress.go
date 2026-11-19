package network

import (
	"context"
	"errors"
	"net/url"
	"strings"
)

// LocalPublicIngress is process-local Master admission state. It is never
// derived from a request header and is distinct from an authenticated peer.
type LocalPublicIngress struct {
	NodeID       string
	Generation   int64
	PublicOrigin string
}

type localPublicIngressKey struct{}

// WithLocalPublicIngress is for the Master handler that already owns the
// current ingress lease and active admission. It grants no resource access.
func WithLocalPublicIngress(ctx context.Context, value LocalPublicIngress) (context.Context, error) {
	invalid := errors.New("invalid local public ingress context")
	if ctx == nil || !HasActivePublicAdmission(ctx) || len(value.NodeID) != 32 || value.Generation <= 0 {
		return nil, invalid
	}
	if _, peer := AuthenticatedIngressFromContext(ctx); peer {
		return nil, invalid
	}
	for _, c := range value.NodeID {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, invalid
		}
	}
	u, err := url.Parse(value.PublicOrigin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != value.PublicOrigin || u.Host != strings.ToLower(u.Host) {
		return nil, invalid
	}
	return context.WithValue(ctx, localPublicIngressKey{}, value), nil
}

func LocalPublicIngressFromContext(ctx context.Context) (LocalPublicIngress, bool) {
	if ctx == nil || !HasActivePublicAdmission(ctx) {
		return LocalPublicIngress{}, false
	}
	if _, peer := AuthenticatedIngressFromContext(ctx); peer {
		return LocalPublicIngress{}, false
	}
	value, ok := ctx.Value(localPublicIngressKey{}).(LocalPublicIngress)
	return value, ok
}

// PublicIngressIdentityFromContext extracts comparable routing identity while
// preserving whether it came from a verified peer or a distinct Master-local
// admission. It never creates an authenticated peer assertion.
func PublicIngressIdentityFromContext(ctx context.Context) (LocalPublicIngress, bool, bool) {
	if peer, ok := AuthenticatedIngressFromContext(ctx); ok {
		return LocalPublicIngress{NodeID: peer.NodeID, Generation: peer.Generation, PublicOrigin: peer.PublicOrigin}, false, true
	}
	if local, ok := LocalPublicIngressFromContext(ctx); ok {
		return local, true, true
	}
	return LocalPublicIngress{}, false, false
}
