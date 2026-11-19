package node

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/publicproxy"
)

// PublicIngressSigner uses one existing paired relationship without exporting
// or persisting its unsealed credential. The Master verifier still checks that
// this node and generation are the currently active ingress on every request.
type PublicIngressSigner struct {
	service        *Service
	relationshipID string
}

func (s *Service) NewPublicIngressSigner(relationshipID string) (*PublicIngressSigner, error) {
	if s == nil || s.repo == nil || s.identity == nil || s.identity.vault == nil || !ValidIdentifier(relationshipID) {
		return nil, errors.New("invalid ingress signing configuration")
	}
	return &PublicIngressSigner{service: s, relationshipID: relationshipID}, nil
}

// SignPublicIngress signs only a validated versioned public proxy proof in its
// distinct protocol domain. It cannot sign arbitrary node control operations.
func (s *PublicIngressSigner) SignPublicIngress(ctx context.Context, masterOrigin string, data []byte) (http.Header, error) {
	fail := errors.New("ingress signing unavailable")
	if s == nil || s.service == nil {
		return nil, fail
	}
	proof, err := publicproxy.ValidateSigningProof(data)
	if err != nil || proof.MasterOrigin != masterOrigin {
		return nil, fail
	}
	identity, err := s.service.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Follower" || identity.ID != proof.IngressID {
		return nil, fail
	}
	rel, err := s.service.repo.Relationship(ctx, s.relationshipID)
	if err != nil || rel.Direction != "upstream" || rel.State != "active" || rel.Protocol != protocol.Version {
		return nil, fail
	}
	endpoint, err := Endpoint(rel.Endpoint)
	if err != nil || endpoint != masterOrigin {
		return nil, fail
	}
	credential, err := s.service.identity.vault.Unseal(rel.Credential)
	if err != nil {
		return nil, fail
	}
	headers, err := protocol.AuthHeaders(credential, rel.ID, http.MethodPost, publicproxy.ProofDomain, data, time.Now().Unix())
	if err != nil {
		return nil, fail
	}
	result := make(http.Header, len(headers))
	for name, value := range headers {
		result.Set(name, value)
	}
	return result, nil
}

// DialPublicIngress uses the same DNS and address admission as node control
// traffic and only dials the active upstream relationship's exact endpoint.
func (s *PublicIngressSigner) DialPublicIngress(ctx context.Context, network, address string) (net.Conn, error) {
	fail := errors.New("ingress connection unavailable")
	if s == nil || s.service == nil || network != "tcp" {
		return nil, fail
	}
	identity, err := s.service.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Follower" {
		return nil, fail
	}
	rel, err := s.service.repo.Relationship(ctx, s.relationshipID)
	if err != nil || rel.Direction != "upstream" || rel.State != "active" || rel.Protocol != protocol.Version {
		return nil, fail
	}
	endpoint, err := Endpoint(rel.Endpoint)
	if err != nil {
		return nil, fail
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fail
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	if address != net.JoinHostPort(parsed.Hostname(), port) {
		return nil, fail
	}
	connection, err := safeDial(ctx, network, address)
	if err != nil {
		return nil, fail
	}
	return connection, nil
}
