package node

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

var ErrResourceEndpointUnprepared = errors.New("node Direct resource endpoint is not prepared")

// ValidateFollowerResourceOrigin validates the independent HTTPS address.
func ValidateFollowerResourceOrigin(origin string) error {
	canonical, err := MasterEndpoint(origin)
	if err != nil || canonical != origin {
		return errors.New("canonical HTTPS resource origin on port 443 required")
	}
	return nil
}

// ConfigureFollowerResourceOrigin is startup-only deployment configuration.
// Advertising this address proves neither reachability nor Direct readiness.
func (s *Service) ConfigureFollowerResourceOrigin(origin string) error {
	if s == nil || s.repo == nil {
		return errors.New("resource origin requires a Follower identity")
	}
	identity, err := s.repo.ReadIdentity(context.Background())
	if err != nil || identity.Role != "Follower" {
		return errors.New("resource origin requires a Follower identity")
	}
	if err := ValidateFollowerResourceOrigin(origin); err != nil {
		return err
	}
	if s.followerResourceOrigin != "" && s.followerResourceOrigin != origin {
		return errors.New("resource origin is startup-only")
	}
	s.followerResourceOrigin = origin
	return nil
}

// ObservedFollowerResourceOrigin returns only the last authenticated, fresh
// heartbeat advertisement. It is not a capability or a readiness decision;
// callers must independently authenticate the endpoint and policy revision.
func (s *Service) ObservedFollowerResourceOrigin(ctx context.Context, relationshipID string) (string, error) {
	if s == nil || s.repo == nil {
		return "", store.ErrNodeState
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" {
		return "", store.ErrNodeState
	}
	relation, err := s.repo.Relationship(ctx, relationshipID)
	if err != nil || relation.State != "active" || relation.Direction != "downstream" || relation.Protocol != protocol.Version || relation.Status != "online" || relation.LastHeartbeat <= 0 || time.Now().Unix()-relation.LastHeartbeat < 0 || time.Now().Unix()-relation.LastHeartbeat >= 120 {
		return "", store.ErrNodeState
	}
	origin, ok := relation.Summary["native_resource_origin"].(string)
	canonical, checkErr := MasterEndpoint(origin)
	if !ok || checkErr != nil || canonical != origin {
		return "", ErrResourceEndpointUnprepared
	}
	return canonical, nil
}

// VerifyFollowerResourceIdentity contacts only the paired node's advertised
// origin over the control transport's verified TLS client. The challenge is
// signed by the paired node key and still names the separate control endpoint.
// This proves identity at that origin, not media-route readiness or policy.
func (s *Service) VerifyFollowerResourceIdentity(ctx context.Context, relationshipID string) (string, error) {
	if s == nil || s.transport == nil {
		return "", store.ErrNodeState
	}
	origin, err := s.ObservedFollowerResourceOrigin(ctx, relationshipID)
	if err != nil {
		return "", err
	}
	relation, err := s.repo.Relationship(ctx, relationshipID)
	if err != nil || relation.State != "active" || relation.Direction != "downstream" {
		return "", store.ErrNodeState
	}
	if _, err = s.verifyFollowerIdentityAt(ctx, relation, origin); err != nil {
		return "", err
	}
	// A replaced advertisement or relationship must not validate a stale probe.
	again, err := s.ObservedFollowerResourceOrigin(ctx, relationshipID)
	if err != nil || again != origin {
		return "", store.ErrNodeState
	}
	current, err := s.repo.Relationship(ctx, relationshipID)
	if err != nil || current.State != "active" || current.Direction != "downstream" || current.PeerID != relation.PeerID || current.PublicKey != relation.PublicKey || current.Endpoint != relation.Endpoint || current.Credential != relation.Credential || current.CreatedAt != relation.CreatedAt {
		return "", store.ErrNodeState
	}
	return origin, nil
}

func (s *Service) verifyFollowerIdentityAt(ctx context.Context, relation store.Relationship, origin string) (map[string]any, error) {
	challenge, err := randomNodeID()
	if err != nil {
		return nil, err
	}
	value, err := s.transport.Request(ctx, origin, "/internal/v1/identity?"+url.Values{"challenge": {challenge}}.Encode(), "GET", nil, "", "")
	if err != nil {
		return nil, err
	}
	signed, err := envelope(value)
	if err != nil {
		return nil, store.ErrNodeState
	}
	return validateFollowerIdentityEnvelope(relation, challenge, signed)
}

func validateFollowerIdentityEnvelope(relation store.Relationship, challenge string, signed Envelope) (map[string]any, error) {
	if protocol.Verify(relation.PublicKey, signed.Payload, signed.Signature) != nil {
		return nil, store.ErrNodeState
	}
	payload := signed.Payload
	version, ok := intField(payload, "protocol")
	endpoint, endpointErr := Endpoint(textField(payload, "endpoint"))
	expectedEndpoint, expectedErr := Endpoint(relation.Endpoint)
	if !ok || version != protocol.Version || endpointErr != nil || expectedErr != nil || endpoint != expectedEndpoint || textField(payload, "node_id") != relation.PeerID || textField(payload, "public_key") != relation.PublicKey || textField(payload, "role") != "Follower" || textField(payload, "challenge") != challenge {
		return nil, store.ErrNodeState
	}
	if _, err := protocol.ReadCapabilities(payload); err != nil {
		return nil, store.ErrNodeState
	}
	return payload, nil
}
