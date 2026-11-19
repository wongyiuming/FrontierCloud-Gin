package node

import (
	"context"
	"net/url"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// ConfigureSelectedAdminOrigin is startup-only and is sourced solely from the
// validated Master management configuration, never ingress/control addresses.
func (s *Service) ConfigureSelectedAdminOrigin(ctx context.Context, origin string) error {
	if s == nil || s.repo == nil || ctx == nil {
		return store.ErrNodeState
	}
	identity, err := s.repo.ReadIdentity(ctx)
	canonical, e := MasterEndpoint(origin)
	u, parseErr := url.Parse(origin)
	if err != nil || identity.Role != "Master" || e != nil || parseErr != nil || u.Port() != "" || canonical != origin {
		return store.ErrNodeState
	}
	s.masterAdminOrigin = canonical
	return nil
}

// SignSelectedAdminOrigin must be called only after the existing control API
// authenticates relation. The proof is tied to one random Owner challenge and
// the exact currently paired identities. It cannot itself authorize uploads.
func (s *Service) SignSelectedAdminOrigin(ctx context.Context, relation store.Relationship, challenge string) (Envelope, error) {
	if s == nil || s.repo == nil || s.identity == nil || ctx == nil || ctx.Err() != nil || !ValidIdentifier(challenge) {
		return Envelope{}, ErrCapability
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" || s.masterAdminOrigin == "" {
		return Envelope{}, ErrCapability
	}
	current, err := s.repo.Relationship(ctx, relation.ID)
	if err != nil || current.State != "active" || current.Direction != "downstream" || current.Protocol != protocol.Version || current.PeerID != relation.PeerID || current.Credential == "" || current.PublicKey == "" || current.CreatedAt <= 0 || opaqueRelationshipBinding(current) != opaqueRelationshipBinding(relation) {
		return Envelope{}, ErrCapability
	}
	now := time.Now().Unix()
	payload := map[string]any{"kind": "selected-admin-origin-v1", "master_id": identity.ID, "owner_id": current.PeerID, "relationship_id": current.ID, "nonce": challenge, "origin": s.masterAdminOrigin, "issued_at": now, "expires_at": now + 5}
	signed, err := s.identity.signed(identity, payload)
	if err != nil {
		return Envelope{}, ErrCapability
	}
	afterIdentity, err := s.repo.ReadIdentity(ctx)
	if err != nil || afterIdentity != identity {
		return Envelope{}, ErrCapability
	}
	afterRelation, err := s.repo.Relationship(ctx, relation.ID)
	if err != nil || afterRelation.State != "active" || afterRelation.Direction != "downstream" || afterRelation.Protocol != protocol.Version || opaqueRelationshipBinding(afterRelation) != opaqueRelationshipBinding(current) || ctx.Err() != nil {
		return Envelope{}, ErrCapability
	}
	return signed, nil
}

// FreshSelectedAdminOrigin does not cache. Unreachable Master, stale signature,
// replay, changed pairing and malformed origins all fail closed. A successful
// result is only a point-in-time proof; it is not instantaneous revocation.
func (s *Service) FreshSelectedAdminOrigin(ctx context.Context, relationshipID string) (string, error) {
	if s == nil || s.repo == nil || s.identity == nil || s.transport == nil || ctx == nil || ctx.Err() != nil {
		return "", ErrCapability
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Follower" {
		return "", ErrCapability
	}
	if relationshipID == "" {
		all, e := s.repo.Relationships(ctx, false)
		if e != nil {
			return "", ErrCapability
		}
		for _, r := range all {
			if r.Direction == "upstream" && r.State == "active" {
				if relationshipID != "" {
					return "", ErrCapability
				}
				relationshipID = r.ID
			}
		}
	}
	relation, err := s.repo.Relationship(ctx, relationshipID)
	if err != nil || relation.Direction != "upstream" || relation.State != "active" || relation.Protocol != protocol.Version || relation.PublicKey == "" || relation.Credential == "" || relation.CreatedAt <= 0 {
		return "", ErrCapability
	}
	challenge, err := randomNodeID()
	if err != nil {
		return "", ErrCapability
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	value, err := s.Call(bounded, relation, "/internal/v1/selected-admin-origin", map[string]any{"challenge": challenge})
	if err != nil {
		return "", ErrCapability
	}
	signed, err := envelope(value)
	if err != nil || protocol.Verify(relation.PublicKey, signed.Payload, signed.Signature) != nil {
		return "", ErrCapability
	}
	p := signed.Payload
	issued, iok := intField(p, "issued_at")
	expires, eok := intField(p, "expires_at")
	now := time.Now().Unix()
	origin := textField(p, "origin")
	canonical, e := MasterEndpoint(origin)
	u, parseErr := url.Parse(origin)
	// The unique challenge and three-second local context bound freshness
	// independently of clock synchronization; tolerate modest clock skew.
	if !iok || !eok || issued <= 0 || expires <= issued || expires-issued != 5 || issued-now > 30 || now-expires > 30 || textField(p, "kind") != "selected-admin-origin-v1" || textField(p, "master_id") != relation.PeerID || textField(p, "owner_id") != identity.ID || textField(p, "relationship_id") != relation.ID || textField(p, "nonce") != challenge || e != nil || parseErr != nil || u.Port() != "" || canonical != origin {
		return "", ErrCapability
	}
	currentIdentity, err := s.repo.ReadIdentity(bounded)
	if err != nil || currentIdentity != identity {
		return "", ErrCapability
	}
	current, err := s.repo.Relationship(bounded, relation.ID)
	if err != nil || current.State != "active" || current.Direction != "upstream" || current.Protocol != protocol.Version || opaqueRelationshipBinding(current) != opaqueRelationshipBinding(relation) || bounded.Err() != nil {
		return "", ErrCapability
	}
	return origin, nil
}
