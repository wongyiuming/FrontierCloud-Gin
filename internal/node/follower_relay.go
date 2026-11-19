package node

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// FollowerRelayClaim is a Master-signed browser-to-Master relay grant. It is
// deliberately not an owner capability: possession cannot authorize a direct
// read from the storage node or reveal the paired relationship credential.
type FollowerRelayClaim struct {
	MasterDirectClaim
	OwnerID        string `json:"owner_id"`
	RelationshipID string `json:"relationship_id"`
}

func (c FollowerRelayClaim) signedPayload() map[string]any {
	payload := c.MasterDirectClaim.signedPayload()
	payload["owner_id"], payload["relationship_id"] = c.OwnerID, c.RelationshipID
	return payload
}

func validFollowerRelayClaim(c FollowerRelayClaim, now int64) bool {
	if c.Kind != "follower-relay-read" && c.Kind != "opaque-follower-relay-read" && c.Kind != "opaque-follower-local-relay-read" || c.ResourceOrigin != c.PublicOrigin || !ValidIdentifier(c.OwnerID) || !ValidIdentifier(c.RelationshipID) || c.OwnerID == c.MasterID || c.OwnerID == c.IngressID {
		return false
	}
	if c.Kind == "opaque-follower-local-relay-read" {
		return c.Version == 1 && ValidIdentifier(c.MasterID) && c.IngressID == c.MasterID && c.Generation > 0 && c.PolicyRevision > 0 && validMasterDirectOrigin(c.PublicOrigin) && resourceIdentifier.MatchString(c.ResourceID) && c.ObjectID == c.ResourceID && resourceIdentifier.MatchString(c.Revision) && resourceIdentifier.MatchString(c.Descriptor) && ValidIdentifier(c.SessionID) && now > 0 && c.ExpiresAt > now && c.ExpiresAt-now <= protocol.TokenSeconds
	}
	copy := c.MasterDirectClaim
	copy.Kind = "master-direct-read"
	return validMasterDirectClaim(copy, now)
}

// IssueFollowerRelayCapability requires a live ingress admission and a live
// browser session. Its caller must already check visibility, exact placement,
// object revision and encryption descriptor while holding the media fence.
func (s *Service) IssueFollowerRelayCapability(ctx context.Context, relationshipID, ownerID, resourceID, objectID, revision, descriptor string) (string, error) {
	return s.issueFollowerRelayCapability(ctx, relationshipID, ownerID, resourceID, objectID, revision, descriptor, "follower-relay-read")
}

// IssueOpaqueFollowerRelayCapability never carries historical media IDs.
// The caller has already authorized the matching tree placement under lease.
func (s *Service) IssueOpaqueFollowerRelayCapability(ctx context.Context, relationshipID, ownerID, alias, revision, descriptor string) (string, error) {
	prerequisite, ok := store.IngressPrerequisiteFromContext(ctx)
	if s == nil || s.repo == nil || !ok || prerequisite.Check(ctx) != nil || !resourceIdentifier.MatchString(alias) {
		return "", ErrCapability
	}
	relation, err := s.repo.Relationship(ctx, relationshipID)
	if err != nil || s.VerifyFollowerOpaqueReadiness(ctx, relation, relation.Endpoint) != nil {
		return "", ErrCapability
	}
	token, err := s.issueFollowerRelayCapability(ctx, relationshipID, ownerID, alias, alias, revision, descriptor, "opaque-follower-relay-read")
	if err != nil || prerequisite.Check(ctx) != nil {
		return "", ErrCapability
	}
	return token, nil
}

func (s *Service) issueFollowerRelayCapability(ctx context.Context, relationshipID, ownerID, resourceID, objectID, revision, descriptor, kind string) (string, error) {
	if s == nil || s.repo == nil || s.identity == nil || s.identity.vault == nil || !network.HasActivePublicAdmission(ctx) {
		return "", ErrCapability
	}
	assertion, local, ok := network.PublicIngressIdentityFromContext(ctx)
	authority := mediacrypto.DirectSessionFromContext(ctx)
	_, sessionID, sessionExpiry, sessionValid := authority.Values()
	if !ok || !sessionValid || local && kind != "opaque-follower-relay-read" {
		return "", ErrCapability
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" || local != (assertion.NodeID == identity.ID) {
		return "", ErrCapability
	}
	if local {
		kind = "opaque-follower-local-relay-read"
	}
	relation, err := s.repo.Relationship(ctx, relationshipID)
	if err != nil || relation.ID != relationshipID || relation.PeerID != ownerID || relation.State != "active" || relation.Direction != "downstream" || relation.Protocol != protocol.Version {
		return "", ErrCapability
	}
	// A durable receipt alone is not evidence that this runtime still has a
	// functioning relay path after restart or a deployment change.
	if s.nativeTransportReady == nil || s.nativeTransportReady(ctx, relation, "Relay") != nil {
		return "", ErrCapability
	}
	repo, ok := s.repo.(store.PublicRoutingRepository)
	if !ok {
		return "", ErrCapability
	}
	current, err := repo.PublicIngress(ctx)
	if err != nil || current.NodeID != assertion.NodeID || current.Generation != assertion.Generation || current.PublicOrigin != assertion.PublicOrigin {
		return "", ErrCapability
	}
	policy, err := repo.NativeTransport(ctx, ownerID)
	if err != nil || policy.MemberID != ownerID || policy.ConfiguredTransport != "Relay" || policy.AppliedTransport != "Relay" || policy.State != "applied" || policy.Revision < 1 {
		return "", ErrCapability
	}
	now := time.Now().Unix()
	claim := FollowerRelayClaim{MasterDirectClaim: MasterDirectClaim{Kind: kind, Version: 1, MasterID: identity.ID, IngressID: assertion.NodeID, Generation: assertion.Generation, PublicOrigin: assertion.PublicOrigin, ResourceOrigin: assertion.PublicOrigin, ResourceID: resourceID, ObjectID: objectID, Revision: revision, Descriptor: descriptor, SessionID: sessionID, PolicyRevision: policy.Revision, ExpiresAt: min(now+protocol.TokenSeconds, sessionExpiry)}, OwnerID: ownerID, RelationshipID: relationshipID}
	if !validFollowerRelayClaim(claim, now) {
		return "", ErrCapability
	}
	private, err := s.identity.vault.Unseal(identity.PrivateKey)
	if err != nil {
		return "", ErrCapability
	}
	signature, err := protocol.Sign(private, claim.signedPayload())
	if _, _, _, alive := authority.Values(); err != nil || !alive || !network.HasActivePublicAdmission(ctx) || s.nativeTransportReady == nil || s.nativeTransportReady(ctx, relation, "Relay") != nil {
		return "", ErrCapability
	}
	raw, err := json.Marshal(claim)
	if err != nil {
		return "", ErrCapability
	}
	return protocol.Encode(raw) + "." + signature, nil
}

// VerifyFollowerRelayCapability is for the authenticated Master reader only.
// The caller additionally checks the live session, visibility, placement and
// descriptor before opening the owner's stream. Existing tickets can drain
// after a policy edit; current ingress authentication is checked per request.
func (s *Service) VerifyFollowerRelayCapability(ctx context.Context, token, resourceID string) (FollowerRelayClaim, error) {
	return s.verifyFollowerRelayCapability(ctx, token, resourceID, "follower-relay-read")
}

func (s *Service) VerifyOpaqueFollowerRelayCapability(ctx context.Context, token, alias string) (FollowerRelayClaim, error) {
	return s.verifyFollowerRelayCapability(ctx, token, alias, "opaque-follower-relay-read")
}

func (s *Service) verifyFollowerRelayCapability(ctx context.Context, token, resourceID, kind string) (FollowerRelayClaim, error) {
	var claim FollowerRelayClaim
	assertion, local, ok := network.PublicIngressIdentityFromContext(ctx)
	if s == nil || s.repo == nil || s.identity == nil || s.identity.vault == nil || !ok || len(token) > 4096 {
		return claim, ErrCapability
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return claim, ErrCapability
	}
	raw, err := protocol.Decode(parts[0])
	if err != nil {
		return claim, ErrCapability
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&claim) != nil || decoder.Decode(new(any)) != io.EOF {
		return FollowerRelayClaim{}, ErrCapability
	}
	if local {
		if kind != "opaque-follower-relay-read" {
			return FollowerRelayClaim{}, ErrCapability
		}
		kind = "opaque-follower-local-relay-read"
	}
	canonical, err := json.Marshal(claim)
	if err != nil || !bytes.Equal(canonical, raw) || !validFollowerRelayClaim(claim, time.Now().Unix()) || claim.Kind != kind || (kind == "opaque-follower-relay-read" || kind == "opaque-follower-local-relay-read") && claim.ObjectID != claim.ResourceID || claim.ResourceID != resourceID || claim.IngressID != assertion.NodeID || claim.Generation != assertion.Generation || claim.PublicOrigin != assertion.PublicOrigin {
		return FollowerRelayClaim{}, ErrCapability
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" || identity.ID != claim.MasterID {
		return FollowerRelayClaim{}, ErrCapability
	}
	if local {
		routing, ok := s.repo.(store.PublicRoutingRepository)
		if !ok {
			return FollowerRelayClaim{}, ErrCapability
		}
		current, err := routing.PublicIngress(ctx)
		if err != nil || current.NodeID != identity.ID || current.Generation != assertion.Generation || current.PublicOrigin != assertion.PublicOrigin {
			return FollowerRelayClaim{}, ErrCapability
		}
	}
	relation, err := s.repo.Relationship(ctx, claim.RelationshipID)
	if err != nil || relation.ID != claim.RelationshipID || relation.PeerID != claim.OwnerID || relation.State != "active" || relation.Direction != "downstream" || relation.Protocol != protocol.Version {
		return FollowerRelayClaim{}, ErrCapability
	}
	public, err := s.public(identity)
	if err != nil || protocol.Verify(public, claim.signedPayload(), parts[1]) != nil {
		return FollowerRelayClaim{}, ErrCapability
	}
	return claim, nil
}

// FollowerRelayOwnerCapability derives the server-to-owner bearer from an
// existing relay grant. Callers must first recheck visibility and placement;
// they must never return this bearer to the ingress or
// browser. Its expiry cannot exceed the original grant, including when a read
// admitted before an ingress switch is allowed to drain.
func (s *Service) FollowerRelayOwnerCapability(ctx context.Context, relayToken, resourceID string, size int64, meta *mediacrypto.Metadata, sessions *mediacrypto.Manager) (string, error) {
	if meta == nil {
		return "", ErrCapability
	}
	return s.followerRelayOwnerCapability(ctx, relayToken, resourceID, size, meta, "", sessions)
}

func (s *Service) followerRelayOwnerPlainCapability(ctx context.Context, relayToken, resourceID string, size int64, digest string, sessions *mediacrypto.Manager) (string, error) {
	if !resourceIdentifier.MatchString(digest) {
		return "", ErrCapability
	}
	return s.followerRelayOwnerCapability(ctx, relayToken, resourceID, size, nil, digest, sessions)
}

func (s *Service) followerRelayOwnerCapability(ctx context.Context, relayToken, resourceID string, size int64, meta *mediacrypto.Metadata, digest string, sessions *mediacrypto.Manager) (string, error) {
	claim, err := s.VerifyFollowerRelayCapability(ctx, relayToken, resourceID)
	if err != nil || sessions == nil || !sessions.CheckDirectSession(claim.SessionID) {
		return "", ErrCapability
	}
	descriptor, err := protocol.IngressMediaDescriptor(size, meta)
	if err != nil || descriptor != claim.Descriptor {
		return "", ErrCapability
	}
	relation, err := s.repo.Relationship(ctx, claim.RelationshipID)
	if err != nil {
		return "", ErrCapability
	}
	credential, err := s.identity.vault.Unseal(relation.Credential)
	if err != nil {
		return "", ErrCapability
	}
	now := time.Now().Unix()
	var token string
	if digest != "" {
		token, err = protocol.PlainIngressMediaToken(credential, relation.ID, claim.MasterID, claim.OwnerID, claim.ObjectID, claim.ResourceID, claim.IngressID, claim.PublicOrigin, claim.SessionID, claim.Generation, now, claim.ExpiresAt, size, digest)
	} else {
		token, err = protocol.IngressMediaToken(credential, relation.ID, claim.MasterID, claim.OwnerID, claim.ObjectID, claim.ResourceID, claim.IngressID, claim.PublicOrigin, claim.SessionID, claim.Generation, now, claim.ExpiresAt, size, meta)
	}
	if err != nil || !sessions.CheckDirectSession(claim.SessionID) {
		return "", ErrCapability
	}
	return token, nil
}
