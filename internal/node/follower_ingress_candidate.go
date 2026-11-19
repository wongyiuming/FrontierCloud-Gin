package node

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

const peerIngressProxyCapability = protocol.PublicIngressProxyCapability

var ErrIngressEndpointUnprepared = errors.New("node ingress endpoint is not prepared")

func ValidateFollowerIngressOrigin(origin string) error {
	canonical, err := MasterEndpoint(origin)
	if err != nil || canonical != origin {
		return errors.New("canonical HTTPS ingress origin on port 443 required")
	}
	return nil
}

// ConfigureFollowerIngressCandidate is called at startup only after the peer
// proxy wrapper has been constructed. It advertises a candidate address, not
// an active ingress or proof of complete data-path readiness.
func (s *Service) ConfigureFollowerIngressCandidate(origin string) error {
	if s == nil || s.repo == nil {
		return store.ErrNodeState
	}
	identity, err := s.repo.ReadIdentity(context.Background())
	if err != nil || identity.Role != "Follower" {
		return store.ErrNodeState
	}
	if err := ValidateFollowerIngressOrigin(origin); err != nil {
		return err
	}
	if s.followerIngressOrigin != "" && s.followerIngressOrigin != origin {
		return errors.New("ingress candidate is startup-only")
	}
	s.followerIngressOrigin = origin
	return nil
}

func (s *Service) runtimeCapabilities() []string {
	features := protocol.AdvertisedCapabilities()
	if s != nil && s.plainReadProbe != nil {
		features = append(features, protocol.NativePlainProofCapability)
	}
	if s != nil && s.opaqueReadProbe != nil {
		features = append(features, protocol.NativeOpaqueProofCapability)
	}
	if s != nil && s.followerIngressOrigin != "" {
		features = append(features, peerIngressProxyCapability)
	}
	return features
}

// ObservedFollowerIngressCandidate reads only an active peer's fresh heartbeat.
// The observed address is independent of both its resource and control origin.
func (s *Service) ObservedFollowerIngressCandidate(ctx context.Context, relationshipID string) (string, error) {
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
	features, err := protocol.ReadCapabilities(relation.Summary)
	origin, ok := relation.Summary["public_ingress_candidate_origin"].(string)
	if err != nil || !slices.Contains(features, peerIngressProxyCapability) || !ok || ValidateFollowerIngressOrigin(origin) != nil {
		return "", ErrIngressEndpointUnprepared
	}
	return origin, nil
}

// VerifyFollowerIngressIdentity proves the candidate origin serves the paired
// Follower identity. Full proxy/data-path readiness and explicit selection are
// separate checks; this method never commits an ingress change.
func (s *Service) VerifyFollowerIngressIdentity(ctx context.Context, relationshipID string) (string, error) {
	if s == nil || s.transport == nil {
		return "", store.ErrNodeState
	}
	origin, err := s.ObservedFollowerIngressCandidate(ctx, relationshipID)
	if err != nil {
		return "", err
	}
	relation, err := s.repo.Relationship(ctx, relationshipID)
	if err != nil || relation.State != "active" || relation.Direction != "downstream" {
		return "", store.ErrNodeState
	}
	payload, err := s.verifyFollowerIdentityAt(ctx, relation, origin)
	if err != nil {
		return "", err
	}
	features, err := protocol.ReadCapabilities(payload)
	if err != nil || !slices.Contains(features, peerIngressProxyCapability) {
		return "", store.ErrNodeState
	}
	again, err := s.ObservedFollowerIngressCandidate(ctx, relationshipID)
	if err != nil || again != origin {
		return "", store.ErrNodeState
	}
	current, err := s.repo.Relationship(ctx, relationshipID)
	if err != nil || current.State != "active" || current.Direction != "downstream" || current.PeerID != relation.PeerID || current.PublicKey != relation.PublicKey || current.Endpoint != relation.Endpoint || current.Credential != relation.Credential || current.CreatedAt != relation.CreatedAt {
		return "", store.ErrNodeState
	}
	return origin, nil
}

// VerifyFollowerIngressProxy verifies the candidate's public identity and a
// round trip from the paired node through the Master's trusted proxy edge.
// It is a preflight only: a subsequent selection must recheck the relationship,
// origin and generation under its exclusive commit fence.
func (s *Service) VerifyFollowerIngressProxy(ctx context.Context, relationshipID string) (string, error) {
	origin, _, _, err := s.verifyFollowerIngressProxyEvidence(ctx, relationshipID)
	return origin, err
}

// The private evidence remains in Master memory for final re-verification.
func (s *Service) verifyFollowerIngressProxyEvidence(ctx context.Context, relationshipID string) (origin string, challenge string, signed Envelope, err error) {
	origin, err = s.VerifyFollowerIngressIdentity(ctx, relationshipID)
	if err != nil {
		return "", "", Envelope{}, err
	}
	relation, err := s.repo.Relationship(ctx, relationshipID)
	if err != nil || relation.State != "active" || relation.Direction != "downstream" {
		return "", "", Envelope{}, store.ErrNodeState
	}
	if err := s.probeFollowerIngressListener(ctx, relation, origin); err != nil {
		return "", "", Envelope{}, err
	}
	if err := s.VerifyFollowerPlainReadiness(ctx, relation, origin); err != nil {
		return "", "", Envelope{}, store.ErrNodeState
	}
	challenge, err = randomNodeID()
	if err != nil {
		return "", "", Envelope{}, err
	}
	value, err := s.Call(ctx, relation, "/internal/v1/public-ingress-probe", map[string]any{"challenge": challenge})
	if err != nil {
		return "", "", Envelope{}, store.ErrNodeState
	}
	signed, err = envelope(value)
	if err != nil {
		return "", "", Envelope{}, store.ErrNodeState
	}
	payload, err := validateFollowerIdentityEnvelope(relation, challenge, signed)
	if err != nil {
		return "", "", Envelope{}, err
	}
	features, err := protocol.ReadCapabilities(payload)
	if err != nil || !slices.Contains(features, peerIngressProxyCapability) {
		return "", "", Envelope{}, store.ErrNodeState
	}
	again, err := s.ObservedFollowerIngressCandidate(ctx, relationshipID)
	if err != nil || again != origin {
		return "", "", Envelope{}, store.ErrNodeState
	}
	current, err := s.repo.Relationship(ctx, relationshipID)
	if err != nil || current.State != "active" || current.Direction != "downstream" || current.PeerID != relation.PeerID || current.PublicKey != relation.PublicKey || current.Endpoint != relation.Endpoint || current.Credential != relation.Credential || current.CreatedAt != relation.CreatedAt {
		return "", "", Envelope{}, store.ErrNodeState
	}
	return origin, challenge, signed, nil
}

// CheckPublicIngressCandidate is an administrator-triggered network preflight.
// It never changes the current ingress, owner placement or transport policy.
func (s *Service) CheckPublicIngressCandidate(ctx context.Context, memberID string) (string, error) {
	if s == nil || s.repo == nil || ctx == nil || !ValidIdentifier(memberID) {
		return "", store.ErrNodeState
	}
	tree := s.opaqueIngressTree.Load()
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" || identity.ID == memberID {
		return "", store.ErrNodeState
	}
	relations, err := s.repo.Relationships(ctx, false)
	if err != nil {
		return "", err
	}
	var relation store.Relationship
	for _, candidate := range relations {
		if candidate.PeerID == memberID && candidate.Direction == "downstream" && candidate.State == "active" {
			if relation.ID != "" {
				return "", store.ErrNodeState
			}
			relation = candidate
		}
	}
	if relation.ID == "" {
		return "", store.ErrNodeState
	}
	started := time.Now()
	if tree != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, started.Add(time.Duration(protocol.TokenSeconds)*time.Second))
		defer cancel()
	}
	origin, challenge, proof, err := s.verifyFollowerIngressProxyEvidence(ctx, relation.ID)
	if err != nil {
		return "", err
	}
	if tree == nil {
		if s.opaqueIngressTree.Load() != nil {
			return "", store.ErrNodeState
		}
		return origin, nil
	}
	if s.ingressSelectionReady == nil {
		return "", store.ErrNodeState
	}
	opaqueChallenge, opaqueProof, err := s.verifyFollowerOpaqueReadinessEvidence(ctx, relation, origin)
	if err != nil {
		return "", err
	}
	// Finish the peer I/O before taking the Owner and tree read leases. This
	// check does not acquire the ingress writer or authorize a later selection.
	ready, err := s.ingressSelectionReady(ctx)
	if validPrerequisiteLease(ready) {
		defer ready.Release()
	}
	composite, ok := ready.(*CatalogPrerequisite)
	if err != nil || !ok || composite == nil || composite.treeStore != tree || s.opaqueIngressTree.Load() != tree {
		return "", store.ErrNodeState
	}
	current, err := s.repo.Relationship(ctx, relation.ID)
	observed, observedErr := s.ObservedFollowerIngressCandidate(ctx, relation.ID)
	now := time.Now()
	if err != nil || observedErr != nil || observed != origin || !sameCatalogRelationship(relation, current) ||
		validateSelectionProbe(current, challenge, proof, started, now) != nil || validateSelectionOpaqueProbe(current, opaqueChallenge, opaqueProof, started, now) != nil || composite.Check(ctx) != nil {
		return "", store.ErrNodeState
	}
	return origin, nil
}
