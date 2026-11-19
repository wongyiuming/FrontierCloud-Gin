package node

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// MediaFollowerDirectCapability only issues after the current, explicitly
// applied Direct policy, runtime readiness and independently verified public
// resource origin all agree. The returned bearer never contains a media key.
func (s *Service) MediaFollowerDirectCapability(ctx context.Context, relationshipID, owner, objectID, resourceID string, size, sessionExpiresAt int64, meta *mediacrypto.Metadata) (string, string, error) {
	return s.mediaFollowerDirectCapability(ctx, relationshipID, owner, objectID, resourceID, size, sessionExpiresAt, meta, "", "")
}

func (s *Service) MediaFollowerDirectPlainCapability(ctx context.Context, relationshipID, owner, objectID, resourceID string, size, sessionExpiresAt int64, digest string) (string, string, error) {
	if !resourceIdentifier.MatchString(digest) {
		return "", "", ErrCapability
	}
	return s.mediaFollowerDirectCapability(ctx, relationshipID, owner, objectID, resourceID, size, sessionExpiresAt, nil, digest, "")
}

// MediaFollowerDirectOpaqueCapability additionally requires v5 owner proof.
// The caller must resolve the blob under the active encrypted-tree lease.
func (s *Service) MediaFollowerDirectOpaqueCapability(ctx context.Context, relationshipID, owner, alias, blob string, size, sessionExpiresAt int64, digest string, meta *mediacrypto.Metadata) (string, string, error) {
	if !resourceIdentifier.MatchString(blob) || !resourceIdentifier.MatchString(alias) || alias == blob || !resourceIdentifier.MatchString(digest) {
		return "", "", ErrCapability
	}
	return s.mediaFollowerDirectCapability(ctx, relationshipID, owner, alias, alias, size, sessionExpiresAt, meta, digest, blob)
}

func (s *Service) mediaFollowerDirectCapability(ctx context.Context, relationshipID, owner, objectID, resourceID string, size, sessionExpiresAt int64, meta *mediacrypto.Metadata, digest, blob string) (string, string, error) {
	assertion, local, ok := network.PublicIngressIdentityFromContext(ctx)
	if !ok || !network.HasActivePublicAdmission(ctx) || s == nil || s.repo == nil || owner == assertion.NodeID || local && blob == "" || meta == nil && digest == "" || blob == "" && meta != nil && digest != "" {
		return "", "", ErrCapability
	}
	relation, err := s.repo.Relationship(ctx, relationshipID)
	if err != nil || relation.State != "active" || relation.Direction != "downstream" || relation.PeerID != owner || s.nativeTransportReady == nil || s.nativeTransportReady(ctx, relation, "Direct") != nil {
		return "", "", ErrCapability
	}
	repository, ok := s.repo.(store.PublicRoutingRepository)
	if !ok {
		return "", "", ErrCapability
	}
	ingress, err := repository.PublicIngress(ctx)
	if err != nil || ingress.NodeID != assertion.NodeID || ingress.Generation != assertion.Generation || ingress.PublicOrigin != assertion.PublicOrigin {
		return "", "", ErrCapability
	}
	policy, err := repository.NativeTransport(ctx, owner)
	if err != nil || policy.MemberID != owner || policy.State != "applied" || policy.Revision < 1 || policy.ConfiguredTransport != "Direct" || policy.AppliedTransport != "Direct" || policy.AppliedOrigin == "" {
		return "", "", ErrCapability
	}
	origin, err := s.VerifyFollowerResourceIdentity(ctx, relationshipID)
	if err != nil || origin != policy.AppliedOrigin {
		return "", "", ErrCapability
	}
	if blob != "" && s.VerifyFollowerOpaqueReadiness(ctx, relation, origin) != nil {
		return "", "", ErrCapability
	}
	if blob == "" && digest != "" && s.VerifyFollowerPlainReadiness(ctx, relation, origin) != nil {
		return "", "", ErrCapability
	}
	var token string
	if blob != "" {
		token, err = s.MediaOpaqueIngressCapability(ctx, relationshipID, owner, objectID, blob, size, sessionExpiresAt, digest, meta)
	} else if digest != "" {
		token, err = s.MediaPlainIngressCapability(ctx, relationshipID, owner, objectID, resourceID, size, sessionExpiresAt, digest)
	} else {
		token, err = s.MediaIngressCapability(ctx, relationshipID, owner, objectID, resourceID, size, sessionExpiresAt, meta)
	}
	if err != nil || s.nativeTransportReady == nil || s.nativeTransportReady(ctx, relation, "Direct") != nil || !network.HasActivePublicAdmission(ctx) {
		return "", "", ErrCapability
	}
	return origin, token, nil
}
