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

// MasterRelayClaim is scoped to Master-owned ciphertext, one browser session,
// one ingress generation and one immutable object revision. It is a header
// capability, never a proxy destination or a media decryption key.
type MasterRelayClaim MasterDirectClaim

func validMasterRelayClaim(claim MasterRelayClaim, now int64) bool {
	if claim.Kind != "master-relay-read" || claim.ResourceOrigin != claim.PublicOrigin {
		return false
	}
	copy := MasterDirectClaim(claim)
	copy.Kind = "master-direct-read"
	return validMasterDirectClaim(copy, now)
}

// IssueMasterRelayCapability is called only by Master after visibility and
// object identity checks, while the current ingress admission is held.
func (s *Service) IssueMasterRelayCapability(ctx context.Context, resourceID, objectID, revision, descriptor string) (string, error) {
	if s == nil || s.repo == nil || s.identity == nil || s.identity.vault == nil || !network.HasActivePublicAdmission(ctx) {
		return "", ErrCapability
	}
	assertion, ok := network.AuthenticatedIngressFromContext(ctx)
	authority := mediacrypto.DirectSessionFromContext(ctx)
	_, sessionID, sessionExpiry, sessionValid := authority.Values()
	if !ok || !sessionValid {
		return "", ErrCapability
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" || identity.ID == assertion.NodeID {
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
	policy, err := s.MasterNativePolicy(ctx)
	if err != nil || policy.MemberID != identity.ID || policy.ConfiguredTransport != "Relay" || policy.AppliedTransport != "Relay" || policy.State != "applied" || policy.Revision < 1 {
		return "", ErrCapability
	}
	now := time.Now().Unix()
	claim := MasterRelayClaim{Kind: "master-relay-read", Version: 1, MasterID: identity.ID, IngressID: assertion.NodeID, Generation: assertion.Generation, PublicOrigin: assertion.PublicOrigin, ResourceOrigin: assertion.PublicOrigin, ResourceID: resourceID, ObjectID: objectID, Revision: revision, Descriptor: descriptor, SessionID: sessionID, PolicyRevision: policy.Revision, ExpiresAt: min(now+protocol.TokenSeconds, sessionExpiry)}
	if !validMasterRelayClaim(claim, now) {
		return "", ErrCapability
	}
	private, err := s.identity.vault.Unseal(identity.PrivateKey)
	if err != nil {
		return "", ErrCapability
	}
	signature, err := protocol.Sign(private, MasterDirectClaim(claim).signedPayload())
	if _, _, _, alive := authority.Values(); err != nil || !alive || !network.HasActivePublicAdmission(ctx) {
		return "", ErrCapability
	}
	raw, err := json.Marshal(claim)
	if err != nil {
		return "", ErrCapability
	}
	return protocol.Encode(raw) + "." + signature, nil
}

// VerifyMasterRelayCapability accepts only an authenticated ingress's own
// header capability. An already admitted stream may finish after selection;
// a new request still passes the Master's current ingress verifier.
func (s *Service) VerifyMasterRelayCapability(ctx context.Context, token, resourceID string) (MasterRelayClaim, error) {
	var claim MasterRelayClaim
	assertion, ok := network.AuthenticatedIngressFromContext(ctx)
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
		return MasterRelayClaim{}, ErrCapability
	}
	canonical, err := json.Marshal(claim)
	if err != nil || !bytes.Equal(canonical, raw) || !validMasterRelayClaim(claim, time.Now().Unix()) || claim.ResourceID != resourceID || claim.IngressID != assertion.NodeID || claim.Generation != assertion.Generation || claim.PublicOrigin != assertion.PublicOrigin {
		return MasterRelayClaim{}, ErrCapability
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" || identity.ID != claim.MasterID {
		return MasterRelayClaim{}, ErrCapability
	}
	public, err := s.public(identity)
	if err != nil || protocol.Verify(public, MasterDirectClaim(claim).signedPayload(), parts[1]) != nil {
		return MasterRelayClaim{}, ErrCapability
	}
	return claim, nil
}
