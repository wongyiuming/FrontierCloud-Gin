package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// MasterDirectClaim is a short-lived read grant signed by the Master node's
// identity. It carries no media key and must be sent in an HTTP header only.
type MasterDirectClaim struct {
	Kind           string `json:"kind"`
	Version        int    `json:"version"`
	MasterID       string `json:"master_id"`
	IngressID      string `json:"ingress_id"`
	Generation     int64  `json:"generation"`
	PublicOrigin   string `json:"public_origin"`
	ResourceOrigin string `json:"resource_origin"`
	ResourceID     string `json:"resource_id"`
	ObjectID       string `json:"object_id"`
	Revision       string `json:"revision"`
	Descriptor     string `json:"descriptor"`
	SessionID      string `json:"session_id"`
	PolicyRevision int64  `json:"policy_revision"`
	ExpiresAt      int64  `json:"expires_at"`
}

func (c MasterDirectClaim) signedPayload() map[string]any {
	return map[string]any{"kind": c.Kind, "version": c.Version, "master_id": c.MasterID, "ingress_id": c.IngressID, "generation": c.Generation, "public_origin": c.PublicOrigin, "resource_origin": c.ResourceOrigin, "resource_id": c.ResourceID, "object_id": c.ObjectID, "revision": c.Revision, "descriptor": c.Descriptor, "session_id": c.SessionID, "policy_revision": c.PolicyRevision, "expires_at": c.ExpiresAt}
}

func validMasterDirectOrigin(origin string) bool {
	value, err := MasterEndpoint(origin)
	return err == nil && value == origin
}

func validMasterDirectClaim(c MasterDirectClaim, now int64) bool {
	return c.Kind == "master-direct-read" && c.Version == 1 && ValidIdentifier(c.MasterID) && ValidIdentifier(c.IngressID) && c.MasterID != c.IngressID && c.Generation > 0 && c.PolicyRevision > 0 && validMasterDirectOrigin(c.PublicOrigin) && validMasterDirectOrigin(c.ResourceOrigin) && resourceIdentifier.MatchString(c.ResourceID) && resourceIdentifier.MatchString(c.ObjectID) && resourceIdentifier.MatchString(c.Revision) && resourceIdentifier.MatchString(c.Descriptor) && ValidIdentifier(c.SessionID) && now > 0 && c.ExpiresAt > now && c.ExpiresAt-now <= protocol.TokenSeconds
}

// IssueMasterDirectCapability may only run in a verifier-authenticated public
// admission. The origin argument must be explicit deployment configuration,
// never a request Host, header, control endpoint or browser-provided URL.
// Object identity, visibility and descriptor are verified by the media layer.
func (s *Service) IssueMasterDirectCapability(ctx context.Context, resourceOrigin, resourceID, objectID, revision, descriptor string) (string, error) {
	if s == nil || s.repo == nil || s.identity == nil || s.identity.vault == nil || !network.HasActivePublicAdmission(ctx) {
		return "", ErrCapability
	}
	assertion, ok := network.AuthenticatedIngressFromContext(ctx)
	if !ok || !validMasterDirectOrigin(resourceOrigin) {
		return "", ErrCapability
	}
	authority := mediacrypto.DirectSessionFromContext(ctx)
	_, sessionID, sessionExpiry, sessionValid := authority.Values()
	if !sessionValid {
		return "", ErrCapability
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" || assertion.NodeID == identity.ID {
		return "", ErrCapability
	}
	repo, ok := s.repo.(store.PublicRoutingRepository)
	if !ok {
		return "", ErrCapability
	}
	ingress, err := repo.PublicIngress(ctx)
	if err != nil || ingress.NodeID != assertion.NodeID || ingress.Generation != assertion.Generation || ingress.PublicOrigin != assertion.PublicOrigin {
		return "", ErrCapability
	}
	policy, err := s.MasterNativePolicy(ctx)
	if err != nil || policy.MemberID != identity.ID || policy.ConfiguredTransport != "Direct" || policy.AppliedTransport != "Direct" || policy.AppliedOrigin != resourceOrigin || policy.State != "applied" || policy.Revision < 1 {
		return "", ErrCapability
	}
	now := time.Now().Unix()
	claim := MasterDirectClaim{Kind: "master-direct-read", Version: 1, MasterID: identity.ID, IngressID: assertion.NodeID, Generation: assertion.Generation, PublicOrigin: assertion.PublicOrigin, ResourceOrigin: resourceOrigin, ResourceID: resourceID, ObjectID: objectID, Revision: revision, Descriptor: descriptor, SessionID: sessionID, PolicyRevision: policy.Revision, ExpiresAt: min(now+protocol.TokenSeconds, sessionExpiry)}
	if !validMasterDirectClaim(claim, now) {
		return "", ErrCapability
	}
	private, err := s.identity.vault.Unseal(identity.PrivateKey)
	if err != nil {
		return "", ErrCapability
	}
	signature, err := protocol.Sign(private, claim.signedPayload())
	if _, _, _, alive := authority.Values(); err != nil || !network.HasActivePublicAdmission(ctx) || !alive {
		return "", ErrCapability
	}
	raw, err := json.Marshal(claim)
	if err != nil {
		return "", ErrCapability
	}
	return protocol.Encode(raw) + "." + signature, nil
}

// VerifyMasterDirectCapability permits an already-issued grant to drain until
// its fixed expiry. It does not issue a new grant or change policy; the media
// reader must independently recheck object identity, visibility and revision.
func (s *Service) VerifyMasterDirectCapability(ctx context.Context, token, resourceOrigin, resourceID string) (MasterDirectClaim, error) {
	return s.verifyMasterDirectCapability(ctx, token, resourceOrigin, resourceID, time.Now().Unix())
}

func (s *Service) verifyMasterDirectCapability(ctx context.Context, token, resourceOrigin, resourceID string, now int64) (MasterDirectClaim, error) {
	var claim MasterDirectClaim
	if s == nil || s.repo == nil || s.identity == nil || s.identity.vault == nil || len(token) > 4096 || !validMasterDirectOrigin(resourceOrigin) {
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
		return MasterDirectClaim{}, ErrCapability
	}
	canonical, err := json.Marshal(claim)
	if err != nil || !bytes.Equal(canonical, raw) || !validMasterDirectClaim(claim, now) || claim.ResourceOrigin != resourceOrigin || claim.ResourceID != resourceID {
		return MasterDirectClaim{}, ErrCapability
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Master" || identity.ID != claim.MasterID {
		return MasterDirectClaim{}, ErrCapability
	}
	public, err := s.public(identity)
	if err != nil || protocol.Verify(public, claim.signedPayload(), parts[1]) != nil {
		return MasterDirectClaim{}, ErrCapability
	}
	return claim, nil
}

// ValidateMasterResourceOrigin rejects absent, non-HTTPS or noncanonical
// configuration. It does not infer a resource address from a control endpoint.
func ValidateMasterResourceOrigin(value string) error {
	if !validMasterDirectOrigin(value) {
		return errors.New("explicit canonical HTTPS Master resource origin required")
	}
	return nil
}
