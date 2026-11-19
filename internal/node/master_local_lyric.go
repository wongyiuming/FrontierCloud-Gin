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

// MasterLocalLyricClaim is distinct from Direct and Relay. Its two resource
// identities are random tree aliases, never historical IDs or logical names.
type MasterLocalLyricClaim MasterDirectClaim

func validMasterLocalLyricClaim(c MasterLocalLyricClaim, now int64) bool {
	return c.Kind == "master-local-lyric-read" && c.Version == 1 && ValidIdentifier(c.MasterID) && c.IngressID == c.MasterID && c.Generation > 0 && c.PolicyRevision == 0 && validMasterDirectOrigin(c.PublicOrigin) && c.ResourceOrigin == c.PublicOrigin && resourceIdentifier.MatchString(c.ResourceID) && resourceIdentifier.MatchString(c.ObjectID) && c.ResourceID != c.ObjectID && resourceIdentifier.MatchString(c.Revision) && resourceIdentifier.MatchString(c.Descriptor) && ValidIdentifier(c.SessionID) && now > 0 && c.ExpiresAt > now && c.ExpiresAt-now <= protocol.TokenSeconds
}

// IssueMasterLocalLyricCapability runs only inside the real Master-local
// admission; caller-owned tree and object authorization remain mandatory.
func (s *Service) IssueMasterLocalLyricCapability(ctx context.Context, lyricAlias, trackAlias, revision, descriptor string) (string, error) {
	if s == nil || s.repo == nil || s.identity == nil || s.identity.vault == nil || ctx == nil {
		return "", ErrCapability
	}
	local, ok := network.LocalPublicIngressFromContext(ctx)
	authority := mediacrypto.DirectSessionFromContext(ctx)
	_, sessionID, expiry, live := authority.Values()
	if !ok || !live {
		return "", ErrCapability
	}
	identity, err := s.repo.ReadIdentity(ctx)
	routing, routingOK := s.repo.(store.PublicRoutingRepository)
	if err != nil || identity.Role != "Master" || identity.ID != local.NodeID || !routingOK {
		return "", ErrCapability
	}
	current, err := routing.PublicIngress(ctx)
	if err != nil || current.NodeID != identity.ID || current.Generation != local.Generation || current.PublicOrigin != local.PublicOrigin {
		return "", ErrCapability
	}
	now := time.Now().Unix()
	claim := MasterLocalLyricClaim{Kind: "master-local-lyric-read", Version: 1, MasterID: identity.ID, IngressID: identity.ID, Generation: local.Generation, PublicOrigin: local.PublicOrigin, ResourceOrigin: local.PublicOrigin, ResourceID: lyricAlias, ObjectID: trackAlias, Revision: revision, Descriptor: descriptor, SessionID: sessionID, ExpiresAt: min(now+protocol.TokenSeconds, expiry)}
	if !validMasterLocalLyricClaim(claim, now) {
		return "", ErrCapability
	}
	private, err := s.identity.vault.Unseal(identity.PrivateKey)
	if err != nil {
		return "", ErrCapability
	}
	signature, err := protocol.Sign(private, MasterDirectClaim(claim).signedPayload())
	if _, _, _, live = authority.Values(); err != nil || !live || !network.HasActivePublicAdmission(ctx) {
		return "", ErrCapability
	}
	raw, err := json.Marshal(claim)
	if err != nil {
		return "", ErrCapability
	}
	return protocol.Encode(raw) + "." + signature, nil
}

// VerifyMasterLocalLyricCapability is called under a newly held Master-local
// ingress admission; a previously issued token cannot start after a switch.
func (s *Service) VerifyMasterLocalLyricCapability(ctx context.Context, token, alias string) (MasterLocalLyricClaim, error) {
	var empty MasterLocalLyricClaim
	if s == nil || s.repo == nil || s.identity == nil || ctx == nil || len(token) > 4096 {
		return empty, ErrCapability
	}
	local, ok := network.LocalPublicIngressFromContext(ctx)
	if !ok {
		return empty, ErrCapability
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return empty, ErrCapability
	}
	raw, err := protocol.Decode(parts[0])
	if err != nil {
		return empty, ErrCapability
	}
	var claim MasterLocalLyricClaim
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&claim) != nil || decoder.Decode(new(any)) != io.EOF {
		return empty, ErrCapability
	}
	canonical, err := json.Marshal(claim)
	if err != nil || !bytes.Equal(raw, canonical) || !validMasterLocalLyricClaim(claim, time.Now().Unix()) || claim.ResourceID != alias || claim.MasterID != local.NodeID || claim.Generation != local.Generation || claim.PublicOrigin != local.PublicOrigin {
		return empty, ErrCapability
	}
	identity, err := s.repo.ReadIdentity(ctx)
	routing, routingOK := s.repo.(store.PublicRoutingRepository)
	if err != nil || identity.Role != "Master" || identity.ID != claim.MasterID || !routingOK {
		return empty, ErrCapability
	}
	current, err := routing.PublicIngress(ctx)
	if err != nil || current.NodeID != identity.ID || current.Generation != claim.Generation || current.PublicOrigin != claim.PublicOrigin {
		return empty, ErrCapability
	}
	public, err := s.public(identity)
	if err != nil || protocol.Verify(public, MasterDirectClaim(claim).signedPayload(), parts[1]) != nil || ctx.Err() != nil || !network.HasActivePublicAdmission(ctx) {
		return empty, ErrCapability
	}
	return claim, nil
}
