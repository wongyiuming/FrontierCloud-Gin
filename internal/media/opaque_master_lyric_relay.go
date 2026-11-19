package media

import (
	"context"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

// OpaqueMasterLyricRelaySource binds the lyric alias and track under
// the existing ingress admission and tree lease. It requires applied Relay;
// no failed Direct or Local route can cause this method to be selected.
func (s *Service) OpaqueMasterLyricRelaySource(ctx context.Context, tree *sealedtree.SQLStore, trackID, lyricID string) (string, string, error) {
	if s == nil || s.control == nil || tree == nil || ctx == nil {
		return "", "", ErrUnavailable
	}
	assertion, ok := network.AuthenticatedIngressFromContext(ctx)
	lease, okLease := ingressTreeAuthority(ctx)
	if !ok || !okLease || lease.Check(ctx) != nil {
		return "", "", ErrUnavailable
	}
	link, err := s.resolveOpaqueLinkedLyric(ctx, tree, trackID, lyricID)
	if err != nil {
		return "", "", ErrUnavailable
	}
	p := link.lyric.Placement
	reader, err := s.OpenVerifiedOpaqueBlob(ctx, p.BlobID, p.SHA256, p.Bytes)
	if err != nil {
		return "", "", ErrUnavailable
	}
	defer reader.Close()
	revision, descriptor, err := link.grantIdentity()
	if err != nil || s.checkOpaqueMasterLyric(ctx, link.lyric) != nil {
		return "", "", ErrUnavailable
	}
	token, err := s.control.IssueMasterRelayCapability(ctx, p.ReadAlias, link.trackBinding, revision, descriptor)
	if err != nil || lease.Check(ctx) != nil || !network.HasActivePublicAdmission(ctx) {
		return "", "", ErrUnavailable
	}
	if _, _, _, alive := mediacrypto.DirectSessionFromContext(ctx).Values(); !alive {
		return "", "", ErrUnavailable
	}
	return assertion.PublicOrigin + "/api/v1/media/master-relay/" + p.ReadAlias, token, nil
}

// OpenOpaqueMasterLyricRelay requires the authenticated ingress, a separately
// signed Relay grant and a newly acquired tree prerequisite. It revalidates
// both aliases, the current association, visibility and exact content version.
// The returned reader holds its volume lock; callers release the tree lease
// after the open and limit response lifetime to the checked grant expiry.
func (s *Service) OpenOpaqueMasterLyricRelay(ctx context.Context, tree *sealedtree.SQLStore, sessions *mediacrypto.Manager, token, lyricAlias string) (*VerifiedOpaqueBlob, node.MasterRelayClaim, error) {
	var empty node.MasterRelayClaim
	if s == nil || s.control == nil || tree == nil || sessions == nil || ctx == nil {
		return nil, empty, ErrUnavailable
	}
	lease, okLease := ingressTreeAuthority(ctx)
	if !okLease || lease.Check(ctx) != nil {
		return nil, empty, ErrUnavailable
	}
	claim, err := s.control.VerifyMasterRelayCapability(ctx, token, lyricAlias)
	if err != nil || !sessions.CheckDirectSession(claim.SessionID) {
		return nil, empty, ErrUnavailable
	}
	reader, err := s.openOpaqueLyricGrant(ctx, tree, lease, claim.ObjectID, lyricAlias, claim.Revision, claim.Descriptor)
	if err != nil {
		return nil, empty, ErrUnavailable
	}
	if !sessions.CheckDirectSession(claim.SessionID) || !network.HasActivePublicAdmission(ctx) || time.Now().Unix() >= claim.ExpiresAt {
		reader.Close()
		return nil, empty, ErrUnavailable
	}
	return reader, claim, nil
}
