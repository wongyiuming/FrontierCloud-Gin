package media

import (
	"context"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

// OpaqueMasterLyricLocalSource is for the Master while it is the active local
// ingress. It never uses a peer assertion, network loopback, or another policy.
func (s *Service) OpaqueMasterLyricLocalSource(ctx context.Context, tree *sealedtree.SQLStore, trackID, lyricID string) (string, string, error) {
	if s == nil || s.control == nil || tree == nil || ctx == nil {
		return "", "", ErrUnavailable
	}
	local, ok := network.LocalPublicIngressFromContext(ctx)
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
	token, err := s.control.IssueMasterLocalLyricCapability(ctx, p.ReadAlias, link.trackBinding, revision, descriptor)
	if err != nil || lease.Check(ctx) != nil || !network.HasActivePublicAdmission(ctx) {
		return "", "", ErrUnavailable
	}
	if _, _, _, alive := mediacrypto.DirectSessionFromContext(ctx).Values(); !alive {
		return "", "", ErrUnavailable
	}
	return local.PublicOrigin + "/api/v1/media/master-local-lyric/" + p.ReadAlias, token, nil
}

// OpenOpaqueMasterLyricLocal verifies a distinct Local grant and rechecks the
// linked objects under the caller's new Master-local admission and tree lease.
// The caller commits that ingress lease before streaming and closes the reader.
func (s *Service) OpenOpaqueMasterLyricLocal(ctx context.Context, tree *sealedtree.SQLStore, sessions *mediacrypto.Manager, token, alias string) (*VerifiedOpaqueBlob, node.MasterLocalLyricClaim, error) {
	var empty node.MasterLocalLyricClaim
	if s == nil || s.control == nil || tree == nil || sessions == nil || ctx == nil {
		return nil, empty, ErrUnavailable
	}
	lease, okLease := ingressTreeAuthority(ctx)
	if !okLease || lease.Check(ctx) != nil {
		return nil, empty, ErrUnavailable
	}
	claim, err := s.control.VerifyMasterLocalLyricCapability(ctx, token, alias)
	if err != nil || !sessions.CheckDirectSession(claim.SessionID) {
		return nil, empty, ErrUnavailable
	}
	reader, err := s.openOpaqueLyricGrant(ctx, tree, lease, claim.ObjectID, alias, claim.Revision, claim.Descriptor)
	if err != nil {
		return nil, empty, ErrUnavailable
	}
	if !sessions.CheckDirectSession(claim.SessionID) || !network.HasActivePublicAdmission(ctx) || time.Now().Unix() >= claim.ExpiresAt {
		reader.Close()
		return nil, empty, ErrUnavailable
	}
	return reader, claim, nil
}
