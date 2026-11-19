package media

import (
	"context"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

// OpaqueMasterLyricDirectSource is an isolated transition primitive, not a
// registered route. The URL carries only the Master lyric read alias.
func (s *Service) OpaqueMasterLyricDirectSource(ctx context.Context, tree *sealedtree.SQLStore, trackID, lyricID, origin string) (string, string, error) {
	if s == nil || s.control == nil || tree == nil || ctx == nil || node.ValidateMasterResourceOrigin(origin) != nil {
		return "", "", ErrUnavailable
	}
	lease, okLease := ingressTreeAuthority(ctx)
	if !okLease || lease.Check(ctx) != nil {
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
	token, err := s.control.IssueMasterDirectCapability(ctx, origin, p.ReadAlias, link.trackBinding, revision, descriptor)
	if err != nil || lease.Check(ctx) != nil || !network.HasActivePublicAdmission(ctx) {
		return "", "", ErrUnavailable
	}
	if _, _, _, ok := mediacrypto.DirectSessionFromContext(ctx).Values(); !ok {
		return "", "", ErrUnavailable
	}
	return origin + "/api/v1/media/master-direct-lyric/" + p.ReadAlias, token, nil
}

// OpenOpaqueMasterLyricDirect rechecks the signed random aliases, live session,
// tree association, visibility, legacy authorization and exact blob revision.
// The caller must check claim.PublicOrigin against the HTTP Origin and close the
// returned reader. Product startup remains disabled until all writers and
// recovery paths obey the tree/volume fencing contracts.
func (s *Service) OpenOpaqueMasterLyricDirect(ctx context.Context, tree *sealedtree.SQLStore, sessions *mediacrypto.Manager, token, origin, lyricAlias string) (*VerifiedOpaqueBlob, node.MasterDirectClaim, error) {
	var empty node.MasterDirectClaim
	if s == nil || s.control == nil || tree == nil || sessions == nil || ctx == nil {
		return nil, empty, ErrUnavailable
	}
	claim, err := s.control.VerifyMasterDirectCapability(ctx, token, origin, lyricAlias)
	if err != nil || !sessions.CheckDirectSession(claim.SessionID) {
		return nil, empty, ErrUnavailable
	}
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		return nil, empty, ErrUnavailable
	}
	defer lease.Release()
	reader, err := s.openOpaqueLyricGrant(ctx, tree, legacyTreeReader{lease}, claim.ObjectID, lyricAlias, claim.Revision, claim.Descriptor)
	if err != nil {
		return nil, empty, ErrUnavailable
	}
	if !sessions.CheckDirectSession(claim.SessionID) || time.Now().Unix() >= claim.ExpiresAt {
		reader.Close()
		return nil, empty, ErrUnavailable
	}
	return reader, claim, nil
}
