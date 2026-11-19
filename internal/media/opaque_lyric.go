package media

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type opaqueLinkedLyric struct {
	trackPath, trackBinding string
	s3                      bool
	lyric                   sealedtree.VisibleObject
}

// ResolveOpaqueLinkedLyric checks the current relation under the public
// admission and the live browser session. It grants no bytes by itself.
func (s *Service) ResolveOpaqueLinkedLyric(ctx context.Context, tree *sealedtree.SQLStore, trackID, lyricID string) (sealedtree.VisibleObject, error) {
	link, err := s.resolveOpaqueLinkedLyric(ctx, tree, trackID, lyricID)
	return link.lyric, err
}

func (s *Service) resolveOpaqueLinkedLyric(ctx context.Context, tree *sealedtree.SQLStore, trackID, lyricID string) (opaqueLinkedLyric, error) {
	var empty opaqueLinkedLyric
	if ctx == nil || lyricID == "" {
		return empty, ErrUnavailable
	}
	authority := mediacrypto.DirectSessionFromContext(ctx)
	if _, _, _, valid := authority.Values(); !valid {
		return empty, ErrUnavailable
	}
	link, err := s.describeOpaqueLinkedLyric(ctx, tree, trackID)
	if err != nil || link.lyric.Entry.ObjectID != lyricID {
		return empty, ErrUnavailable
	}
	if _, _, _, valid := authority.Values(); !valid || !network.HasActivePublicAdmission(ctx) {
		return empty, ErrUnavailable
	}
	return link, nil
}

// DescribeOpaqueLinkedLyric checks the exact track and Master-owned link
// under the admission's tree lease. It grants neither a content key nor bytes.
func (s *Service) DescribeOpaqueLinkedLyric(ctx context.Context, tree *sealedtree.SQLStore, trackID string) (string, sealedtree.VisibleObject, error) {
	link, err := s.describeOpaqueLinkedLyric(ctx, tree, trackID)
	return link.trackPath, link.lyric, err
}

func (s *Service) describeOpaqueLinkedLyric(ctx context.Context, tree *sealedtree.SQLStore, trackID string) (opaqueLinkedLyric, error) {
	var empty opaqueLinkedLyric
	if s == nil || s.repository == nil || s.pool == nil || s.nodes == nil || tree == nil || ctx == nil || trackID == "" || !network.HasActivePublicAdmission(ctx) {
		return empty, ErrUnavailable
	}
	_, peer := network.AuthenticatedIngressFromContext(ctx)
	local, localOK := network.LocalPublicIngressFromContext(ctx)
	if !peer && !localOK {
		return empty, ErrUnavailable
	}
	lease, ok := ingressTreeAuthority(ctx)
	if !ok || lease.Check(ctx) != nil {
		return empty, ErrUnavailable
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return empty, err
	}
	defer release()
	if localOK {
		routing, ok := s.nodes.(store.ExistingIngressRepository)
		identity, e := s.IdentityState(ctx)
		if !ok || e != nil || identity.Role != "Master" {
			return empty, ErrUnavailable
		}
		current, err := routing.ExistingPublicIngress(ctx)
		if err != nil || local.NodeID != identity.ID || current.NodeID != local.NodeID || current.Generation != local.Generation || current.PublicOrigin != local.PublicOrigin {
			return empty, ErrUnavailable
		}
	}
	link, err := s.readOpaqueLinkedLyric(ctx, lease, tree, trackID)
	if err != nil || lease.Check(ctx) != nil || !network.HasActivePublicAdmission(ctx) {
		return empty, ErrUnavailable
	}
	return link, nil
}

// An S3 placement is authenticated by the tree. A separate provider gate is
// needed to issue its audio bytes, but lyrics are always read from Master.
func readOpaqueS3Track(ctx context.Context, lease ingressTreeReader, tree *sealedtree.SQLStore, trackID string, includeHidden bool) (sealedtree.S3ListingObject, error) {
	reader, ok := lease.(ingressS3TreeReader)
	if !ok {
		return sealedtree.S3ListingObject{}, ErrUnavailable
	}
	track, err := reader.ReadS3ListingObject(ctx, tree, trackID, includeHidden)
	p := track.Placement
	if err != nil || track.Entry.ObjectID != trackID || (track.Entry.Kind != "audio" && track.Entry.Kind != "video") || p.ObjectID != trackID || p.Proof.MetadataFormat != store.S3OpaqueMetadata || p.Encryption == nil || p.Encryption.Validate() != nil || p.Encryption.CiphertextSize != p.Proof.Bytes {
		return sealedtree.S3ListingObject{}, ErrUnavailable
	}
	return track, nil
}

func (s *Service) readOpaqueLinkedLyric(ctx context.Context, lease ingressTreeReader, tree *sealedtree.SQLStore, trackID string) (opaqueLinkedLyric, error) {
	var empty opaqueLinkedLyric
	// The caller holds a shared tree lease across both exact reads. Hiding
	// the track affects discovery, while the lyric still needs its own proof.
	track, err := lease.ReadListingObject(ctx, tree, trackID, true)
	entry, facts := track.Entry, track.Facts
	link := opaqueLinkedLyric{trackPath: track.Path, trackBinding: track.Placement.ReadAlias}
	switch {
	case err == nil:
		p := track.Placement
		if p.State != "active" || p.Encryption == nil || p.Encryption.Validate() != nil || p.Encryption.CiphertextSize != p.Bytes {
			return empty, ErrUnavailable
		}
	case errors.Is(err, sealedtree.ErrInvalid):
		provider, err := readOpaqueS3Track(ctx, lease, tree, trackID, true)
		if err != nil {
			return empty, ErrUnavailable
		}
		entry, facts = provider.Entry, provider.Facts
		link = opaqueLinkedLyric{trackPath: provider.Path, trackBinding: trackID, s3: true}
	default:
		return empty, ErrUnavailable
	}
	if entry.ObjectID != trackID || entry.Kind != "audio" || !strings.HasPrefix(link.trackPath, "music/") || facts.Lyric == nil {
		return empty, ErrUnavailable
	}
	lyric, err := lease.ReadVisibleObject(ctx, tree, facts.Lyric.LyricID)
	if err != nil || !strings.HasPrefix(lyric.Path, "lyrics/") || s.checkOpaqueMasterLyric(ctx, lyric) != nil ||
		tree.VerifyNativeLinkedLyricFacts(entry, facts, lyric.Entry) != nil {
		return empty, ErrUnavailable
	}
	link.lyric = lyric
	return link, nil
}

func (s *Service) checkOpaqueMasterLyric(ctx context.Context, lyric sealedtree.VisibleObject) error {
	identity, err := s.IdentityState(ctx)
	p := lyric.Placement
	if err != nil || identity.Role != "Master" || p.OwnerID != identity.ID || p.ObjectID != lyric.Entry.ObjectID || p.NativeObjectID != lyric.Entry.ObjectID || p.State != "active" || p.Bytes <= 0 || p.Encryption == nil || p.Encryption.Validate() != nil || p.Encryption.CiphertextSize != p.Bytes || p.Encryption.PlaintextSize > maxLyricBytes {
		return ErrUnavailable
	}
	return nil
}

func (link opaqueLinkedLyric) grantIdentity() (revision, descriptor string, err error) {
	p := link.lyric.Placement
	revision, err = opaqueSourceRevision(p)
	if err != nil {
		return "", "", err
	}
	if link.s3 {
		// S3 has no native track alias. Bind the signed catalog ID in a
		// separate revision domain so it cannot authorize a native alias.
		digest := sha256.Sum256([]byte("frontiercloud:s3-linked-lyric:v1\x00" + link.trackBinding + revision))
		revision = hex.EncodeToString(digest[:])
	}
	descriptor, err = protocol.IngressMediaDescriptor(p.Bytes, p.Encryption)
	return revision, descriptor, err
}

func (s *Service) openOpaqueLyricGrant(ctx context.Context, tree *sealedtree.SQLStore, lease ingressTreeReader, trackBinding, lyricAlias, revision, descriptor string) (*VerifiedOpaqueBlob, error) {
	release, err := s.acquire(ctx, false)
	if err != nil {
		return nil, ErrUnavailable
	}
	trackID := trackBinding
	track, err := lease.ReadListingObjectByAlias(ctx, tree, trackBinding, true)
	native := err == nil
	if native {
		trackID = track.Entry.ObjectID
	} else if !errors.Is(err, sealedtree.ErrInvalid) {
		release()
		return nil, ErrUnavailable
	}
	link, err := s.readOpaqueLinkedLyric(ctx, lease, tree, trackID)
	release()
	if err != nil || link.s3 == native || link.trackBinding != trackBinding || link.lyric.Placement.ReadAlias != lyricAlias {
		return nil, ErrUnavailable
	}
	actualRevision, actualDescriptor, err := link.grantIdentity()
	if err != nil || actualRevision != revision || actualDescriptor != descriptor || lease.Check(ctx) != nil {
		return nil, ErrUnavailable
	}
	lyric := link.lyric
	reader, err := s.OpenVerifiedOpaqueBlob(ctx, lyric.Placement.BlobID, lyric.Placement.SHA256, lyric.Placement.Bytes)
	if err != nil {
		return nil, ErrUnavailable
	}
	if s.checkOpaqueMasterLyric(ctx, lyric) != nil || lease.Check(ctx) != nil {
		reader.Close()
		return nil, ErrUnavailable
	}
	return reader, nil
}

// OpenOpaqueLinkedLyric keeps the volume reader under an already admitted
// live browser session. The caller retains admission through its decision.
func (s *Service) OpenOpaqueLinkedLyric(ctx context.Context, tree *sealedtree.SQLStore, trackID, lyricID string) (*VerifiedOpaqueBlob, error) {
	lyric, err := s.ResolveOpaqueLinkedLyric(ctx, tree, trackID, lyricID)
	if err != nil {
		return nil, err
	}
	lease, ok := ingressTreeAuthority(ctx)
	if !ok {
		return nil, ErrUnavailable
	}
	reader, err := s.OpenVerifiedOpaqueBlob(ctx, lyric.Placement.BlobID, lyric.Placement.SHA256, lyric.Placement.Bytes)
	if err != nil {
		return nil, ErrUnavailable
	}
	if _, _, _, alive := mediacrypto.DirectSessionFromContext(ctx).Values(); !alive || lease.Check(ctx) != nil || !network.HasActivePublicAdmission(ctx) {
		reader.Close()
		return nil, ErrUnavailable
	}
	return reader, nil
}
