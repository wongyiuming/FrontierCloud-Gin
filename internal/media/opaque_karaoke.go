package media

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type OpaqueKaraokeTrack struct {
	Path, ID, ObjectID, Kind string
	Bytes                    int64
	Encryption               *mediacrypto.Metadata
	S3, ExplicitLyric        bool
}

// DescribeOpaqueKaraoke is a metadata-only transition adapter. It neither
// issues a byte grant nor creates the legacy default-lyric association.
// Callers must retain the real tree and ingress admission through response
// commit; native resource issuance independently checks the applied policy.
func (s *Service) DescribeOpaqueKaraoke(ctx context.Context, tree *sealedtree.SQLStore, token string) (OpaqueKaraokeTrack, bool, error) {
	var empty OpaqueKaraokeTrack
	if s == nil || s.identity == nil || s.nodes == nil || s.repository == nil || s.pool == nil || tree == nil || ctx == nil || !network.HasActivePublicAdmission(ctx) {
		return empty, false, ErrUnavailable
	}
	_, peer := network.AuthenticatedIngressFromContext(ctx)
	local, isLocal := network.LocalPublicIngressFromContext(ctx)
	if !peer && !isLocal {
		return empty, false, ErrUnavailable
	}
	if isLocal {
		identity, err := s.IdentityState(ctx)
		routing, ok := s.nodes.(store.ExistingIngressRepository)
		if err != nil || !ok || identity.Role != "Master" || local.NodeID != identity.ID {
			return empty, false, ErrUnavailable
		}
		current, err := routing.ExistingPublicIngress(ctx)
		if err != nil || current.NodeID != local.NodeID || current.Generation != local.Generation || current.PublicOrigin != local.PublicOrigin {
			return empty, false, ErrUnavailable
		}
	}
	lease, okLease := ingressTreeAuthority(ctx)
	if !okLease || lease.Check(ctx) != nil {
		return empty, false, ErrUnavailable
	}
	kind, id, err := s.identity.ResolveKaraoke(token)
	if err != nil || kind != "global" {
		return empty, false, ErrUnavailable
	}
	// The signed handle identifies one exact track. Hide controls discovery.
	track, err := lease.ReadListingObject(ctx, tree, id, true)
	var result OpaqueKaraokeTrack
	var facts sealedtree.Facts
	switch {
	case err == nil:
		if track.Entry.ObjectID != id || track.Entry.Kind != "audio" && track.Entry.Kind != "video" || s.checkOpaqueKaraokePlacement(ctx, lease, id, track.Placement) != nil {
			return empty, false, ErrUnavailable
		}
		result = OpaqueKaraokeTrack{Path: track.Path, ID: id, ObjectID: track.Placement.NativeObjectID, Kind: track.Entry.Kind, Bytes: track.Placement.Bytes, Encryption: track.Placement.Encryption}
		facts = track.Facts
	case errors.Is(err, sealedtree.ErrInvalid):
		provider, err := readOpaqueS3Track(ctx, lease, tree, id, true)
		if err != nil {
			return empty, false, ErrUnavailable
		}
		result = OpaqueKaraokeTrack{Path: provider.Path, ID: id, ObjectID: provider.Placement.Proof.ObjectID, Kind: provider.Entry.Kind, Bytes: provider.Placement.Proof.Bytes, Encryption: provider.Placement.Encryption, S3: true}
		facts = provider.Facts
	default:
		return empty, false, ErrUnavailable
	}
	result.ExplicitLyric = facts.Lyric != nil
	hasLyric := result.ExplicitLyric
	if result.Kind == "audio" && !hasLyric {
		_, fallback, e := opaqueBuiltinLyricDecision(ctx, lease, tree, id)
		if e != nil || !fallback {
			return empty, false, ErrUnavailable
		}
		hasLyric = true
	}
	if result.ExplicitLyric {
		if _, lyric, err := s.DescribeOpaqueLinkedLyric(ctx, tree, id); err != nil || lyric.Entry.ObjectID != facts.Lyric.LyricID {
			return empty, false, ErrUnavailable
		}
	}
	if lease.Check(ctx) != nil || !network.HasActivePublicAdmission(ctx) {
		return empty, false, ErrUnavailable
	}
	return result, hasLyric, nil
}

// OpaqueKaraokeBuiltinFallback returns only the built-in lyric for an
// authenticated tree decision. Source decisions require separately authenticated
// import evidence and therefore remain unavailable. An explicit association
// never becomes fallback merely because its owner is offline or data is absent.
func (s *Service) OpaqueKaraokeBuiltinFallback(ctx context.Context, tree *sealedtree.SQLStore, token string) ([]LyricEntry, bool, error) {
	if s == nil || s.identity == nil || ctx == nil {
		return nil, false, ErrUnavailable
	}
	kind, id, err := s.identity.ResolveKaraoke(token)
	if err != nil || kind != "global" {
		return nil, false, ErrUnavailable
	}
	return s.opaqueBuiltinFallback(ctx, tree, id, "")
}

// OpaqueTrackBuiltinFallback additionally binds the requested legacy path to
// the authenticated tree, including for the legacy hidden-track display case.
func (s *Service) OpaqueTrackBuiltinFallback(ctx context.Context, tree *sealedtree.SQLStore, id, requestedPath string) ([]LyricEntry, bool, error) {
	if requestedPath == "" {
		return nil, false, ErrUnavailable
	}
	return s.opaqueBuiltinFallback(ctx, tree, id, requestedPath)
}

func (s *Service) opaqueBuiltinFallback(ctx context.Context, tree *sealedtree.SQLStore, id, requestedPath string) ([]LyricEntry, bool, error) {
	if s == nil || s.pool == nil || s.nodes == nil || tree == nil || ctx == nil || id == "" || !network.HasActivePublicAdmission(ctx) {
		return nil, false, ErrUnavailable
	}
	_, peer := network.AuthenticatedIngressFromContext(ctx)
	_, local := network.LocalPublicIngressFromContext(ctx)
	if !peer && !local {
		return nil, false, ErrUnavailable
	}
	lease, ok := ingressTreeAuthority(ctx)
	if !ok || lease.Check(ctx) != nil {
		return nil, false, ErrUnavailable
	}
	track, err := lease.ReadListingObject(ctx, tree, id, true)
	switch {
	case err == nil:
		if track.Entry.ObjectID != id || track.Entry.Kind != "audio" || requestedPath != "" && track.Path != requestedPath || s.checkOpaqueKaraokePlacement(ctx, lease, id, track.Placement) != nil {
			return nil, false, ErrUnavailable
		}
	case errors.Is(err, sealedtree.ErrInvalid):
		provider, err := readOpaqueS3Track(ctx, lease, tree, id, true)
		if err != nil || provider.Entry.Kind != "audio" || requestedPath != "" && provider.Path != requestedPath {
			return nil, false, ErrUnavailable
		}
	default:
		return nil, false, ErrUnavailable
	}
	return opaqueBuiltinLyricDecision(ctx, lease, tree, id)
}

func opaqueBuiltinLyricDecision(ctx context.Context, lease ingressTreeReader, tree *sealedtree.SQLStore, id string) ([]LyricEntry, bool, error) {
	selection, err := lease.SelectLyricForDisplay(ctx, tree, id)
	if err != nil || (selection.Origin != "native" && selection.Origin != "local") || lease.Check(ctx) != nil || !network.HasActivePublicAdmission(ctx) {
		return nil, false, ErrUnavailable
	}
	if !selection.BuiltinFallback {
		return nil, false, nil
	}
	entries, err := ParseLRC([]byte(defaultContent))
	if err != nil {
		return nil, false, ErrUnavailable
	}
	return entries, true, nil
}

// checkOpaqueKaraokePlacement borrows the admission's existing Owner, ingress
// and tree fences. Acquiring another Owner fence here would invert their order.
func (s *Service) checkOpaqueKaraokePlacement(ctx context.Context, lease ingressTreeReader, id string, placement sealedtree.Placement) error {
	if placement.ObjectID != id || placement.NativeObjectID != id || placement.State != "active" || placement.Bytes <= 0 || placement.Encryption == nil || placement.Encryption.Validate() != nil || placement.Encryption.CiphertextSize != placement.Bytes {
		return ErrUnavailable
	}
	if _, err := s.NativeCatalogOwnerResolver(); err != nil {
		return ErrUnavailable
	}
	repo := s.pool.(nativeCatalogRepository)
	routing := s.nodes.(nativeCatalogRouting)
	ingress, _, ok := network.PublicIngressIdentityFromContext(ctx)
	if !ok {
		return ErrUnavailable
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return ErrUnavailable
	}
	defer release()
	view, err := s.nativeCatalogView(ctx, repo, routing, placement.OwnerID)
	member, memberErr := repo.NativeCatalogMember(ctx, placement.OwnerID)
	if err != nil || view.ingress.NodeID != ingress.NodeID || view.ingress.Generation != ingress.Generation || view.ingress.PublicOrigin != ingress.PublicOrigin || memberErr != nil || member.ID != placement.OwnerID || member.Health != "online" {
		return ErrUnavailable
	}
	var relation store.Relationship
	var deadline time.Time
	if view.relation != "" {
		relation, err = s.nodes.Relationship(ctx, view.relation)
		age := time.Now().Unix() - relation.LastHeartbeat
		if err != nil || relation.ID != view.relation || relation.State != "active" || relation.Direction != "downstream" || relation.PeerID != placement.OwnerID || relation.Status != "online" || relation.LastHeartbeat <= 0 || age < 0 || age >= 120 {
			return ErrUnavailable
		}
		deadline = time.Unix(relation.LastHeartbeat+120, 0)
	} else if view.master != placement.OwnerID || view.kind != "MasterLocal" {
		return ErrUnavailable
	}
	registrar, ok := lease.(interface {
		RegisterPrecommitCheck(func(context.Context) error, time.Time) error
	})
	if !ok {
		return ErrUnavailable
	}
	return registrar.RegisterPrecommitCheck(func(c context.Context) error {
		unlock, e := s.acquire(c, false)
		if e != nil {
			return ErrUnavailable
		}
		defer unlock()
		// The enclosing admission checks the held Owner and tree leases after
		// callbacks. Re-entering that busy admission here would fail.
		latestView, e := s.nativeCatalogView(c, repo, routing, placement.OwnerID)
		latestMember, memberErr := repo.NativeCatalogMember(c, placement.OwnerID)
		if e != nil || latestView != view || memberErr != nil || latestMember.ID != member.ID || latestMember.Health != "online" {
			return ErrUnavailable
		}
		if view.relation != "" {
			latest, e := s.nodes.Relationship(c, view.relation)
			if e != nil || !reflect.DeepEqual(latest, relation) || !time.Now().Before(deadline) {
				return ErrUnavailable
			}
		}
		return c.Err()
	}, deadline)
}
