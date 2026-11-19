package media

import (
	"context"
	"reflect"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// OpaqueIngressSource checks the authenticated placement under the active
// ingress/tree lease without sending a business path to the owner.
func (s *Service) OpaqueIngressSource(ctx context.Context, tree *sealedtree.SQLStore, expected store.MediaObject, sessionExpiresAt int64) (source, origin, token string, err error) {
	return s.opaqueIngressSource(ctx, tree, expected, "", sessionExpiresAt, nil)
}

// OpaqueSourceDetails contains the non-secret response fields bound to the
// same checked placement. The blob locator stays only in the signed bearer.
type OpaqueSourceDetails struct {
	Source, Origin, Token, Revision, Transport, SourceObjectID, OwnerID string
	Size                                                                int64
}

// OpaquePublicMedia authenticates the path and both browser IDs before any
// key is wrapped. Directory visibility only affects catalog discovery.
func (s *Service) OpaquePublicMedia(ctx context.Context, tree *sealedtree.SQLStore, name, resourceID, objectID string) (store.MediaObject, sealedtree.Placement, error) {
	lease, ok := ingressTreeAuthority(ctx)
	if !ok || !network.HasActivePublicAdmission(ctx) || lease.Check(ctx) != nil || tree == nil || name == "" || resourceID == "" || objectID == "" {
		return store.MediaObject{}, sealedtree.Placement{}, ErrUnavailable
	}
	visible, err := lease.ReadListingObject(ctx, tree, resourceID, true)
	placement := visible.Placement
	if err != nil || visible.Path != name || visible.Entry.ObjectID != resourceID || visible.Entry.Kind != "audio" && visible.Entry.Kind != "video" || placement.ObjectID != resourceID || placement.NativeObjectID != objectID || placement.State != "active" || placement.Encryption == nil || placement.Encryption.Validate() != nil || placement.Encryption.CiphertextSize != placement.Bytes {
		return store.MediaObject{}, sealedtree.Placement{}, ErrUnavailable
	}
	return store.MediaObject{ID: resourceID, Path: visible.Path, Kind: visible.Entry.Kind, Encryption: placement.Encryption}, placement, nil
}

func (s *Service) opaqueFollowerRelationship(ctx context.Context, placement sealedtree.Placement) (store.Relationship, error) {
	repo, ok := s.pool.(nativeCatalogRepository)
	if !ok || s.nodes == nil {
		return store.Relationship{}, ErrUnavailable
	}
	member, err := repo.NativeCatalogMember(ctx, placement.OwnerID)
	if err != nil || member.ID != placement.OwnerID || member.Kind != "Follower" || member.RelationshipID == nil {
		return store.Relationship{}, ErrUnavailable
	}
	relation, err := s.nodes.Relationship(ctx, *member.RelationshipID)
	if err != nil || relation.ID != *member.RelationshipID || relation.PeerID != placement.OwnerID || relation.Direction != "downstream" || relation.State != "active" || relation.Protocol != protocol.Version {
		return store.Relationship{}, ErrUnavailable
	}
	return relation, nil
}

func (s *Service) OpaqueIngressResource(ctx context.Context, tree *sealedtree.SQLStore, expected store.MediaObject, objectID string, sessionExpiresAt int64) (OpaqueSourceDetails, error) {
	if local, ok := network.LocalPublicIngressFromContext(ctx); ok {
		lease, valid := ingressTreeAuthority(ctx)
		if !valid || lease.Check(ctx) != nil || tree == nil {
			return OpaqueSourceDetails{}, ErrUnavailable
		}
		visible, err := lease.ReadListingObject(ctx, tree, expected.ID, true)
		if err != nil {
			return OpaqueSourceDetails{}, ErrUnavailable
		}
		if visible.Placement.OwnerID == local.NodeID {
			return s.OpaqueMasterLocalResource(ctx, tree, expected, objectID, sessionExpiresAt)
		}
	}
	var details OpaqueSourceDetails
	source, origin, token, err := s.opaqueIngressSource(ctx, tree, expected, objectID, sessionExpiresAt, &details)
	if err != nil {
		return OpaqueSourceDetails{}, err
	}
	details.Source, details.Origin, details.Token = source, origin, token
	return details, nil
}

func (s *Service) opaqueIngressSource(ctx context.Context, tree *sealedtree.SQLStore, expected store.MediaObject, objectID string, sessionExpiresAt int64, details *OpaqueSourceDetails) (source, origin, token string, err error) {
	assertion, local, ok := network.PublicIngressIdentityFromContext(ctx)
	if !ok || !network.HasActivePublicAdmission(ctx) || s == nil || s.control == nil || s.pool == nil || tree == nil || expected.ID == "" || expected.Path == "" || expected.Kind == "lyric" {
		return "", "", "", ErrUnavailable
	}
	lease, valid := ingressTreeAuthority(ctx)
	if !valid || lease.Check(ctx) != nil {
		return "", "", "", ErrUnavailable
	}
	visible, err := lease.ReadListingObject(ctx, tree, expected.ID, true)
	if err != nil || visible.Entry.ObjectID != expected.ID || visible.Path != expected.Path || visible.Entry.Kind != expected.Kind || !reflect.DeepEqual(visible.Placement.Encryption, expected.Encryption) || visible.Placement.State != "active" {
		return "", "", "", ErrUnavailable
	}
	placement := visible.Placement
	relation, err := s.opaqueFollowerRelationship(ctx, placement)
	if err != nil || placement.ObjectID != visible.Entry.ObjectID || objectID != "" && objectID != placement.NativeObjectID || placement.Bytes < 0 {
		return "", "", "", ErrUnavailable
	}
	if local && placement.OwnerID == assertion.NodeID {
		return "", "", "", ErrUnavailable
	}
	ownerRoute := "/internal/v1/opaque-media/" + placement.ReadAlias
	transport := "Local"
	if placement.OwnerID != assertion.NodeID {
		routing, ok := s.nodes.(store.PublicRoutingRepository)
		if !ok {
			return "", "", "", ErrUnavailable
		}
		policy, policyErr := routing.NativeTransport(ctx, placement.OwnerID)
		if policyErr != nil || policy.MemberID != placement.OwnerID || policy.State != "applied" || policy.Revision < 1 || policy.ConfiguredTransport != policy.AppliedTransport || policy.AppliedTransport != "Direct" && policy.AppliedTransport != "Relay" {
			return "", "", "", ErrUnavailable
		}
		transport = policy.AppliedTransport
	}
	switch {
	case placement.OwnerID == assertion.NodeID:
		origin = assertion.PublicOrigin
		if s.control.VerifyFollowerOpaqueReadiness(ctx, relation, origin) != nil {
			return "", "", "", ErrUnavailable
		}
		token, err = s.control.MediaOpaqueIngressCapability(ctx, relation.ID, placement.OwnerID, placement.ReadAlias, placement.BlobID, placement.Bytes, sessionExpiresAt, placement.SHA256, placement.Encryption)
	case transport == "Direct":
		origin, token, err = s.control.MediaFollowerDirectOpaqueCapability(ctx, relation.ID, placement.OwnerID, placement.ReadAlias, placement.BlobID, placement.Bytes, sessionExpiresAt, placement.SHA256, placement.Encryption)
	case transport == "Relay":
		origin = assertion.PublicOrigin
		ownerRoute = "/api/v1/media/opaque-follower-relay/" + placement.ReadAlias
		if local {
			ownerRoute = "/api/v1/media/opaque-local-follower-relay/" + placement.ReadAlias
		}
		var revision, descriptor string
		revision, err = opaqueSourceRevision(placement)
		if err == nil {
			descriptor, err = protocol.IngressMediaDescriptor(placement.Bytes, placement.Encryption)
		}
		if err == nil {
			token, err = s.control.IssueOpaqueFollowerRelayCapability(ctx, relation.ID, placement.OwnerID, placement.ReadAlias, revision, descriptor)
		}
	default:
		return "", "", "", ErrUnavailable
	}
	if err != nil || lease.Check(ctx) != nil || !network.HasActivePublicAdmission(ctx) {
		return "", "", "", ErrUnavailable
	}
	if details != nil {
		revision, revisionErr := opaqueSourceRevision(placement)
		if revisionErr != nil {
			return "", "", "", ErrUnavailable
		}
		details.Revision, details.Size, details.Transport, details.SourceObjectID, details.OwnerID = revision, placement.Bytes, transport, placement.ReadAlias, placement.OwnerID
	}
	return origin + ownerRoute, origin, token, nil
}

// OpaqueFollowerRelayObject re-resolves an already admitted Relay grant under
// the newly held tree lease. It repeats authorization and exact placement
// checks; a tree change between admissions cannot be used
// to derive authority for a replacement object.
func (s *Service) OpaqueFollowerRelayObject(ctx context.Context, tree *sealedtree.SQLStore, token, alias string) (sealedtree.Placement, node.FollowerRelayClaim, error) {
	var empty sealedtree.Placement
	var emptyClaim node.FollowerRelayClaim
	if s == nil || s.control == nil || tree == nil {
		return empty, emptyClaim, ErrUnavailable
	}
	lease, valid := ingressTreeAuthority(ctx)
	if !valid || lease.Check(ctx) != nil {
		return empty, emptyClaim, ErrUnavailable
	}
	claim, err := s.control.VerifyOpaqueFollowerRelayCapability(ctx, token, alias)
	if err != nil {
		return empty, emptyClaim, ErrUnavailable
	}
	visible, err := lease.ReadListingObjectByAlias(ctx, tree, alias, true)
	if err != nil || visible.Entry.Kind != "audio" && visible.Entry.Kind != "video" || visible.Placement.State != "active" {
		return empty, emptyClaim, ErrUnavailable
	}
	placement := visible.Placement
	relation, err := s.opaqueFollowerRelationship(ctx, placement)
	revision, revErr := opaqueSourceRevision(placement)
	descriptor, descErr := protocol.IngressMediaDescriptor(placement.Bytes, placement.Encryption)
	if err != nil || revErr != nil || descErr != nil || claim.RelationshipID != relation.ID || claim.OwnerID != placement.OwnerID || placement.ObjectID != visible.Entry.ObjectID || claim.Revision != revision || claim.Descriptor != descriptor || lease.Check(ctx) != nil {
		return empty, emptyClaim, ErrUnavailable
	}
	return placement, claim, nil
}

// Neither names nor historical IDs participate in the browser-visible
// revision; an independent random placement changes it on replacement.
func opaqueSourceRevision(placement sealedtree.Placement) (string, error) {
	return protocol.OpaquePlacementRevision(placement.ReadAlias, placement.BlobID, placement.SHA256, placement.Bytes, placement.Encryption)
}
