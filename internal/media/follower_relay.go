package media

import (
	"context"
	"reflect"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func followerRelayRevision(row store.GlobalMedia) string {
	return store.NativeResourceRevision(row)
}

// FollowerIngressPolicy identifies the durable owner before choosing a path.
// Local is relative to the selected ingress and is never inferred from a
// failed Direct or Relay request.
func (s *Service) FollowerIngressPolicy(ctx context.Context, object store.MediaObject) (bool, store.NativeTransportPolicy, error) {
	var empty store.NativeTransportPolicy
	assertion, ok := network.AuthenticatedIngressFromContext(ctx)
	if !ok || !network.HasActivePublicAdmission(ctx) || s.pool == nil || object.ID == "" {
		return false, empty, ErrUnavailable
	}
	row, err := s.pool.Resource(ctx, object.ID)
	if err != nil || row.ID != object.ID || row.Path != object.Path || row.Kind != object.Kind || row.State != "active" || row.RelationshipID == nil || row.Transport == "S3" {
		return false, empty, ErrUnavailable
	}
	if row.MemberID == assertion.NodeID {
		return true, empty, nil
	}
	repository, ok := s.nodes.(store.PublicRoutingRepository)
	if !ok {
		return false, empty, ErrUnavailable
	}
	policy, err := repository.NativeTransport(ctx, row.MemberID)
	if err != nil || policy.MemberID != row.MemberID {
		return false, empty, ErrUnavailable
	}
	return false, policy, nil
}

// FollowerRelaySource authorizes a single native object without disclosing
// the owner's connection address or relationship capability to the browser.
// The bounded owner stream uses this grant and a separate owner capability.
func (s *Service) FollowerRelaySource(ctx context.Context, expected store.MediaObject) (string, string, error) {
	if err := s.repository.CheckLegacyPhysicalWritesAllowed(ctx); err != nil {
		return "", "", err
	}
	assertion, ok := network.AuthenticatedIngressFromContext(ctx)
	if !ok || !network.HasActivePublicAdmission(ctx) || s.control == nil || s.pool == nil || expected.ID == "" || expected.Path == "" {
		return "", "", ErrUnavailable
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return "", "", err
	}
	defer release()
	object, err := s.cryptoObject(ctx, expected.Path, expected.ID, false)
	if err != nil {
		return "", "", err
	}
	if object.ID != expected.ID || object.Path != expected.Path || object.Kind != expected.Kind || !reflect.DeepEqual(object.Encryption, expected.Encryption) {
		return "", "", store.ErrNodeState
	}
	row, relation, err := s.resolveGlobalFor(ctx, object.ID, object.Path, true)
	if err != nil {
		return "", "", err
	}
	if relation == nil || row.RelationshipID == nil || *row.RelationshipID != relation.ID || row.MemberID != relation.PeerID || row.MemberID == assertion.NodeID || row.Transport == "S3" {
		return "", "", ErrUnavailable
	}
	if object.Encryption == nil {
		if _, ok := plaintextContentDigest(row.ETag); !ok || row.Bytes <= 0 {
			return "", "", ErrUnavailable
		}
		if err := s.control.VerifyFollowerPlainReadiness(ctx, *relation, relation.Endpoint); err != nil {
			return "", "", ErrUnavailable
		}
	}
	descriptor, err := protocol.IngressMediaDescriptor(row.Bytes, object.Encryption)
	if err != nil {
		return "", "", err
	}
	token, err := s.control.IssueFollowerRelayCapability(ctx, relation.ID, row.MemberID, row.ID, row.ObjectID, followerRelayRevision(row), descriptor)
	if err != nil {
		return "", "", err
	}
	return assertion.PublicOrigin + "/api/v1/media/follower-relay/" + row.ID, token, nil
}

// FollowerRelayObject verifies the grant and rechecks current visibility,
// owner, exact revision and descriptor. Callers must check its session before
// deriving a separate owner capability and must never expose that capability.
func (s *Service) FollowerRelayObject(ctx context.Context, token, resourceID string) (store.GlobalMedia, node.FollowerRelayClaim, error) {
	if err := s.repository.CheckLegacyPhysicalWritesAllowed(ctx); err != nil {
		return store.GlobalMedia{}, node.FollowerRelayClaim{}, err
	}
	var row store.GlobalMedia
	var claim node.FollowerRelayClaim
	if s.control == nil {
		return row, claim, ErrUnavailable
	}
	claim, err := s.control.VerifyFollowerRelayCapability(ctx, token, resourceID)
	if err != nil {
		return row, claim, err
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return row, claim, err
	}
	defer release()
	object, err := s.cryptoObject(ctx, "", resourceID, false)
	if err != nil {
		return row, claim, err
	}
	row, relation, err := s.resolveGlobalFor(ctx, object.ID, object.Path, true)
	if err != nil {
		return row, claim, err
	}
	descriptor, err := protocol.IngressMediaDescriptor(row.Bytes, object.Encryption)
	if err != nil || relation == nil || row.RelationshipID == nil || *row.RelationshipID != claim.RelationshipID || relation.ID != claim.RelationshipID || row.MemberID != claim.OwnerID || row.ObjectID != claim.ObjectID || followerRelayRevision(row) != claim.Revision || descriptor != claim.Descriptor {
		return store.GlobalMedia{}, node.FollowerRelayClaim{}, store.ErrNodeState
	}
	if object.Encryption == nil {
		if _, ok := plaintextContentDigest(row.ETag); !ok || row.Bytes <= 0 {
			return store.GlobalMedia{}, node.FollowerRelayClaim{}, store.ErrNodeState
		}
	}
	return row, claim, nil
}
