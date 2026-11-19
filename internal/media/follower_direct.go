package media

import (
	"context"
	"reflect"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// FollowerDirectSource keeps resource ownership and explicit Direct policy;
// it never substitutes the node's control address or falls back to Relay.
func (s *Service) FollowerDirectSource(ctx context.Context, expected store.MediaObject, sessionExpiresAt int64) (string, string, string, error) {
	if err := s.repository.CheckLegacyPhysicalWritesAllowed(ctx); err != nil {
		return "", "", "", err
	}
	assertion, ok := network.AuthenticatedIngressFromContext(ctx)
	if !ok || !network.HasActivePublicAdmission(ctx) || s.control == nil || s.pool == nil || expected.ID == "" || expected.Encryption == nil {
		return "", "", "", ErrUnavailable
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return "", "", "", err
	}
	defer release()
	object, err := s.cryptoObject(ctx, expected.Path, expected.ID, false)
	if err != nil {
		return "", "", "", err
	}
	if object.ID != expected.ID || object.Path != expected.Path || object.Kind != expected.Kind || !reflect.DeepEqual(object.Encryption, expected.Encryption) {
		return "", "", "", store.ErrNodeState
	}
	row, relation, err := s.resolveGlobalFor(ctx, object.ID, object.Path, true)
	if err != nil {
		return "", "", "", err
	}
	if relation == nil || row.RelationshipID == nil || *row.RelationshipID != relation.ID || row.MemberID != relation.PeerID || row.MemberID == assertion.NodeID || row.Transport == "S3" {
		return "", "", "", ErrUnavailable
	}
	origin, token, err := s.control.MediaFollowerDirectCapability(ctx, relation.ID, row.MemberID, row.ObjectID, row.ID, row.Bytes, sessionExpiresAt, object.Encryption)
	if err != nil {
		return "", "", "", err
	}
	return origin + "/internal/v1/media/" + row.ObjectID, origin, token, nil
}

func (s *Service) FollowerDirectPlainSource(ctx context.Context, expected store.MediaObject, objectID string, sessionExpiresAt int64) (string, string, string, string, int64, error) {
	if err := s.repository.CheckLegacyPhysicalWritesAllowed(ctx); err != nil {
		return "", "", "", "", 0, err
	}
	assertion, ok := network.AuthenticatedIngressFromContext(ctx)
	if !ok || !network.HasActivePublicAdmission(ctx) || s.control == nil || s.pool == nil || expected.ID == "" || expected.Encryption != nil {
		return "", "", "", "", 0, ErrUnavailable
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return "", "", "", "", 0, err
	}
	defer release()
	object, err := s.cryptoObject(ctx, expected.Path, expected.ID, false)
	if err != nil || object.ID != expected.ID || object.Path != expected.Path || object.Kind != expected.Kind || object.Encryption != nil {
		return "", "", "", "", 0, ErrUnavailable
	}
	row, relation, err := s.resolveGlobalFor(ctx, object.ID, object.Path, true)
	if err != nil || relation == nil || row.RelationshipID == nil || *row.RelationshipID != relation.ID || row.MemberID != relation.PeerID || row.MemberID == assertion.NodeID || row.Transport == "S3" || row.ObjectID != objectID || row.Bytes <= 0 {
		return "", "", "", "", 0, ErrUnavailable
	}
	digest, ok := plaintextContentDigest(row.ETag)
	if !ok {
		return "", "", "", "", 0, ErrUnavailable
	}
	origin, token, err := s.control.MediaFollowerDirectPlainCapability(ctx, relation.ID, row.MemberID, row.ObjectID, row.ID, row.Bytes, sessionExpiresAt, digest)
	if err != nil {
		return "", "", "", "", 0, err
	}
	return origin + "/internal/v1/media/" + row.ObjectID, origin, token, followerRelayRevision(row), row.Bytes, nil
}
