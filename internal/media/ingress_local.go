package media

import (
	"context"
	"reflect"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// IngressLocalSource issues an owner-bound read only after repeating the
// visibility, object, encryption and current-ingress checks under the media
// mutation fence. The caller holds the ingress verifier's admission lease.
// Non-local resources remain unavailable until their own paths are wired.
func (s *Service) IngressLocalSource(ctx context.Context, expected store.MediaObject, sessionExpiresAt int64) (string, string, error) {
	if err := s.repository.CheckLegacyPhysicalWritesAllowed(ctx); err != nil {
		return "", "", err
	}
	assertion, ok := network.AuthenticatedIngressFromContext(ctx)
	if !ok || expected.ID == "" || expected.Path == "" || expected.Encryption == nil || s.control == nil {
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
	row, relation, err := s.resolveGlobal(ctx, object.ID, object.Path)
	if err != nil {
		return "", "", err
	}
	if relation == nil || row.Transport != "Local" || row.MemberID != assertion.NodeID || relation.PeerID != assertion.NodeID || row.RelationshipID == nil || *row.RelationshipID != relation.ID {
		return "", "", ErrUnavailable
	}
	token, err := s.control.MediaIngressCapability(ctx, relation.ID, row.MemberID, row.ObjectID, row.ID, row.Bytes, sessionExpiresAt, object.Encryption)
	if err != nil {
		return "", "", err
	}
	return assertion.PublicOrigin + "/internal/v1/media/" + row.ObjectID, token, nil
}

// IngressLocalPlainSource uses only a durable, cryptographic content ETag.
// Older size/mtime ETags remain unavailable until independently reverified.
func (s *Service) IngressLocalPlainSource(ctx context.Context, expected store.MediaObject, objectID string, sessionExpiresAt int64) (string, string, string, int64, error) {
	if err := s.repository.CheckLegacyPhysicalWritesAllowed(ctx); err != nil {
		return "", "", "", 0, err
	}
	assertion, ok := network.AuthenticatedIngressFromContext(ctx)
	if !ok || !network.HasActivePublicAdmission(ctx) || expected.ID == "" || expected.Path == "" || expected.Encryption != nil || s.control == nil {
		return "", "", "", 0, ErrUnavailable
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return "", "", "", 0, err
	}
	defer release()
	object, err := s.cryptoObject(ctx, expected.Path, expected.ID, false)
	if err != nil || object.ID != expected.ID || object.Path != expected.Path || object.Kind != expected.Kind || object.Encryption != nil {
		return "", "", "", 0, ErrUnavailable
	}
	row, relation, err := s.resolveGlobal(ctx, object.ID, object.Path)
	if err != nil || relation == nil || row.Transport != "Local" || row.MemberID != assertion.NodeID || relation.PeerID != assertion.NodeID || row.RelationshipID == nil || *row.RelationshipID != relation.ID || row.ObjectID != objectID || row.Bytes <= 0 {
		return "", "", "", 0, ErrUnavailable
	}
	digest, ok := plaintextContentDigest(row.ETag)
	if !ok {
		return "", "", "", 0, ErrUnavailable
	}
	if err := s.control.VerifyFollowerPlainReadiness(ctx, *relation, assertion.PublicOrigin); err != nil {
		return "", "", "", 0, ErrUnavailable
	}
	token, err := s.control.MediaPlainIngressCapability(ctx, relation.ID, row.MemberID, row.ObjectID, row.ID, row.Bytes, sessionExpiresAt, digest)
	if err != nil {
		return "", "", "", 0, err
	}
	return assertion.PublicOrigin + "/internal/v1/media/" + row.ObjectID, token, followerRelayRevision(row), row.Bytes, nil
}
