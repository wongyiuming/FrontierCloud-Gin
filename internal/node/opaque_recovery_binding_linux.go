//go:build linux

package node

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// VisitRecoveryExpectedOwnerBinding derives the existing Follower registry
// binding from a trusted, authenticated Master tree or selected-recording
// projection. Caller holds the genuine local Owner-control lease and the
// source-generation authority throughout the callback; masterID and
// relationshipID must themselves come from that authenticated recovery scope.
// This does not authenticate the projection, inspect Owner files, contact the
// Master, or grant a read. The result is provisional until return nil.
func (s *Service) VisitRecoveryExpectedOwnerBinding(ctx context.Context, owner store.OwnerControlLease, masterID, relationshipID string, expected sealedtree.RecoveryMediaPlacement, visit func(protocol.OpaqueOwnerBinding) error) error {
	if s == nil || s.repo == nil || s.identity == nil || ctx == nil || owner == nil || visit == nil || !ValidIdentifier(masterID) || !ValidIdentifier(relationshipID) ||
		(expected.Kind != "audio" && expected.Kind != "video" && expected.Kind != "lyric" && expected.Kind != "recording") ||
		(expected.Kind == "recording" && !ValidIdentifier(expected.ObjectID)) || (expected.Kind != "recording" && !resourceIdentifier.MatchString(expected.ObjectID)) ||
		expected.S3CompositeSHA256 != "" || expected.S3ETag != "" || expected.S3VersionID != "" || expected.S3ObjectRevision != 0 ||
		expected.AliasRevoked != (expected.AliasRevocationOperationID != "") || (expected.AliasRevoked && !ValidIdentifier(expected.AliasRevocationOperationID)) {
		return ErrCapability
	}
	observer, ok := s.repo.(interface {
		VerifyOwnerControlBinding(context.Context, string) error
	})
	if !ok || owner.Check(ctx) != nil {
		return ErrCapability
	}
	control, err := owner.Binding(ctx)
	if err != nil || !resourceIdentifier.MatchString(control) || observer.VerifyOwnerControlBinding(ctx, control) != nil {
		return ErrCapability
	}
	identity, err := s.repo.ReadIdentity(ctx)
	if err != nil || identity.Role != "Follower" || identity.ID != expected.OwnerID || identity.ID != s.identity.ID || identity.PrivateKey == "" || identity.PrivateKey != s.identity.PrivateKey {
		return ErrCapability
	}
	relation, err := s.repo.Relationship(ctx, relationshipID)
	if err != nil || relation.ID != relationshipID || relation.PeerID != masterID || relation.State != "active" || relation.Direction != "upstream" || relation.Protocol != protocol.Version || relation.PublicKey == "" || relation.Credential == "" || relation.CreatedAt <= 0 {
		return ErrCapability
	}
	ownerBinding := protocol.OpaqueOwnerBinding{MasterID: masterID, OwnerID: identity.ID, RelationshipID: relation.ID, Alias: expected.ReadAlias, Blob: expected.BlobID, Revision: expected.AliasRevision, Digest: expected.NativeSHA256, Descriptor: expected.Descriptor, Size: expected.Bytes}
	if !ownerBinding.Valid() {
		return ErrCapability
	}
	check := func() error {
		if ctx.Err() != nil || owner.Check(ctx) != nil {
			return ErrCapability
		}
		binding, e := owner.Binding(ctx)
		if e != nil || binding != control || observer.VerifyOwnerControlBinding(ctx, control) != nil {
			return ErrCapability
		}
		id, e := s.repo.ReadIdentity(ctx)
		if e != nil || id != identity {
			return ErrCapability
		}
		current, e := s.repo.Relationship(ctx, relationshipID)
		if e != nil || current.ID != relation.ID || current.PeerID != relation.PeerID || current.Endpoint != relation.Endpoint || current.PublicKey != relation.PublicKey || current.Credential != relation.Credential || current.Direction != relation.Direction || current.Mode != relation.Mode || current.State != relation.State || current.Protocol != relation.Protocol || current.CreatedAt != relation.CreatedAt || owner.Check(ctx) != nil {
			return ErrCapability
		}
		return nil
	}
	if check() != nil {
		return ErrCapability
	}
	if err = visit(ownerBinding); err != nil {
		return err
	}
	return check()
}
