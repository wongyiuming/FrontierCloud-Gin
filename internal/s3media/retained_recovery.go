package s3media

import (
	"context"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// RetainedS3ObjectObservation records provider metadata from an exact-version
// HEAD. It contains neither a provider path nor a credential, and it does not
// attest to a full ciphertext or plaintext hash.
type RetainedS3ObjectObservation struct {
	ObjectID           string
	MemberID           string
	PhysicalObjectID   string
	ObjectRevision     int64
	MemberRevision     int64
	CredentialRevision int64
	StoredBytes        int64
	VersionID          string
	ETag               string
	ChecksumType       string
	CompositeSHA256    string
}

// ObserveRetainedS3Object compares an authenticated sealed placement with the
// configured provider. The caller must hold the recovery and configuration
// fences and supply a check for that authority. HEAD cannot establish reverse
// inventory completeness or prevent writes by other provider clients.
func (s *Service) ObserveRetainedS3Object(ctx context.Context, expected store.S3Member, placement sealedtree.S3Placement, check func(context.Context) error) (RetainedS3ObjectObservation, error) {
	var empty RetainedS3ObjectObservation
	physicalID, valid := retainedS3PlacementID(expected, placement)
	if !valid {
		return empty, ErrProof
	}
	if ctx == nil || ctx.Err() != nil || check == nil || s.master(ctx) != nil {
		return empty, ErrUnavailable
	}
	current, err := s.selectedReadMember(ctx, expected)
	if err != nil {
		return empty, ErrUnavailable
	}
	provider, closeProvider, err := s.provider(current)
	if err != nil {
		return empty, ErrUnavailable
	}
	defer closeProvider()
	if check(ctx) != nil || ctx.Err() != nil {
		return empty, ErrUnavailable
	}
	observed, err := observeRetainedS3Object(ctx, provider, current, placement, physicalID)
	if err != nil {
		return empty, err
	}
	if _, err := s.selectedReadMember(ctx, expected); err != nil || check(ctx) != nil || ctx.Err() != nil {
		return empty, ErrUnavailable
	}
	return observed, nil
}

func retainedS3PlacementID(member store.S3Member, placement sealedtree.S3Placement) (string, bool) {
	proof := placement.Proof
	physicalID, opaque := store.S3OpaqueOwner(proof.Key)
	return physicalID, opaque && proof.MetadataFormat == store.S3OpaqueMetadata && proof.VersionID != "" && proof.VersionID != "null" &&
		placement.Encryption != nil && placement.MatchesCurrentMember(member.ID, config(member.Location))
}

func observeRetainedS3Object(ctx context.Context, provider s3store.Provider, current store.S3Member, placement sealedtree.S3Placement, physicalID string) (RetainedS3ObjectObservation, error) {
	var empty RetainedS3ObjectObservation
	proof := placement.Proof
	observed, err := provider.Head(ctx, proof.Key, proof.VersionID)
	if err != nil {
		return empty, ErrUnavailable
	}
	if !matchesSelectedPublishedHead(observed, proof) {
		return empty, ErrProof
	}
	return RetainedS3ObjectObservation{
		ObjectID: placement.ObjectID, MemberID: current.ID, PhysicalObjectID: physicalID,
		ObjectRevision: placement.ObjectRevision, MemberRevision: current.Revision, CredentialRevision: current.CredentialRevision,
		StoredBytes: observed.Size, VersionID: observed.VersionID, ETag: observed.ETag,
		ChecksumType: observed.ChecksumType, CompositeSHA256: observed.ChecksumSHA256,
	}, nil
}
