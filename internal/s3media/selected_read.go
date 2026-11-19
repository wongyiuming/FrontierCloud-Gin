package s3media

import (
	"context"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// SelectedReadSource signs the already authenticated tree proof. The caller
// must hold the real public-admission and S3 configuration fence, and must
// have arranged for configuration changes and deletion to drain these grants
// through deadline, including after restart. check must verify those same
// authorities; this method cannot install or substitute for that gate.
// No logical filename is included in either provider request.
func (s *Service) SelectedReadSource(ctx context.Context, expected store.S3Member, proof store.S3ObjectProof, deadline int64, check func(context.Context) error) (SourceGrant, error) {
	var empty SourceGrant
	if ctx == nil || ctx.Err() != nil || check == nil || check(ctx) != nil || proof.MemberID != expected.ID || proof.MediaID == "" || proof.ObjectID == "" || proof.MetadataFormat != store.S3OpaqueMetadata || proof.Bytes < 1 || proof.Bytes > store.S3MaxObjectBytes || proof.ETag == "" || !store.ValidS3MetadataIdentity(proof.MetadataFormat, proof.Key, proof.MetadataOwner, proof.MediaID, proof.ObjectID) {
		return empty, ErrUnavailable
	}
	if err := s.master(ctx); err != nil {
		return empty, err
	}
	current, err := s.selectedReadMember(ctx, expected)
	if err != nil {
		return empty, err
	}
	if current.CredentialExpiresAt != 0 {
		deadline = min(deadline, current.CredentialExpiresAt)
	}
	expiry, err := grantDuration(deadline)
	if err != nil {
		return empty, err
	}
	provider, closeProvider, err := s.provider(current)
	if err != nil {
		return empty, err
	}
	defer closeProvider()
	headSigner, ok := provider.(s3store.HeadPresigner)
	if !ok {
		return empty, ErrUnavailable
	}
	get, err := provider.PresignGet(ctx, proof.Key, proof.VersionID, proof.ETag, "", expiry)
	if err != nil || check(ctx) != nil || get.ExpiresAt <= time.Now().Unix() || get.ExpiresAt > deadline || get.Headers["If-Match"] != proof.ETag {
		return empty, ErrUnavailable
	}
	expiry, err = grantDuration(min(deadline, get.ExpiresAt))
	if err != nil {
		return empty, err
	}
	head, err := headSigner.PresignHead(ctx, proof.Key, proof.VersionID, proof.ETag, expiry)
	if err != nil || check(ctx) != nil || head.ExpiresAt <= time.Now().Unix() || head.ExpiresAt > deadline || head.ExpiresAt > get.ExpiresAt || head.Headers["If-Match"] != proof.ETag {
		return empty, ErrUnavailable
	}
	if _, err = s.selectedReadMember(ctx, expected); err != nil || check(ctx) != nil || ctx.Err() != nil {
		return empty, ErrUnavailable
	}
	return SourceGrant{ObjectID: proof.ObjectID, SizeBytes: proof.Bytes, GET: get, HEAD: head}, nil
}

func (s *Service) selectedReadMember(ctx context.Context, expected store.S3Member) (store.S3Member, error) {
	current, err := s.repository.S3Member(ctx, expected.ID)
	if err != nil || current.ID != expected.ID || current.Kind != "S3" || current.Transport != "S3" || current.RelationshipID != nil || current.CleanupOnly || current.SealedCredentials == "" || current.Revision < 1 || current.CredentialRevision < 1 || current.Revision != expected.Revision || current.CredentialRevision != expected.CredentialRevision || current.SealedCredentials != expected.SealedCredentials || current.CredentialExpiresAt != expected.CredentialExpiresAt || current.Location != expected.Location || current.ProbeState != "ready" || current.ProbeRevision != current.Revision || current.CredentialExpiresAt != 0 && current.CredentialExpiresAt <= time.Now().Unix() {
		return store.S3Member{}, ErrUnavailable
	}
	return current, nil
}
