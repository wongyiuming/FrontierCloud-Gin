package s3media

import (
	"context"
	"errors"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// DeleteSelectedPublishedObject removes only the authenticated published
// object. Before calling, the coordinator must record the delete intent,
// block new read grants and let existing grants expire. check revalidates
// the held provider configuration and deletion authority around each I/O.
// A nil result proves absence for the exact provider version, not that any
// separate catalog or capacity transaction has committed.
func DeleteSelectedPublishedObject(ctx context.Context, provider s3store.Provider, proof store.S3ObjectProof, check func(context.Context) error) error {
	if ctx == nil || provider == nil || check == nil || proof.MetadataFormat != store.S3OpaqueMetadata ||
		proof.MemberID == "" || proof.SessionID == "" || proof.MediaID == "" || proof.ObjectID == "" ||
		proof.Bytes < 1 || proof.Bytes > store.S3MaxObjectBytes || proof.ETag == "" || proof.CompositeSHA256 == "" ||
		!store.ValidS3MetadataIdentity(proof.MetadataFormat, proof.Key, proof.MetadataOwner, proof.MediaID, proof.ObjectID) {
		return ErrProof
	}
	alive := func() bool { return ctx.Err() == nil && check(ctx) == nil && ctx.Err() == nil }
	if !alive() {
		return ErrUnavailable
	}
	observed, err := provider.Head(ctx, proof.Key, proof.VersionID)
	if !alive() {
		return ErrUnavailable
	}
	if errors.Is(err, s3store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !matchesSelectedPublishedHead(observed, proof) {
		return ErrProof
	}
	err = provider.Delete(ctx, proof.Key, proof.VersionID, proof.ETag)
	if !alive() {
		return ErrUnavailable
	}
	if err != nil && !s3store.IsUncertain(err) && !errors.Is(err, s3store.ErrNotFound) {
		return err
	}
	_, err = provider.Head(ctx, proof.Key, proof.VersionID)
	if !alive() {
		return ErrUnavailable
	}
	if errors.Is(err, s3store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return ErrPending
}

func matchesSelectedPublishedHead(observed s3store.Proof, proof store.S3ObjectProof) bool {
	metadata := map[string]string{"fc-format": store.S3OpaqueMetadata, "fc-owner": proof.MetadataOwner}
	return observed.VersionID == proof.VersionID && observed.ETag == proof.ETag && observed.Size == proof.Bytes &&
		observed.ChecksumType == "COMPOSITE" && observed.ChecksumSHA256 == proof.CompositeSHA256 && exactMetadata(observed.Metadata, metadata)
}
