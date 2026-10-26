package s3media

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func metadata(upload store.S3Upload) map[string]string {
	return map[string]string{"fc-session": upload.Reservation.ID, "fc-object": upload.ObjectID, "fc-member": upload.Reservation.MemberID, "fc-media": upload.Reservation.MediaID}
}

func (s *Service) uploadProvider(ctx context.Context, upload store.S3Upload) (s3store.Provider, func(), error) {
	member, err := s.repository.S3Member(ctx, upload.Reservation.MemberID)
	if err != nil {
		return nil, nil, err
	}
	if member.CredentialRevision != upload.CredentialRevision {
		return nil, nil, s3store.ErrCredentials
	}
	return s.provider(member)
}

// Begin never retries a potentially accepted CreateMultipart request. An
// uncertain response remains durable and does not release the reservation.
func (s *Service) Begin(ctx context.Context, id string) (store.S3Upload, error) {
	if err := s.master(ctx); err != nil {
		return store.S3Upload{}, err
	}
	release, err := s.lease(ctx, "upload:"+id)
	if err != nil {
		return store.S3Upload{}, err
	}
	defer release()
	upload, err := s.repository.S3Upload(ctx, id)
	if err != nil {
		return upload, err
	}
	if upload.State == "created" || upload.State == "published" {
		return upload, nil
	}
	provider, closeProvider, err := s.uploadProvider(ctx, upload)
	if err != nil {
		return upload, err
	}
	defer closeProvider()
	upload, err = s.repository.S3StartCreate(ctx, id, upload.Revision)
	if err != nil {
		return upload, err
	}
	providerID, operationErr := provider.CreateMultipart(ctx, upload.Key, metadata(upload))
	outcome := "created"
	if operationErr != nil {
		outcome = "rejected"
		if s3store.IsUncertain(operationErr) {
			outcome = "unknown"
		}
	}
	finish, cancel := finishContext(ctx)
	defer cancel()
	upload, err = s.repository.S3FinishCreate(finish, id, upload.Revision, providerID, outcome, ErrorCode(operationErr))
	if err != nil {
		return upload, err
	}
	return upload, operationErr
}

func (s *Service) Status(ctx context.Context, id string, touch bool) (store.S3Upload, error) {
	if err := s.master(ctx); err != nil {
		return store.S3Upload{}, err
	}
	if touch {
		return s.repository.S3TouchUpload(ctx, id)
	}
	return s.repository.S3Upload(ctx, id)
}

func (s *Service) PartGrant(ctx context.Context, id string, number int, bytes int64, checksum string) (s3store.Grant, error) {
	if err := s.master(ctx); err != nil {
		return s3store.Grant{}, err
	}
	release, err := s.lease(ctx, "upload:"+id)
	if err != nil {
		return s3store.Grant{}, err
	}
	defer release()
	upload, err := s.repository.S3Upload(ctx, id)
	if err != nil {
		return s3store.Grant{}, err
	}
	provider, closeProvider, err := s.uploadProvider(ctx, upload)
	if err != nil {
		return s3store.Grant{}, err
	}
	defer closeProvider()
	// Record the maximum outstanding authorization before a bearer is signed.
	part, err := s.repository.S3IssuePart(ctx, id, number, checksum, bytes)
	if err != nil {
		return s3store.Grant{}, err
	}
	expiry, err := grantDuration(part.GrantUntil)
	if err != nil {
		return s3store.Grant{}, err
	}
	return provider.PresignPart(ctx, upload.Key, upload.ProviderUploadID, int32(number), bytes, checksum, expiry)
}

func (s *Service) ConfirmPart(ctx context.Context, id string, number int) (store.S3Upload, error) {
	if err := s.master(ctx); err != nil {
		return store.S3Upload{}, err
	}
	release, err := s.lease(ctx, "upload:"+id)
	if err != nil {
		return store.S3Upload{}, err
	}
	defer release()
	upload, err := s.repository.S3Upload(ctx, id)
	if err != nil {
		return upload, err
	}
	provider, closeProvider, err := s.uploadProvider(ctx, upload)
	if err != nil {
		return upload, err
	}
	defer closeProvider()
	parts, err := provider.ListParts(ctx, upload.Key, upload.ProviderUploadID)
	if err != nil {
		return upload, err
	}
	for _, part := range parts {
		if int(part.Number) == number {
			return s.repository.S3ConfirmPart(ctx, id, store.S3Part{Number: number, Bytes: part.Size, SHA256: part.SHA256, ETag: part.ETag})
		}
	}
	return upload, s3store.ErrIncomplete
}

func objectProof(upload store.S3Upload, proof s3store.Proof) (store.S3ObjectProof, error) {
	if proof.Size != upload.Reservation.ExpectedBytes || proof.ChecksumType != "COMPOSITE" || proof.ETag == "" || len(proof.ETag) > publishedETagBytes || len(proof.Metadata) != len(metadata(upload)) {
		return store.S3ObjectProof{}, ErrProof
	}
	for key, value := range metadata(upload) {
		if proof.Metadata[key] != value {
			return store.S3ObjectProof{}, ErrProof
		}
	}
	if len(upload.Parts) < 1 || len(upload.Parts) > int(store.S3MaxObjectBytes/store.S3PartBytes) {
		return store.S3ObjectProof{}, ErrProof
	}
	composite := sha256.New()
	var bytes int64
	for index, part := range upload.Parts {
		digest, err := base64.StdEncoding.DecodeString(part.SHA256)
		if err != nil || len(digest) != sha256.Size || !part.Confirmed || part.Number != index+1 || part.Bytes < 1 || part.Bytes > store.S3PartBytes || (index != len(upload.Parts)-1 && part.Bytes != store.S3PartBytes) {
			return store.S3ObjectProof{}, ErrProof
		}
		_, _ = composite.Write(digest)
		bytes += part.Bytes
	}
	expected := base64.StdEncoding.EncodeToString(composite.Sum(nil)) + "-" + strconv.Itoa(len(upload.Parts))
	if bytes != proof.Size || proof.ChecksumSHA256 != expected {
		return store.S3ObjectProof{}, ErrProof
	}
	return store.S3ObjectProof{Key: upload.Key, SessionID: upload.Reservation.ID, ObjectID: upload.ObjectID, MemberID: upload.Reservation.MemberID, MediaID: upload.Reservation.MediaID, Bytes: proof.Size, ETag: proof.ETag, VersionID: proof.VersionID, CompositeSHA256: expected}, nil
}

// Complete recovers a lost completion response by verifying the same owned
// object first. Publication still requires all durable part proofs and commits
// catalog, crypto metadata and quota in one SQL transaction.
func (s *Service) Complete(ctx context.Context, id string, audit store.AdminAudit) (store.GlobalMedia, error) {
	if err := s.master(ctx); err != nil {
		return store.GlobalMedia{}, err
	}
	release, err := s.lease(ctx, "upload:"+id)
	if err != nil {
		return store.GlobalMedia{}, err
	}
	defer release()
	upload, err := s.repository.S3Upload(ctx, id)
	if err != nil {
		return store.GlobalMedia{}, err
	}
	if upload.State == "published" {
		object, err := s.repository.S3Object(ctx, upload.Reservation.MediaID)
		return object.Media, err
	}
	provider, closeProvider, err := s.uploadProvider(ctx, upload)
	if err != nil {
		return store.GlobalMedia{}, err
	}
	defer closeProvider()
	upload, err = s.repository.S3StartComplete(ctx, id, upload.Revision)
	if err != nil {
		return store.GlobalMedia{}, err
	}
	proof, err := provider.Head(ctx, upload.Key, "")
	if errors.Is(err, s3store.ErrNotFound) {
		var parts []s3store.Part
		parts, err = provider.ListParts(ctx, upload.Key, upload.ProviderUploadID)
		if err == nil {
			if len(parts) != len(upload.Parts) {
				return store.GlobalMedia{}, s3store.ErrIncomplete
			}
			for i, part := range parts {
				expected := upload.Parts[i]
				if !expected.Confirmed || int(part.Number) != expected.Number || part.Size != expected.Bytes || part.SHA256 != expected.SHA256 || part.ETag != expected.ETag {
					return store.GlobalMedia{}, ErrProof
				}
			}
			proof, err = provider.Complete(ctx, upload.Key, upload.ProviderUploadID, parts)
		}
	}
	if err != nil {
		return store.GlobalMedia{}, err
	}
	verified, err := objectProof(upload, proof)
	if err != nil {
		return store.GlobalMedia{}, err
	}
	finish, cancel := finishContext(ctx)
	defer cancel()
	published, err := s.repository.S3FinalizeUpload(finish, id, upload.Revision, verified, audit)
	if err == nil {
		s.mutations.Add(1)
	}
	return published, err
}

// ReadGrant returns both URL and signed headers. A native media-element
// redirect cannot carry If-Match: the browser data plane must inject headers.
func (s *Service) ReadGrant(ctx context.Context, id, filename string) (s3store.Grant, error) {
	if err := s.master(ctx); err != nil {
		return s3store.Grant{}, err
	}
	release, err := s.lease(ctx, "object:"+id)
	if err != nil {
		return s3store.Grant{}, err
	}
	defer release()
	object, err := s.repository.S3IssueReadGrant(ctx, id, time.Now().Unix()+store.S3GrantSeconds)
	if err != nil {
		return s3store.Grant{}, err
	}
	member, err := s.repository.S3Member(ctx, object.Media.MemberID)
	if err != nil {
		return s3store.Grant{}, err
	}
	provider, closeProvider, err := s.provider(member)
	if err != nil {
		return s3store.Grant{}, err
	}
	defer closeProvider()
	expiry, err := grantDuration(object.GrantUntil)
	if err != nil {
		return s3store.Grant{}, err
	}
	return provider.PresignGet(ctx, object.Proof.Key, object.Proof.VersionID, object.Proof.ETag, filename, expiry)
}

func grantDuration(until int64) (time.Duration, error) {
	// SigV4 represents expiry in whole seconds. Round down to stay within the
	// durable authorization deadline even near a wall-clock second boundary.
	expiry := time.Until(time.Unix(until, 0)).Truncate(time.Second)
	if expiry <= 0 || expiry > time.Duration(store.S3GrantSeconds)*time.Second {
		return 0, s3store.ErrConfig
	}
	return expiry, nil
}
