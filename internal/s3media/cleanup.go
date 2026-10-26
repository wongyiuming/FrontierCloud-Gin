package s3media

import (
	"context"
	"errors"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func (s *Service) cleanupProvider(ctx context.Context, upload store.S3Upload) (s3store.Provider, func(), error) {
	member, err := s.repository.S3Member(ctx, upload.Reservation.MemberID)
	if err != nil {
		return nil, nil, err
	}
	if member.CredentialRevision != upload.CredentialRevision && !member.CleanupOnly {
		return nil, nil, s3store.ErrCredentials
	}
	return s.provider(member)
}

func exactMetadata(actual, expected map[string]string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	return true
}

// Delete only the observed exact version/ETag after checking ownership. Even a
// lost DELETE reply is reconciled through a separate exact-version HEAD.
func deleteOwned(ctx context.Context, provider s3store.Provider, key string, expected map[string]string, version, etag string) (string, string, error) {
	proof, err := provider.Head(ctx, key, version)
	if errors.Is(err, s3store.ErrNotFound) {
		return version, etag, nil
	}
	if err != nil {
		return version, etag, err
	}
	if !exactMetadata(proof.Metadata, expected) || version != "" && proof.VersionID != version || etag != "" && proof.ETag != etag {
		return version, etag, ErrProof
	}
	version, etag = proof.VersionID, proof.ETag
	operationErr := provider.Delete(ctx, key, version, etag)
	if operationErr != nil && !s3store.IsUncertain(operationErr) && !errors.Is(operationErr, s3store.ErrNotFound) {
		return version, etag, operationErr
	}
	_, err = provider.Head(ctx, key, version)
	if errors.Is(err, s3store.ErrNotFound) {
		return version, etag, nil
	}
	if err != nil {
		return version, etag, err
	}
	return version, etag, ErrPending
}

func abortKnown(ctx context.Context, provider s3store.Provider, key, id string) error {
	if id == "" {
		return nil
	}
	operationErr := provider.Abort(ctx, key, id)
	if operationErr != nil && !s3store.IsUncertain(operationErr) && !errors.Is(operationErr, s3store.ErrNotFound) {
		return operationErr
	}
	parts, err := provider.ListParts(ctx, key, id)
	if errors.Is(err, s3store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	// S3 also documents an empty ListParts after a successful abort as proof
	// that its parts are gone. A lost abort reply plus an empty still-open
	// upload is ambiguous, so only an acknowledged abort accepts this form.
	if operationErr == nil && len(parts) == 0 {
		return nil
	}
	return ErrPending
}

func discoverUpload(ctx context.Context, provider s3store.Provider, key string, created int64) (string, error) {
	lister, ok := provider.(s3store.ExactUploadLister)
	if !ok {
		return "", ErrUnavailable
	}
	listing, err := lister.ListUploads(ctx, key)
	if err != nil {
		return "", err
	}
	// An empty listing cannot distinguish delayed Create from no Create.
	if !listing.Complete || len(listing.Uploads) == 0 {
		return "", ErrPending
	}
	if len(listing.Uploads) != 1 {
		return "", ErrProof
	}
	found := listing.Uploads[0]
	if found.InitiatedAt < created-30 || found.InitiatedAt > time.Now().Unix()+30 {
		return "", ErrProof
	}
	return found.UploadID, nil
}

func (s *Service) Cancel(ctx context.Context, id string, audit store.AdminAudit) (store.S3Upload, error) {
	if err := s.master(ctx); err != nil {
		return store.S3Upload{}, err
	}
	release, err := s.lease(ctx, "upload:"+id)
	if err != nil {
		return store.S3Upload{}, err
	}
	defer release()
	upload, err := s.repository.S3RequestAbort(ctx, id, audit)
	if err != nil || upload.State == "aborted" {
		return upload, err
	}
	if upload.GrantUntil > time.Now().Unix() {
		return upload, ErrPending
	}
	provider, closeProvider, err := s.cleanupProvider(ctx, upload)
	if err != nil {
		return upload, err
	}
	defer closeProvider()
	if upload.CreateUncertain && upload.ProviderUploadID == "" {
		providerID, err := discoverUpload(ctx, provider, upload.Key, upload.Reservation.CreatedAt)
		if err != nil {
			return upload, err
		}
		upload, err = s.repository.S3FinishCreate(ctx, id, upload.Revision, providerID, "created", "")
		if err != nil {
			return upload, err
		}
	}
	if err = abortKnown(ctx, provider, upload.Key, upload.ProviderUploadID); err != nil {
		return upload, err
	}
	version, etag, err := deleteOwned(ctx, provider, upload.Key, metadata(upload), upload.Proof.VersionID, upload.Proof.ETag)
	if err != nil {
		return upload, err
	}
	proof := store.S3AbsenceProof{Key: upload.Key, VersionID: version, ETag: etag, ProviderUploadID: upload.ProviderUploadID, SessionID: upload.Reservation.ID, ObjectID: upload.ObjectID, MemberID: upload.Reservation.MemberID, MediaID: upload.Reservation.MediaID, ObjectAbsent: true, MultipartAbsent: true}
	finish, cancel := finishContext(ctx)
	defer cancel()
	return s.repository.S3FinishAbort(finish, id, upload.Revision, proof, audit)
}

func (s *Service) Delete(ctx context.Context, id string, audit store.AdminAudit) error {
	if err := s.master(ctx); err != nil {
		return err
	}
	release, err := s.lease(ctx, "object:"+id)
	if err != nil {
		return err
	}
	defer release()
	object, err := s.repository.S3StartDelete(ctx, id, audit)
	if err != nil {
		return err
	}
	if object.GrantUntil > time.Now().Unix() {
		return ErrPending
	}
	member, err := s.repository.S3Member(ctx, object.Media.MemberID)
	if err != nil {
		return err
	}
	provider, closeProvider, err := s.provider(member)
	if err != nil {
		return err
	}
	defer closeProvider()
	expected := map[string]string{"fc-session": object.Proof.SessionID, "fc-object": object.Proof.ObjectID, "fc-member": object.Proof.MemberID, "fc-media": object.Proof.MediaID}
	version, etag, err := deleteOwned(ctx, provider, object.Proof.Key, expected, object.Proof.VersionID, object.Proof.ETag)
	if err != nil {
		return err
	}
	proof := store.S3AbsenceProof{Key: object.Proof.Key, VersionID: version, ETag: etag, SessionID: object.Proof.SessionID, ObjectID: object.Proof.ObjectID, MemberID: object.Proof.MemberID, MediaID: object.Proof.MediaID, ObjectAbsent: true, MultipartAbsent: true}
	finish, cancel := finishContext(ctx)
	defer cancel()
	err = s.repository.S3FinishDelete(finish, id, object.Revision, proof, audit)
	if err == nil {
		s.mutations.Add(1)
	}
	return err
}
