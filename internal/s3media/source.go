package s3media

import (
	"context"
	"encoding/json"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// SourceGrant is internal control metadata. HTTP constructs its bounded public
// response only after the media service checks the current path and object ID.
type SourceGrant struct {
	ObjectID  string
	SizeBytes int64
	GET, HEAD s3store.Grant
}

func (s *Service) ReadSource(ctx context.Context, id, filename string) (SourceGrant, error) {
	if err := s.master(ctx); err != nil {
		return SourceGrant{}, err
	}
	release, err := s.lease(ctx, "object:"+id)
	if err != nil {
		return SourceGrant{}, err
	}
	defer release()
	object, err := s.repository.S3IssueReadGrant(ctx, id, time.Now().Unix()+store.S3GrantSeconds)
	if err != nil {
		return SourceGrant{}, err
	}
	member, err := s.repository.S3Member(ctx, object.Media.MemberID)
	if err != nil {
		return SourceGrant{}, err
	}
	provider, closeProvider, err := s.provider(member)
	if err != nil {
		return SourceGrant{}, err
	}
	defer closeProvider()
	headSigner, ok := provider.(s3store.HeadPresigner)
	if !ok {
		return SourceGrant{}, ErrUnavailable
	}
	expiry, err := grantDuration(object.GrantUntil)
	if err != nil {
		return SourceGrant{}, err
	}
	get, err := provider.PresignGet(ctx, object.Proof.Key, object.Proof.VersionID, object.Proof.ETag, filename, expiry)
	if err != nil {
		return SourceGrant{}, err
	}
	// Signing the first grant may consume part of its bounded horizon.
	expiry, err = grantDuration(min(object.GrantUntil, get.ExpiresAt))
	if err != nil {
		return SourceGrant{}, err
	}
	head, err := headSigner.PresignHead(ctx, object.Proof.Key, object.Proof.VersionID, object.Proof.ETag, expiry)
	if err != nil {
		return SourceGrant{}, err
	}
	return SourceGrant{ObjectID: object.Media.ObjectID, SizeBytes: object.Proof.Bytes, GET: get, HEAD: head}, nil
}

func (s *Service) RecoveryCredentials(ctx context.Context, id string, revision int64, credentials s3store.Credentials, audit store.NodeAudit) (store.S3Member, error) {
	if err := s.master(ctx); err != nil {
		return store.S3Member{}, err
	}
	if err := credentials.Validate(time.Now()); err != nil {
		return store.S3Member{}, err
	}
	encoded, err := json.Marshal(credentials)
	if err != nil {
		return store.S3Member{}, s3store.ErrCredentials
	}
	sealed, err := s.vault.Seal(string(encoded))
	if err != nil {
		return store.S3Member{}, s3store.ErrCredentials
	}
	return s.repository.S3RecoveryCredentials(ctx, id, revision, sealed, credentials.ExpiresAt, audit)
}
