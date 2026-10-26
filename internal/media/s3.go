package media

import (
	"context"
	"errors"
	"os"
	"path"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Ordinary media endpoints cannot express the signed headers required by S3.
// The browser must request a current source grant and send it directly.
var ErrBrowserSource = errors.New("media requires a browser source grant")

type s3Control interface {
	Generation() uint64
	Members(context.Context) ([]store.S3Member, error)
	Add(context.Context, s3media.Configuration, store.NodeAudit) (store.S3Member, error)
	Configure(context.Context, string, int64, s3media.Configuration, store.NodeAudit) (store.S3Member, error)
	Probe(context.Context, string, int64, string, store.NodeAudit) (store.S3Member, error)
	Remove(context.Context, string, int64, store.NodeAudit) error
	RecoveryCredentials(context.Context, string, int64, s3store.Credentials, store.NodeAudit) (store.S3Member, error)
	Begin(context.Context, string) (store.S3Upload, error)
	Status(context.Context, string, bool) (store.S3Upload, error)
	PartGrant(context.Context, string, int, int64, string) (s3store.Grant, error)
	ConfirmPart(context.Context, string, int) (store.S3Upload, error)
	Complete(context.Context, string, store.AdminAudit) (store.GlobalMedia, error)
	Cancel(context.Context, string, store.AdminAudit) (store.S3Upload, error)
	Delete(context.Context, string, store.AdminAudit) error
	ReadSource(context.Context, string, string) (s3media.SourceGrant, error)
	Reconcile(context.Context) error
}

// ConfigureS3 is startup-only. No provider credential or URL enters native node
// control, filesystem upload stages, ordinary ZIP construction or relay paths.
func (s *Service) ConfigureS3(service *s3media.Service) {
	if service == nil {
		s.s3 = nil
		return
	}
	s.s3 = service
}

func (s *Service) acquireS3(ctx context.Context) (func(), error) {
	if err := s.requireMaster(ctx); err != nil {
		return nil, err
	}
	release, err := s.acquire(ctx, false)
	if err != nil {
		return nil, err
	}
	if err = s.ready(); err != nil {
		release()
		return nil, err
	}
	if s.s3 == nil {
		release()
		return nil, ErrUnavailable
	}
	return release, nil
}

func (s *Service) S3Members(ctx context.Context) ([]store.S3Member, error) {
	release, err := s.acquireS3(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return s.s3.Members(ctx)
}
func (s *Service) S3AddMember(ctx context.Context, cfg s3media.Configuration, a store.NodeAudit) (store.S3Member, error) {
	release, err := s.acquireS3(ctx)
	if err != nil {
		return store.S3Member{}, err
	}
	defer release()
	return s.s3.Add(ctx, cfg, a)
}
func (s *Service) S3ConfigureMember(ctx context.Context, id string, revision int64, cfg s3media.Configuration, a store.NodeAudit) (store.S3Member, error) {
	release, err := s.acquireS3(ctx)
	if err != nil {
		return store.S3Member{}, err
	}
	defer release()
	return s.s3.Configure(ctx, id, revision, cfg, a)
}
func (s *Service) S3ProbeMember(ctx context.Context, id string, revision int64, origin string, a store.NodeAudit) (store.S3Member, error) {
	release, err := s.acquireS3(ctx)
	if err != nil {
		return store.S3Member{}, err
	}
	defer release()
	return s.s3.Probe(ctx, id, revision, origin, a)
}
func (s *Service) S3RemoveMember(ctx context.Context, id string, revision int64, a store.NodeAudit) error {
	release, err := s.acquireS3(ctx)
	if err != nil {
		return err
	}
	defer release()
	return s.s3.Remove(ctx, id, revision, a)
}
func (s *Service) S3RecoveryCredentials(ctx context.Context, id string, revision int64, credentials s3store.Credentials, a store.NodeAudit) (store.S3Member, error) {
	release, err := s.acquireS3(ctx)
	if err != nil {
		return store.S3Member{}, err
	}
	defer release()
	return s.s3.RecoveryCredentials(ctx, id, revision, credentials, a)
}
func (s *Service) S3UploadStatus(ctx context.Context, id string, touch bool) (store.S3Upload, error) {
	release, err := s.acquireS3(ctx)
	if err != nil {
		return store.S3Upload{}, err
	}
	defer release()
	return s.s3.Status(ctx, id, touch)
}
func (s *Service) S3BeginUpload(ctx context.Context, id string) (store.S3Upload, error) {
	release, err := s.acquireS3(ctx)
	if err != nil {
		return store.S3Upload{}, err
	}
	defer release()
	return s.s3.Begin(ctx, id)
}
func (s *Service) S3PartGrant(ctx context.Context, id string, number int, size int64, checksum string) (s3store.Grant, error) {
	release, err := s.acquireS3(ctx)
	if err != nil {
		return s3store.Grant{}, err
	}
	defer release()
	return s.s3.PartGrant(ctx, id, number, size, checksum)
}
func (s *Service) S3ConfirmPart(ctx context.Context, id string, number int) (store.S3Upload, error) {
	release, err := s.acquireS3(ctx)
	if err != nil {
		return store.S3Upload{}, err
	}
	defer release()
	return s.s3.ConfirmPart(ctx, id, number)
}
func (s *Service) S3CompleteUpload(ctx context.Context, id string, a store.AdminAudit) (UploadResult, error) {
	release, err := s.acquireS3(ctx)
	if err != nil {
		return UploadResult{}, err
	}
	defer release()
	row, err := s.s3.Complete(ctx, id, a)
	s.invalidateCatalog()
	return UploadResult{Path: row.Path, MediaID: row.ID}, err
}
func (s *Service) S3CancelUpload(ctx context.Context, id string, a store.AdminAudit) (store.S3Upload, error) {
	release, err := s.acquireS3(ctx)
	if err != nil {
		return store.S3Upload{}, err
	}
	defer release()
	return s.s3.Cancel(ctx, id, a)
}
func (s *Service) ReconcileS3(ctx context.Context) error {
	release, err := s.acquireS3(ctx)
	if err != nil {
		return err
	}
	defer release()
	before := s.s3.Generation()
	err = s.s3.Reconcile(ctx)
	if s.s3.Generation() != before {
		s.invalidateCatalog()
	}
	return err
}
func (s *Service) RunS3Recovery(ctx context.Context) {
	timer := time.NewTicker(30 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			role, err := s.role(ctx)
			if err != nil || role != "Master" || s.s3 == nil {
				continue
			}
			bounded, cancel := context.WithTimeout(ctx, 25*time.Second)
			_ = s.ReconcileS3(bounded)
			cancel()
		}
	}
}

// ReadSource rechecks the path and immutable identity under the same shared
// mutation fence as source authorization. A native object returns an empty
// grant; S3 always requires an explicit immutable object ID.
func (s *Service) ReadSource(ctx context.Context, name, expectedObjectID string, admin bool) (s3media.SourceGrant, error) {
	release, err := s.acquire(ctx, false)
	if err != nil {
		return s3media.SourceGrant{}, err
	}
	defer release()
	return s.readSource(ctx, name, expectedObjectID, admin, false)
}
func (s *Service) PlaintextSource(ctx context.Context, name, expectedObjectID string, admin bool) (s3media.SourceGrant, error) {
	release, err := s.acquire(ctx, false)
	if err != nil {
		return s3media.SourceGrant{}, err
	}
	defer release()
	return s.readSource(ctx, name, expectedObjectID, admin, true)
}
func (s *Service) readSource(ctx context.Context, name, expectedObjectID string, admin, plainOnly bool) (s3media.SourceGrant, error) {
	object, err := s.cryptoObject(ctx, name, "", admin)
	if err != nil {
		return s3media.SourceGrant{}, err
	}
	if expectedObjectID != "" && expectedObjectID != object.ID {
		return s3media.SourceGrant{}, os.ErrNotExist
	}
	role, err := s.role(ctx)
	if err != nil {
		return s3media.SourceGrant{}, err
	}
	if role != "Master" || object.Kind == "lyric" {
		if plainOnly {
			return s3media.SourceGrant{}, ErrPath
		}
		return s3media.SourceGrant{}, nil
	}
	row, _, err := s.resolveGlobal(ctx, "", name)
	if err != nil {
		return s3media.SourceGrant{}, err
	}
	if row.Transport != "S3" {
		if plainOnly {
			return s3media.SourceGrant{}, ErrPath
		}
		return s3media.SourceGrant{}, nil
	}
	if expectedObjectID == "" || row.ObjectID != expectedObjectID || row.ID != object.ID || plainOnly && object.Encryption != nil {
		return s3media.SourceGrant{}, ErrPath
	}
	if s.s3 == nil {
		return s3media.SourceGrant{}, ErrUnavailable
	}
	return s.s3.ReadSource(ctx, row.ID, path.Base(row.Path))
}
